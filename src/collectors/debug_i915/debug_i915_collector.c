#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
/* #include <libgen.h> */
#include <ctype.h>
#include <fcntl.h>
#include <libiberty/demangle.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#include <libelf.h>
#include <elfutils/libdw.h>

#include "iaprof.h"
#include "debug_i915_collector.h"
#include "stores/buffer_profile.h"
#include "utils/utils.h"
#include "utils/hash_table.h"

static uint32_t vm_counter = 0;
struct debug_i915_info_t debug_i915_info;
pthread_rwlock_t debug_i915_info_lock;

/* For waiting on vm_create events from BPF */
pthread_cond_t debug_i915_vm_create_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t debug_i915_vm_create_lock = PTHREAD_MUTEX_INITIALIZER;

typedef char *sym_str_t;

typedef struct {
        char *filename;
        int   linenum;
} Debug_Info;

use_hash_table(sym_str_t, Debug_Info);

int store_buffer_copy(uint32_t vm_id, uint64_t gpu_addr, void *buff, uint64_t buff_sz)
{
        struct vm_profile *vm;
        struct buffer_profile *gem;

        vm = acquire_vm_profile(vm_id);

        /* Find the buffer that this batchbuffer is associated with */
        gem = get_buffer_profile(vm, gpu_addr);
        if (gem == NULL) {
                if (debug) {
                        fprintf(stderr,
                                "WARNING: couldn't find a buffer to store a binary in.\n");
                }
                goto cleanup;
        }

        handle_binary(&(gem->buff), buff, &(gem->buff_sz),
                      buff_sz);

cleanup:
        release_vm_profile(vm);
        return 0;
}


void init_debug_i915(int i915_fd, int pid)
{
        int debug_fd;
        int i;
        int flags;

        /* This is called from the bpf_collect_thread when we see a new
         * PID. We must protect debug_i915_info from data races when it
         * is likely to be simultaneously accessed from
         * debug_i915_collect_thread. */

        pthread_rwlock_rdlock(&debug_i915_info_lock);

        /* First, check if we've already initialized this PID. */
        for (i = 0; i < debug_i915_info.num_pids; i++) {
                if (debug_i915_info.pids[i] == pid) {
                        goto out_unlock;
                }
        }

        pthread_rwlock_unlock(&debug_i915_info_lock);

        /* Open the fd to begin debugging this PID */
        struct prelim_drm_i915_debugger_open_param open = {};
        open.pid = pid;
        debug_fd = ioctl(i915_fd, PRELIM_DRM_IOCTL_I915_DEBUGGER_OPEN, &open);

        if (debug_fd < 0) {
                fprintf(stderr,
                        "Failed to open the debug interface for PID %d.\n",
                        pid);
                goto out;
        }

        flags = fcntl(debug_fd, F_GETFL, 0);
        fcntl(debug_fd, F_SETFL, flags | O_NONBLOCK);

        pthread_rwlock_wrlock(&debug_i915_info_lock);

        /* @TODO: check for MAX_PIDS */

        /* Add the PID and fd to the arrays */
        debug_i915_info.pollfds[debug_i915_info.num_pids].fd = debug_fd;
        debug_i915_info.pollfds[debug_i915_info.num_pids].events = POLLIN;
        debug_i915_info.pids[debug_i915_info.num_pids] = pid;
        debug_i915_info.symtabs[debug_i915_info.num_pids].pid = pid;
        debug_i915_info.num_pids++;

out_unlock:;
        pthread_rwlock_unlock(&debug_i915_info_lock);
out:;
}

int debug_i915_get_sym(int pid, uint64_t addr, char **out_gpu_symbol, char **out_gpu_file, int *out_gpu_line)
{
        int i, pid_index;
        struct i915_symbol_table *table;
        struct i915_symbol_entry *entry;
        char less_than_last;

        if (debug) {
                fprintf(stderr, "Finding symbol for pid=%d addr=0x%lx\n", pid,
                        addr);
        }

        /* Find which index this PID relates to */
        pid_index = -1;
        for (i = 0; i < debug_i915_info.num_pids; i++) {
                if (debug_i915_info.pids[i] == pid) {
                        pid_index = i;
                        break;
                }
        }
        if (pid_index == -1) {
                fprintf(stderr, "WARNING: PID %d does not have GPU symbols.\n",
                        pid);
                return -1;
        }

        /* Find the addr range in this PID's symbol table */
        /* XXX: Completely rewrite. */
        table = &(debug_i915_info.symtabs[pid_index]);
        for (i = 0; i < table->num_syms; i++) {
                entry = &(table->symtab[i]);
                if (addr < entry->start_addr) {
                        less_than_last = true;
                        continue;
                }
                if (less_than_last && (addr > entry->start_addr)) {
                        if (out_gpu_symbol != NULL) {
                                *out_gpu_symbol = entry->symbol;
                        }
                        if (out_gpu_file != NULL) {
                                *out_gpu_file = entry->filename;
                        }
                        if (out_gpu_line != NULL) {
                                *out_gpu_line = entry->linenum;
                        }
                        return 0;
                }
        }

        if (debug) {
                fprintf(stderr,
                        "WARNING: Couldn't find a symbol for addr=0x%lx\n",
                        addr);
        }

        return -1;
}

/* Adds a symbol to the per-PID symbol table.
   XXX: Check for duplicates and throw a warning */
void debug_i915_add_sym(Elf64_Sym *symbol, Elf *elf, int string_table_index,
                        int pid_index, hash_table(sym_str_t, Debug_Info) debug_info_table)
{
        struct i915_symbol_table *table;
        struct i915_symbol_entry *entry;
        int num_syms;
        char *name;
        Debug_Info *info;

        pthread_rwlock_wrlock(&debug_i915_info_lock);

        table = &(debug_i915_info.symtabs[pid_index]);

        /* Grow the symbol table */
        table->num_syms++;
        num_syms = table->num_syms;
        table->symtab = realloc(table->symtab,
                                sizeof(struct i915_symbol_entry) * num_syms);
        /* Add this symbol to the table */
        entry = &(table->symtab[table->num_syms - 1]);
        memset(entry, 0, sizeof(*entry));
        entry->start_addr = (uint64_t)symbol->st_value;

        name = elf_strptr(elf, string_table_index, symbol->st_name);
        if (name == NULL) {
                entry->symbol   = strdup("???");
                entry->filename = strdup("<unknown>");
        } else {
                info = hash_table_get_val(debug_info_table, name);
                if (info != NULL) {
                        entry->filename = strdup(info->filename);
                        entry->linenum  = info->linenum;
                }
                entry->symbol =
                        cplus_demangle(name, DMGL_NO_OPTS | DMGL_PARAMS | DMGL_AUTO);
                if (entry->symbol == NULL) {
                        entry->symbol = strdup(name);
                }
        }

        debug_printf("    Symbol 0x%lx:%s @ %s:%d\n", entry->start_addr,
                entry->symbol, entry->filename, entry->linenum);

        pthread_rwlock_unlock(&debug_i915_info_lock);
}

void handle_elf_symtab(Elf *elf, Elf_Scn *section, size_t string_table_index,
                       int pid_index, hash_table(sym_str_t, Debug_Info) debug_info_table)
{
        Elf_Data *section_data;
        size_t num_symbols, i;
        Elf64_Sym *symbols;

        section_data = elf_getdata(section, NULL);
        while (section_data != NULL) {
                if (!(section_data->d_type == ELF_T_SYM)) {
                        /* Why would data in a .symtab not be a symbol...? */
                        continue;
                }

                num_symbols = section_data->d_size / sizeof(Elf64_Sym);
                symbols = (Elf64_Sym *)section_data->d_buf;
                for (i = 0; i < num_symbols; i++) {
                        if (ELF64_ST_TYPE(symbols[i].st_info) == STT_FUNC) {
                                /* Add an entry into our internal symbol tables, and record
                                   the name and address */

                                debug_i915_add_sym(&(symbols[i]), elf,
                                                   string_table_index,
                                                   pid_index, debug_info_table);
                        }
                }

                /* Go to the next buffer of symbols, if applicable */
                section_data = elf_getdata(section, section_data);
        }
}

static int dwarf_func_cb(Dwarf_Die *diep, void *arg) {
        const char                        *name;
        const char                        *dwarf_filename;
        char                              *filename;
        int                                probably_jit;
        char                              *base;
        Debug_Info                         info;
        hash_table(sym_str_t, Debug_Info)  debug_info_table;
        Debug_Info                        *existing_info;


        name = dwarf_diename(diep);
        if (name == NULL) {
                goto out;
        }

        dwarf_filename = dwarf_decl_file(diep);

        if (dwarf_filename == NULL) {
            filename = strdup("<unknown>");
        } else {
            filename = strdup(dwarf_filename);

            probably_jit = 1;

            for (base = basename(filename); *base; base += 1) {
                if (!isdigit(*base)){
                    probably_jit = 0;
                }
            }

            if (probably_jit) {
                free(filename);
                filename = strdup("JIT");
            }
        }

        info.filename = filename;

        info.linenum = 0;
        dwarf_decl_line(diep, &info.linenum);

        debug_info_table = (hash_table(sym_str_t, Debug_Info))arg;

        if ((existing_info = hash_table_get_val(debug_info_table, (char*)name)) != NULL) {
                if (existing_info->filename != NULL) {
                        free(existing_info->filename);
                }
                existing_info->filename = info.filename;
                existing_info->linenum  = info.linenum;
        } else {
                hash_table_insert(debug_info_table, strdup(name), info);
        }

out:;
        return DWARF_CB_OK;
}

hash_table(sym_str_t, Debug_Info) build_debug_info_table(Elf *elf)
{
        hash_table(sym_str_t, Debug_Info)  debug_info_table;
        Dwarf                             *dwarf;
        Dwarf_CU                          *cu;
        Dwarf_CU                          *next_cu;
        Dwarf_Half                         version;
        uint8_t                            unit_type;
        int                                retval;
        Dwarf_Die                          cudie;
        Dwarf_Die                          subdie;


        debug_info_table = hash_table_make_e(sym_str_t, Debug_Info, str_hash, str_equ);

        dwarf = dwarf_begin_elf(elf, DWARF_C_READ, NULL);

        if (dwarf == NULL) {
/*                 fprintf(stderr, "error opening dwarf from elf: %s\n", dwarf_errmsg(dwarf_errno())); */
                goto out;
        }


        cu      = NULL;
        next_cu = NULL;

        do {
                cu = next_cu;

                version   = 123;
                unit_type = 123;

                retval = dwarf_get_units(dwarf, cu, &next_cu, &version, &unit_type, &cudie, &subdie);

                if (retval != 0) {
                        break;
                }

                dwarf_getfuncs(&cudie, dwarf_func_cb, debug_info_table, 0);

        } while (next_cu != NULL);

        dwarf_end(dwarf);

out:;
        return debug_info_table;
}

void free_debug_info_table(hash_table(sym_str_t, Debug_Info) debug_info_table) {
        char *key;
        Debug_Info *val;

        hash_table_traverse(debug_info_table, key, val) {
                free(key);
                free(val->filename);
        }

        hash_table_free(debug_info_table);
}

void handle_elf(unsigned char *data, uint64_t data_size, int pid_index)
{
        Elf *elf;
        hash_table(sym_str_t, Debug_Info) debug_info_table;
        Elf64_Ehdr *elf_header;
        Elf_Scn *section;
        Elf64_Shdr *section_header;
        int retval;
        size_t string_table_index;


        /* Initialize the ELF from the buffer */
        elf = elf_memory((char *)data, data_size);
        if (!elf) {
                fprintf(stderr, "WARNING: Error reading an ELF file.\n");
                return;
        }

        /* Build a debug info table. */
        debug_info_table = build_debug_info_table(elf);

        /* Get the ELF header */
        elf_header = elf64_getehdr(elf);
        if (elf_header == NULL) {
                fprintf(stderr, "WARNING: Failed to get the ELF header.\n");
                goto cleanup;
        }

        /* Get the index of the string table section. */
        retval = elf_getshdrstrndx(elf, &string_table_index);
        if (retval != 0) {
                fprintf(stderr,
                        "WARNING: Failed to get the index of the ELF string table.\n");
                goto cleanup;
        }


        /* Iterate over ELF sections to find .symbtab sections */
        section = elf_nextscn(elf, NULL);
        while (section != NULL) {
                /* Get the section header */
                section_header = elf64_getshdr(section);
                if (section_header == NULL) {
                        fprintf(stderr,
                                "WARNING: There was an error reading the ELF section headers.\n");
                        goto cleanup;
                }

                /* Get the string name */
                debug_printf("Section: %s type: %d\n",
                        elf_strptr(elf, string_table_index,
                                section_header->sh_name),
                                section_header->sh_type);

                /* If this is a .symtab section, it'll be marked as SHT_SYMTAB */
                if (section_header->sh_type == SHT_SYMTAB) {
                        debug_printf("  Symbol table:\n");
                        handle_elf_symtab(elf, section, string_table_index,
                                          pid_index, debug_info_table);
                }

                /* Next section */
                section = elf_nextscn(elf, section);
        }

cleanup:
        free_debug_info_table(debug_info_table);

        retval = elf_end(elf);
        if (retval != 0) {
                fprintf(stderr, "WARNING: Failed to cleanup ELF object.\n");
        }
}

void handle_event_uuid(int debug_fd, struct prelim_drm_i915_debug_event *event,
                       int pid_index)
{
        struct prelim_drm_i915_debug_event_uuid *uuid;
        struct prelim_drm_i915_debug_read_uuid read_uuid = {};
        char uuid_str[37];
        int retval;
        unsigned char *data;

        uuid = (struct prelim_drm_i915_debug_event_uuid *)event;

        /* Only look at UUIDs being created with a nonzero size */
        if (!(event->flags & PRELIM_DRM_I915_DEBUG_EVENT_CREATE)) {
                return;
        }
        if (!uuid->payload_size) {
                return;
        }

        read_uuid.client_handle = uuid->client_handle;
        read_uuid.handle = uuid->handle;
        read_uuid.payload_size = uuid->payload_size;
        read_uuid.payload_ptr = (uint64_t)malloc(uuid->payload_size);
        retval = ioctl(debug_fd, PRELIM_I915_DEBUG_IOCTL_READ_UUID, &read_uuid);

        if (retval != 0) {
                fprintf(stderr, "  Failed to read a UUID!\n");
                goto cleanup;
        }

        memcpy(uuid_str, read_uuid.uuid, 37);
        data = (unsigned char *)read_uuid.payload_ptr;

        /* Check for the ELF magic bytes */
        if (*((uint32_t *)data) == 0x464c457f) {
                handle_elf(data, read_uuid.payload_size, pid_index);
        }
cleanup:
        free((void *)read_uuid.payload_ptr);
        return;
}

void handle_event_vm_bind(int debug_fd, struct prelim_drm_i915_debug_event *event,
                          int pid_index)
{
        struct prelim_drm_i915_debug_event_vm_bind *vm_bind;
        struct prelim_drm_i915_debug_vm_open vmo = {};
        int fd;
        uint8_t *ptr;

        vm_bind = (struct prelim_drm_i915_debug_event_vm_bind *)event;

        if (!(event->flags & PRELIM_DRM_I915_DEBUG_EVENT_CREATE)) {
                return;
        }

        debug_printf("vm_handle=%llu va_start=0x%llx va_length=%llu num_uuids=%u flags=0x%x\n",
               vm_bind->vm_handle, vm_bind->va_start, vm_bind->va_length, vm_bind->num_uuids,
               vm_bind->flags);

        vmo.client_handle = vm_bind->client_handle;
        vmo.handle = vm_bind->vm_handle;
        vmo.flags = PRELIM_I915_DEBUG_VM_OPEN_READ_ONLY;
        fd = ioctl(debug_fd, PRELIM_I915_DEBUG_IOCTL_VM_OPEN, &vmo);

        if (fd < 0) {
                fprintf(stderr,
                        "Failed to get fd from vm_open_ioctl: %d\n", fd);
                return;
        }

        ptr = (uint8_t *) mmap(NULL, vm_bind->va_length, PROT_READ, MAP_SHARED, fd, vm_bind->va_start);
        if (ptr == MAP_FAILED) {
                fprintf(stderr, "FAILED TO MMAP: %d\n", errno);
                goto cleanup;
        }

/*         store_buffer_copy(vm_id, vm_bind->va_start, ptr, vm_bind->va_length); */
        munmap(ptr, vm_bind->va_length);

cleanup:
        return;
}

void handle_event_vm(int fd, struct prelim_drm_i915_debug_event *event, int pid_index)
{
        struct prelim_drm_i915_debug_event_vm *vm_event;
        struct vm_profile *vm;

        vm_event = (struct prelim_drm_i915_debug_event_vm *)event;

        if (!(event->flags & PRELIM_DRM_I915_DEBUG_EVENT_CREATE)) {
                return;
        }

        printf("handle=%llu\n", vm_event->handle);
        fflush(stdout);

        vm = acquire_ordered_vm_profile(vm_counter);

        while (!vm) {
                pthread_mutex_lock(&debug_i915_vm_create_lock);
                if (pthread_cond_wait(&debug_i915_vm_create_cond, &debug_i915_vm_create_lock) != 0) {
                        fprintf(stderr, "Failed to wait on the debug_i915 condition.\n");
                        pthread_mutex_unlock(&debug_i915_vm_create_lock);
                        goto cleanup;
                }
                pthread_mutex_unlock(&debug_i915_vm_create_lock);
                vm = acquire_ordered_vm_profile(vm_counter);
        }

        printf("debug_i915 got a vm for %llu (order %u)!\n", vm_event->handle, vm_counter);
        fflush(stdout);
        vm->debugger_vm_id = vm_event->handle;
        release_vm_profile(vm);
cleanup:
        vm_counter++;
        return;
}

/* Returns whether an event was actually read. */
int read_debug_i915_event(int fd, int pid_index)
{
        int retval, ack_retval;
        struct prelim_drm_i915_debug_event_ack ack_event = {};

        __attribute__((aligned(__alignof__(struct prelim_drm_i915_debug_event))))
        char event_buff[sizeof(struct prelim_drm_i915_debug_event) + MAX_EVENT_SIZE];

        struct prelim_drm_i915_debug_event *event;

        event = (struct prelim_drm_i915_debug_event *)event_buff;

        memset(event, 0,
               sizeof(struct prelim_drm_i915_debug_event) + MAX_EVENT_SIZE);

        event->size = MAX_EVENT_SIZE;
        event->type = PRELIM_DRM_I915_DEBUG_EVENT_READ;
        event->flags = 0;

        retval = ioctl(fd, PRELIM_I915_DEBUG_IOCTL_READ_EVENT, event);

        if (retval != 0) {
                if (errno == ETIMEDOUT || errno == EAGAIN) {
                        /* No more events. */
                } else {
                        fprintf(stderr, "read_event failed with: %d, errno=%d\n", retval, errno);
                }
                errno = 0;
                return 0;
        }
        /* Handle the event */
        if (event->type == PRELIM_DRM_I915_DEBUG_EVENT_UUID) {
                handle_event_uuid(fd, event, pid_index);
#ifdef BUFFER_COPY_METHOD_DEBUG
        } else if (event->type == PRELIM_DRM_I915_DEBUG_EVENT_VM_BIND) {
                handle_event_vm_bind(fd, event, pid_index);
        } else if (event->type == PRELIM_DRM_I915_DEBUG_EVENT_VM) {
                handle_event_vm(fd, event, pid_index);
#endif
        }

        /* ACK the event, otherwise the workload will stall. */
        if (event->flags & PRELIM_DRM_I915_DEBUG_EVENT_NEED_ACK) {
                ack_event.type = event->type;
                ack_event.seqno = event->seqno;
                ack_retval = ioctl(fd, PRELIM_I915_DEBUG_IOCTL_ACK_EVENT,
                                   &ack_event);
                if (ack_retval != 0) {
                        fprintf(stderr, "  Failed to ACK event!\n");
                        return 1;
                }
        }

        return 1;
}

void read_debug_i915_events(int fd, int pid_index)
{
        while (read_debug_i915_event(fd, pid_index));
}

char *debug_i915_event_to_str(int debug_event)
{
        return debug_events[debug_event];
}

void free_debug_i915() {
        int i;
        struct i915_symbol_table *symtab;
        int n;
        struct i915_symbol_entry *entry;

        for (i = 0; i < MAX_PIDS; i += 1) {
                symtab = &debug_i915_info.symtabs[i];

                for (n = 0; n < symtab->num_syms; n += 1) {
                        entry = symtab->symtab + n;
                        if (entry->symbol != NULL) {
                                free(entry->symbol);
                        }
                        if (entry->filename != NULL) {
                                free(entry->filename);
                        }
                }

                free(symtab->symtab);

                memset(symtab, 0, sizeof(*symtab));
        }
}
