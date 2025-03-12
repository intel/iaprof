#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <libgen.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#include <libelf.h>
#include <elfutils/libdw.h>

#ifdef XE_DRIVER
#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>
#endif

#include "iaprof.h"
#include "debug_collector.h"
#include "stores/buffer_profile.h"
#include "utils/utils.h"
#include "utils/hash_table.h"
#include "utils/demangle.h"

#ifdef SLOW_MODE
static uint32_t vm_bind_counter = 0;
#endif

struct debug_info_t debug_info;
pthread_rwlock_t debug_info_lock;

/* For waiting on vm_bind events from BPF */
pthread_cond_t debug_vm_bind_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t debug_vm_bind_lock = PTHREAD_MUTEX_INITIALIZER;

typedef char *sym_str_t;

typedef struct {
        char *filename;
        int   linenum;
} Debug_Info;

use_hash_table_e(sym_str_t, Debug_Info, str_equ);

typedef struct shader_binary *shader_binary_ptr;

use_tree(uint64_t, shader_binary_ptr);

static tree(uint64_t, shader_binary_ptr) shader_binaries;

pthread_mutex_t debug_shader_binaries_lock = PTHREAD_MUTEX_INITIALIZER;

void deinit_debug(int index)
{

        pthread_rwlock_wrlock(&debug_info_lock);
        close(debug_info.pollfds[index].fd);
        memset(debug_info.pollfds + index, 0, sizeof(struct pollfd));
        debug_info.pids[index] = 0;

        /* Free symtab info */
/*         debug_info.symtabs[debug_info.num_pids].pid = pid; */

/*         debug_info.num_pids--; */
        pthread_rwlock_unlock(&debug_info_lock);
}

void init_debug(int fd, int pid)
{
        int debug_fd;
        int i;
        int flags;

        /* This is called from the bpf_collect_thread when we see a new
         * PID. We must protect debug_info from data races when it
         * is likely to be simultaneously accessed from
         * debug_collect_thread. */

        pthread_rwlock_rdlock(&debug_info_lock);

        if (shader_binaries == NULL) {
                shader_binaries = tree_make(uint64_t, shader_binary_ptr);
        }

        /* First, check if we've already initialized this PID. */
        for (i = 0; i < debug_info.num_pids; i++) {
                if (debug_info.pids[i] == pid) {
                        goto out_unlock;
                }
        }

        pthread_rwlock_unlock(&debug_info_lock);

        /* Open the fd to begin debugging this PID */
#ifdef XE_DRIVER
        struct drm_xe_eudebug_connect open = {};
        open.pid = pid;
        debug_fd = ioctl(fd, DRM_IOCTL_XE_EUDEBUG_CONNECT, &open);
#else
        struct prelim_drm_i915_debugger_open_param open = {};
        open.pid = pid;
        debug_fd = ioctl(fd, PRELIM_DRM_IOCTL_I915_DEBUGGER_OPEN, &open);
#endif

        if (debug_fd < 0) {
                WARN("Failed to open the debug interface for PID %d: %d.\n", pid, debug_fd);
                goto out;
        }

        flags = fcntl(debug_fd, F_GETFL, 0);
        fcntl(debug_fd, F_SETFL, flags | O_NONBLOCK);

        pthread_rwlock_wrlock(&debug_info_lock);

        /* @TODO: check for MAX_PIDS */

        /* Add the PID and fd to the arrays */
        debug_info.pollfds[debug_info.num_pids].fd = debug_fd;
        debug_info.pollfds[debug_info.num_pids].events = POLLIN;
        debug_info.pids[debug_info.num_pids] = pid;
        debug_info.symtabs[debug_info.num_pids].pid = pid;
        debug_info.num_pids++;

out_unlock:;
        pthread_rwlock_unlock(&debug_info_lock);
out:;
}

int debug_get_sym(int pid, uint64_t addr, char **out_gpu_symbol, char **out_gpu_file, int *out_gpu_line)
{
        int i, j;
        struct symbol_table *table;
        struct symbol_entry *entry;

        debug_printf("Finding symbol for pid=%d addr=0x%lx\n", pid, addr);

        for (i = 0; i < debug_info.num_pids; i++) {
                /* Find the addr range in this PID's symbol table */
                table = &(debug_info.symtabs[i]);

                if (table->pid != pid) { continue; }

                for (j = 0; j < table->num_syms; j++) {
                        entry = &(table->symtab[j]);
                        if (addr >= entry->start_addr && addr < entry->start_addr + entry->size) {
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

                break;
        }

        WARN("Couldn't find a symbol for addr=0x%lx\n", addr);

        return -1;
}

void debug_add_sym(char *symbol, uint64_t start_addr, uint64_t size, char *filename, int linenum, int pid_index) {
        struct symbol_table *table;
        int num_syms;
        struct symbol_entry *entry;

        pthread_rwlock_wrlock(&debug_info_lock);

        table = &(debug_info.symtabs[pid_index]);

        /* Grow the symbol table */
        table->num_syms++;
        num_syms = table->num_syms;
        table->symtab = realloc(table->symtab,
                                sizeof(struct symbol_entry) * num_syms);

        /* Add this symbol to the table */
        entry = &(table->symtab[table->num_syms - 1]);
        memset(entry, 0, sizeof(*entry));
        entry->start_addr = start_addr;
        entry->size = size;
        entry->symbol = symbol;
        entry->filename = filename;
        entry->linenum = linenum;

        pthread_rwlock_unlock(&debug_info_lock);
}

void debug_add_shader_binary(Elf_Scn *section) {
        Elf64_Shdr *shdr;
        uint64_t address;
        tree_it(uint64_t, shader_binary_ptr) it;
        struct shader_binary *bin;
        Elf_Data *data;

        shdr = elf64_getshdr(section);

        address = DRM_CANONICALIZE(shdr->sh_addr);

        it = tree_lookup(shader_binaries, address);
        if (tree_it_good(it)) {
                free(tree_it_val(it));
                tree_delete(shader_binaries, address);
        }
        bin = malloc(sizeof(struct shader_binary) + shdr->sh_size);
        memset(bin, 0, sizeof(*bin));

        bin->start = address;
        bin->size = shdr->sh_size;

        data = elf_getdata(section, NULL);

        memcpy(bin->bytes, data->d_buf, bin->size);

        pthread_mutex_lock(&debug_shader_binaries_lock);
        tree_insert(shader_binaries, bin->start, bin);
        pthread_mutex_unlock(&debug_shader_binaries_lock);
}

/* Adds a symbol to the per-PID symbol table.
   XXX: Check for duplicates and throw a warning */
void handle_elf_symbol(Elf64_Sym *symbol, Elf *elf, int string_table_index,
                        int pid_index, hash_table(sym_str_t, Debug_Info) debug_info_table)
{
        uint64_t address;
        char *name;
        char *filename;
        int linenum;
        char *demangled;
        Debug_Info *info;
        Elf_Scn *section;

        address = DRM_CANONICALIZE(symbol->st_value);
        name = elf_strptr(elf, string_table_index, symbol->st_name);
        filename = NULL;
        linenum = 0;

        if (name == NULL) {
                name = strdup("???");
        } else {
                info = hash_table_get_val(debug_info_table, name);
                if (info != NULL) {
                        filename = strdup(info->filename);
                        linenum  = info->linenum;
                }
                demangled = demangle(name);
                if (demangled != NULL) {
                        name = demangled;
                } else {
                        name = strdup(name);
                }
        }
        if (filename == NULL) {
                filename = strdup("<unknown>");
        }

        debug_printf("    Symbol 0x%lx:%s @ %s:%d\n", address,
                name, filename, linenum);

        debug_add_sym(name, address, symbol->st_size, filename, linenum, pid_index);

        section = elf_getscn(elf, symbol->st_shndx);
        debug_add_shader_binary(section);
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

                                handle_elf_symbol(&(symbols[i]), elf,
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


        debug_info_table = hash_table_make(sym_str_t, Debug_Info, str_hash);

        dwarf = dwarf_begin_elf(elf, DWARF_C_READ, NULL);

        if (dwarf == NULL) {
/*                 WARN("error opening dwarf from elf: %s\n", dwarf_errmsg(dwarf_errno())); */
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

void handle_elf_progbits(Elf *elf, Elf_Scn *section, Elf64_Shdr *section_header, size_t string_table_index, int pid_index, hash_table(sym_str_t, Debug_Info) debug_info_table) {
        uint64_t    address;
        char       *name;
        int         len;
        char       *seek;
        char       *filename;
        int         linenum;
        char       *demangled;
        Debug_Info *info;

        address = DRM_CANONICALIZE(section_header->sh_addr);

        name = elf_strptr(elf, string_table_index, section_header->sh_name);
        len  = strlen(name);

        if (len == 0) { return; }

        /* Chop off *. prefix. */
        for (seek = name + len; seek > name && *(seek - 1) != '.'; seek -= 1);
        name = seek;

        if (*name == 0) { return; }

        filename = NULL;
        linenum  = 0;

        info = hash_table_get_val(debug_info_table, name);
        if (info != NULL) {
                filename = strdup(info->filename);
                linenum  = info->linenum;
        }
        demangled = demangle(name);
        if (demangled != NULL) {
                name = demangled;
        } else {
                name = strdup(name);
        }

        if (filename == NULL) {
                filename = strdup("<unknown>");
        }

        debug_printf("    Symbol 0x%lx:%s @ %s:%d\n", address,
                name, filename, linenum);

        debug_add_sym(name, address, section_header->sh_size, filename, linenum, pid_index);
        debug_add_shader_binary(section);
}

void handle_elf(unsigned char *data, uint64_t data_size, int pid_index)
{
        Elf *elf;
        hash_table(sym_str_t, Debug_Info) debug_info_table;
        Elf64_Ehdr *elf_header;
        int seen_symtab;
        Elf_Scn *section;
        Elf64_Shdr *section_header;
        int retval;
        size_t string_table_index;

        pthread_rwlock_rdlock(&debug_info_lock);
        debug_printf("ELF for pid %d\n", debug_info.pids[pid_index]);
        pthread_rwlock_unlock(&debug_info_lock);

        /* Initialize the ELF from the buffer */
        elf = elf_memory((char *)data, data_size);
        if (!elf) {
                WARN("Error reading an ELF file.\n");
                return;
        }

        /* Build a debug info table. */
        debug_info_table = build_debug_info_table(elf);

        /* Get the ELF header */
        elf_header = elf64_getehdr(elf);
        if (elf_header == NULL) {
                WARN("Failed to get the ELF header.\n");
                goto cleanup;
        }

        /* Get the index of the string table section. */
        retval = elf_getshdrstrndx(elf, &string_table_index);
        if (retval != 0) {
                WARN("Failed to get the index of the ELF string table.\n");
                goto cleanup;
        }


        /* Iterate over ELF sections to find .symbtab sections */
        seen_symtab = 0;
        section = elf_nextscn(elf, NULL);
        while (section != NULL) {
                /* Get the section header */
                section_header = elf64_getshdr(section);
                if (section_header == NULL) {
                        WARN("There was an error reading the ELF section headers.\n");
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
                        seen_symtab = 1;
                }

                /* Next section */
                section = elf_nextscn(elf, section);
        }

        if (!seen_symtab) {
                section = elf_nextscn(elf, NULL);
                while (section != NULL) {
                        /* Get the section header */
                        section_header = elf64_getshdr(section);
                        if (section_header == NULL) {
                                WARN("There was an error reading the ELF section headers.\n");
                                goto cleanup;
                        }

                        if (section_header->sh_type == SHT_PROGBITS) {
                                /* Get the string name */
                                debug_printf("Progbits: %s\n",
                                        elf_strptr(elf, string_table_index,
                                                section_header->sh_name));

                                handle_elf_progbits(elf, section, section_header, string_table_index,
                                                pid_index, debug_info_table);
                        }

                        /* Next section */
                        section = elf_nextscn(elf, section);
                }

        }

cleanup:
        free_debug_info_table(debug_info_table);

        retval = elf_end(elf);
        if (retval != 0) {
                WARN("Failed to cleanup ELF object.\n");
        }
}

#ifdef XE_DRIVER
void handle_event_uuid(int debug_fd, struct drm_xe_eudebug_event *event,
                       int pid_index)
#else
void handle_event_uuid(int debug_fd, struct prelim_drm_i915_debug_event *event,
                       int pid_index)
#endif
{
        int retval;
        unsigned char *data;
        uint64_t size;

#ifdef XE_DRIVER
        struct drm_xe_eudebug_event_metadata *uuid;
        struct drm_xe_eudebug_read_metadata read_uuid = {};
        uuid = (struct drm_xe_eudebug_event_metadata *)event;
        if (!(event->flags & DRM_XE_EUDEBUG_EVENT_CREATE)) {
                return;
        }
        if (!uuid->len) {
                return;
        }
        read_uuid.client_handle = uuid->client_handle;
        read_uuid.metadata_handle = uuid->metadata_handle;
        read_uuid.size = uuid->len;
        read_uuid.ptr = (uint64_t)malloc(uuid->len);
        read_uuid.flags = 0;

        errno = 0;
        retval = ioctl(debug_fd, DRM_XE_EUDEBUG_IOCTL_READ_METADATA, &read_uuid);

        data = (unsigned char *)read_uuid.ptr;
        size = read_uuid.size;
#else
        struct prelim_drm_i915_debug_event_uuid *uuid;
        struct prelim_drm_i915_debug_read_uuid read_uuid = {};
        uuid = (struct prelim_drm_i915_debug_event_uuid *)event;
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

        errno = 0;
        retval = ioctl(debug_fd, PRELIM_I915_DEBUG_IOCTL_READ_UUID, &read_uuid);

        data = (unsigned char *)read_uuid.payload_ptr;
        size = read_uuid.payload_size;
#endif

        if (retval != 0) {
                fprintf(stderr, "  Failed to read metadata: %d!\n", errno);
                goto cleanup;
        }

        /* Check for the ELF magic bytes */
        if (*((uint32_t *)data) == 0x464c457f) {
                handle_elf(data, size, pid_index);
        }
cleanup:
        free((void *)data);
        return;
}


#ifdef SLOW_MODE
void handle_event_vm_bind(int debug_fd, struct prelim_drm_i915_debug_event *event,
                          int pid_index)
{
        struct vm_profile *vm;
        struct buffer_binding *bind;
        struct prelim_drm_i915_debug_event_vm_bind *vm_bind;
        uint64_t gpu_addr;
        char found;

        vm_bind = (struct prelim_drm_i915_debug_event_vm_bind *)event;

        if (!(event->flags & PRELIM_DRM_I915_DEBUG_EVENT_CREATE)) {
                return;
        }

        /* If any of the top 16 bits are set, it's an invalid address. We only want
           the bottom 48 bits. */
        gpu_addr = vm_bind->va_start;
        if (gpu_addr & 0xffff000000000000) {
                vm_bind_counter++;
                return;
        }

        debug_printf("vm_bind_debug vm_handle=%llu va_start=0x%lx va_length=%llu num_uuids=%u vm_bind_counter=%u\n",
               vm_bind->vm_handle, gpu_addr, vm_bind->va_length, vm_bind->num_uuids,
               vm_bind_counter);

        /* Wait on this VM_BIND to happen in BPF, so that we can know which VM
           to associate it with! */
        found = 0;
        while (!found) {
                pthread_mutex_lock(&debug_vm_bind_lock);

                FOR_BINDING(vm, bind, {
                        if (bind->vm_bind_order == vm_bind_counter) {
                                found = 1;
                                FOR_BINDING_CLEANUP(); goto out;
                        }
                });

                if (pthread_cond_wait(&debug_vm_bind_cond, &debug_vm_bind_lock) != 0) {
                        fprintf(stderr, "Failed to wait on the debug condition.\n");
                        pthread_mutex_unlock(&debug_vm_bind_lock);
                        goto cleanup;
                }

                FOR_BINDING(vm, bind, {
                        if (bind->vm_bind_order == vm_bind_counter) {
                                found = 1;
                                FOR_BINDING_CLEANUP(); goto out;
                        }
                });
out:;
                pthread_mutex_unlock(&debug_vm_bind_lock);
        }

cleanup:
        vm_bind_counter++;

        return;
}
#endif

#ifdef XE_DRIVER
/* Returns whether an event was actually read. */
int read_debug_event(int fd, int pid_index)
{
        int retval, ack_retval;
        struct drm_xe_eudebug_ack_event ack_event = {};
        uint32_t size;

        size = sizeof(struct drm_xe_eudebug_event) + MAX_EVENT_SIZE;

        /* Prepare the event struct to be read */
        __attribute__((aligned(__alignof__(struct drm_xe_eudebug_event))))
        char event_buff[size];
        struct drm_xe_eudebug_event *event;
        event = (struct drm_xe_eudebug_event *)event_buff;

        memset(event, 0, size);

        /* Call ioctl */
        event->len = size;
        event->type = DRM_XE_EUDEBUG_EVENT_READ;
        event->flags = 0;
        event->reserved = 0;
        retval = ioctl(fd, DRM_XE_EUDEBUG_IOCTL_READ_EVENT, event);

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
        if (event->type == DRM_XE_EUDEBUG_EVENT_METADATA) {
                handle_event_uuid(fd, event, pid_index);
#ifdef SLOW_MODE
        } else if (event->type == DRM_XE_EUDEBUG_EVENT_VM_BIND) {
                handle_event_vm_bind(fd, event, pid_index);
#endif
        }

        /* ACK the event, otherwise the workload will stall. */
        if (event->flags & DRM_XE_EUDEBUG_EVENT_NEED_ACK) {
                ack_event.type = event->type;
                ack_event.seqno = event->seqno;
                ack_retval = ioctl(fd, DRM_XE_EUDEBUG_IOCTL_ACK_EVENT,
                                   &ack_event);
                if (ack_retval != 0) {
                        fprintf(stderr, "  Failed to ACK event!\n");
                        return 1;
                }
        }

        return 1;
}
#else
/* Returns whether an event was actually read. */
int read_debug_event(int fd, int pid_index)
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
#ifdef SLOW_MODE
        } else if (event->type == PRELIM_DRM_I915_DEBUG_EVENT_VM_BIND) {
                handle_event_vm_bind(fd, event, pid_index);
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
#endif

void read_debug_events(int fd, int pid_index)
{
        while (read_debug_event(fd, pid_index));
}

char *debug_event_to_str(int debug_event)
{
        return debug_events[debug_event];
}

void free_debug() {
        int i;
        struct symbol_table *symtab;
        int n;
        struct symbol_entry *entry;

        for (i = 0; i < MAX_PIDS; i += 1) {
                symtab = &debug_info.symtabs[i];

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

struct shader_binary *get_shader_binary(uint64_t gpu_addr) {
        tree_it(uint64_t, shader_binary_ptr) it;

        if (shader_binaries == NULL) {
                return NULL;
        }

        it = tree_lookup(shader_binaries, gpu_addr);

        return tree_it_good(it) ? tree_it_val(it) : NULL;
}
