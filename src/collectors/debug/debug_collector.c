/*
Copyright 2025 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

#if GPU_DRIVER == GPU_DRIVER_xe
#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>
#endif

#include "commands/record.h"

#include "printers/interval/interval_printer.h"
#include "printers/debug/debug_printer.h"
#include "debug_collector.h"
#include "stores/gpu_kernel.h"
#include "utils/utils.h"
#include "utils/hash_table.h"
#include "utils/demangle.h"

struct eudebug_info_t eudebug_info;
pthread_rwlock_t eudebug_info_lock;

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

void deinit_eudebug(int index)
{

        pthread_rwlock_wrlock(&eudebug_info_lock);
        close(eudebug_info.pollfds[index].fd);
        memset(eudebug_info.pollfds + index, 0, sizeof(struct pollfd));
        eudebug_info.pids[index] = 0;

        /* Free symtab info */
/*         eudebug_info.symtabs[eudebug_info.num_pids].pid = pid; */

/*         eudebug_info.num_pids--; */
        pthread_rwlock_unlock(&eudebug_info_lock);
}

void init_eudebug(int fd, int pid)
{
        int eudebug_fd;
        int i;
        int flags;

        /* This is called from the bpf_collect_thread when we see a new
         * PID. We must protect eudebug_info from data races when it
         * is likely to be simultaneously accessed from
         * eudebug_collect_thread. */

        pthread_rwlock_rdlock(&eudebug_info_lock);

        if (shader_binaries == NULL) {
                shader_binaries = tree_make(uint64_t, shader_binary_ptr);
        }

        /* First, check if we've already initialized this PID. */
        for (i = 0; i < eudebug_info.num_pids; i++) {
                if (eudebug_info.pids[i] == pid) {
                        goto out_unlock;
                }
        }

        pthread_rwlock_unlock(&eudebug_info_lock);

        /* Open the fd to begin debugging this PID */
#if GPU_DRIVER == GPU_DRIVER_xe
        struct drm_xe_eudebug_connect open = {};
        open.pid = pid;
        eudebug_fd = ioctl(fd, DRM_IOCTL_XE_EUDEBUG_CONNECT, &open);
#elif GPU_DRIVER == GPU_DRIVER_i915
        struct prelim_drm_i915_debugger_open_param open = {};
        open.pid = pid;
        eudebug_fd = ioctl(fd, PRELIM_DRM_IOCTL_I915_DEBUGGER_OPEN, &open);
#endif

        if (eudebug_fd < 0) {
                debug_printf("Failed to open the debug interface for PID %d: %d.\n", pid, eudebug_fd);
                goto out;
        }

        debug_printf("initialized eudebug for PID %d\n", pid);

        flags = fcntl(eudebug_fd, F_GETFL, 0);
        fcntl(eudebug_fd, F_SETFL, flags | O_NONBLOCK);

        pthread_rwlock_wrlock(&eudebug_info_lock);

        /* @TODO: check for MAX_PIDS */

        /* Add the PID and fd to the arrays */
        eudebug_info.pollfds[eudebug_info.num_pids].fd = eudebug_fd;
        eudebug_info.pollfds[eudebug_info.num_pids].events = POLLIN;
        eudebug_info.pids[eudebug_info.num_pids] = pid;
        eudebug_info.num_pids++;

out_unlock:;
        pthread_rwlock_unlock(&eudebug_info_lock);
out:;
}

void set_kernel_info(uint64_t addr, uint64_t size, uint64_t symbol_id, uint64_t filename_id, int linenum) {
        struct shader *shader;

        shader = acquire_or_create_shader(addr);

        assert((size == 0 || shader->size == 0 || size == shader->size) && "shader size mismatch");

        size        && (shader->size        = size);
        symbol_id   && (shader->symbol_id   = symbol_id);
        filename_id && (shader->filename_id = filename_id);
        linenum     && (shader->linenum     = linenum);

        release_shader(shader);
}

void set_kernel_binary(uint64_t addr, unsigned char *bytes, uint64_t size) {
        struct shader *shader;

        if (bytes == NULL || size == 0) { return; }

        shader = acquire_or_create_shader(addr);

        assert(shader->binary == NULL && "shader binary already set");

        if (shader->size != 0 && shader->size > size) {
                assert(0 && "shader size mismatch");
        }

        shader->binary = malloc(size);
        memcpy(shader->binary, bytes, size);
        shader->size = size;

        release_shader(shader);
}

static void extract_elf_shader_binary(Elf_Scn *section) {
        Elf64_Shdr *shdr;
        uint64_t    address;
        Elf_Data   *data;

        shdr    = elf64_getshdr(section);
        address = shdr->sh_addr & SHADER_ADDRESS_MASK;
        data    = elf_getdata(section, NULL);

        set_kernel_binary(address, data->d_buf, data->d_size);
}

/* Adds a symbol to the per-PID symbol table.
   XXX: Check for duplicates and throw a warning */
static void extract_elf_symbol(Elf64_Sym *symbol, Elf *elf, int string_table_index, hash_table(sym_str_t, Debug_Info) debug_info_table)
{
        uint64_t    address;
        char       *name;
        char       *filename;
        int         linenum;
        char       *demangled;
        Debug_Info *info;
        Elf_Scn    *section;

        address   = DRM_CANONICALIZE(symbol->st_value);
        name      = elf_strptr(elf, string_table_index, symbol->st_name);
        demangled = NULL;
        filename  = NULL;
        linenum   = 0;

        if (name == NULL) {
                name = "???";
        } else {
                info = hash_table_get_val(debug_info_table, name);
                if (info != NULL) {
                        filename = info->filename;
                        linenum  = info->linenum;
                }
                demangled = demangle(name);
                if (demangled != NULL) {
                        name = demangled;
                }
        }
        if (filename == NULL) {
                filename = "<unknown>";
        }

        debug_printf("    Symbol 0x%lx:%s @ %s:%d\n", address, name, filename, linenum);

        set_kernel_info(address & SHADER_ADDRESS_MASK, symbol->st_size, print_string(name), print_string(filename), linenum);

        if (demangled) {
                free(demangled);
        }

        section = elf_getscn(elf, symbol->st_shndx);

        extract_elf_shader_binary(section);
}

static void extract_elf_symtab(Elf *elf, Elf_Scn *section, size_t string_table_index, hash_table(sym_str_t, Debug_Info) debug_info_table)
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

                                extract_elf_symbol(&(symbols[i]), elf, string_table_index, debug_info_table);
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

static hash_table(sym_str_t, Debug_Info) build_debug_info_table(Elf *elf)
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

static void free_debug_info_table(hash_table(sym_str_t, Debug_Info) debug_info_table) {
        char *key;
        Debug_Info *val;

        hash_table_traverse(debug_info_table, key, val) {
                free(key);
                free(val->filename);
        }

        hash_table_free(debug_info_table);
}

static void extract_elf_progbits(Elf *elf, Elf_Scn *section, Elf64_Shdr *section_header, size_t string_table_index, hash_table(sym_str_t, Debug_Info) debug_info_table) {
        uint64_t    address;
        char       *name;
        int         len;
        char       *seek;
        char       *filename;
        int         linenum;
        char       *demangled;
        Debug_Info *info;

        address = DRM_CANONICALIZE(section_header->sh_addr);

        name      = elf_strptr(elf, string_table_index, section_header->sh_name);
        len       = strlen(name);
        demangled = NULL;

        if (len == 0) { return; }

        /* Chop off *. prefix. */
        for (seek = name + len; seek > name && *(seek - 1) != '.'; seek -= 1);
        name = seek;

        if (*name == 0) { return; }

        filename = NULL;
        linenum  = 0;

        info = hash_table_get_val(debug_info_table, name);
        if (info != NULL) {
                filename = info->filename;
                linenum  = info->linenum;
        }
        demangled = demangle(name);
        if (demangled != NULL) {
                name = demangled;
        }
        if (filename == NULL) {
                filename = "<unknown>";
        }

        debug_printf("    Symbol 0x%lx:%s @ %s:%d\n", address, name, filename, linenum);

        set_kernel_info(address & SHADER_ADDRESS_MASK, section_header->sh_size, print_string(name), print_string(filename), linenum);

        if (demangled != NULL) {
                free(demangled);
        }

        extract_elf_shader_binary(section);
}

void extract_elf_kernel_info(const unsigned char *elf_data, uint64_t elf_data_size)
{
        Elf *elf;
        hash_table(sym_str_t, Debug_Info) debug_info_table;
        Elf64_Ehdr *elf_header;
        int seen_symtab;
        Elf_Scn *section;
        Elf64_Shdr *section_header;
        int retval;
        size_t string_table_index;

        debug_printf("Processing ELF\n");

        /* Initialize the ELF from the buffer */
        elf = elf_memory((char *)elf_data, elf_data_size);
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
                        extract_elf_symtab(elf, section, string_table_index, debug_info_table);
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
                                debug_printf("Progbits: %s\n", elf_strptr(elf, string_table_index, section_header->sh_name));
                                extract_elf_progbits(elf, section, section_header, string_table_index, debug_info_table);
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

#if GPU_DRIVER == GPU_DRIVER_xe
static void handle_event_uuid(int debug_fd, struct drm_xe_eudebug_event *event, int pid_index)
#elif GPU_DRIVER == GPU_DRIVER_i915
static void handle_event_uuid(int debug_fd, struct prelim_drm_i915_debug_event *event, int pid_index)
#endif
{
        int retval;
        unsigned char *data;
        uint64_t size;

#if GPU_DRIVER == GPU_DRIVER_xe
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
#elif GPU_DRIVER == GPU_DRIVER_i915
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
                extract_elf_kernel_info(data, size);
        }
cleanup:
        free((void *)data);
        return;
}


#if GPU_DRIVER == GPU_DRIVER_xe
/* Returns whether an event was actually read. */
int read_eudebug_event(int fd, int pid_index)
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
#elif GPU_DRIVER == GPU_DRIVER_i915
/* Returns whether an event was actually read. */
int read_eudebug_event(int fd, int pid_index)
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

void read_eudebug_events(int fd, int pid_index)
{
        while (read_eudebug_event(fd, pid_index));
}

char *debug_event_to_str(int debug_event)
{
        return debug_events[debug_event];
}

struct shader_binary *get_shader_binary(uint64_t gpu_addr) {
        tree_it(uint64_t, shader_binary_ptr) it;

        if (shader_binaries == NULL) {
                return NULL;
        }

        it = tree_lookup(shader_binaries, gpu_addr);

        return tree_it_good(it) ? tree_it_val(it) : NULL;
}
