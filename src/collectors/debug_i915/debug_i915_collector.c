#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <libiberty/demangle.h>

#include <libelf.h>

#include "iaprof.h"
#include "debug_i915_collector.h"
#include "utils/utils.h"

void init_debug_i915(int i915_fd, int pid)
{
        int debug_fd;
        int i;
        
        /* First, check if we've already initialized this PID. */
        for (i = 0; i < debug_i915_info.num_pids; i++) {
                if (debug_i915_info.pids[i] == pid) {
                        return;
                }
        }
        
        /* Open the fd to begin debugging this PID */
        struct prelim_drm_i915_debugger_open_param open = {};
        open.pid = pid;
        debug_fd = ioctl(i915_fd, PRELIM_DRM_IOCTL_I915_DEBUGGER_OPEN, &open);
        if (debug_fd < 0) {
                fprintf(stderr, "Failed to open the debug interface for PID %d.\n", pid);
                return;
        }
        
        /* Add the PID and fd to the arrays */
        debug_i915_info.fds[debug_i915_info.num_pids] = debug_fd;
        debug_i915_info.pids[debug_i915_info.num_pids] = pid;
        debug_i915_info.symtabs[debug_i915_info.num_pids].pid = pid;
        debug_i915_info.num_pids++;
        
        add_to_epoll_fd(debug_fd);
}

char *debug_i915_get_sym(int pid, uint64_t addr)
{
        int i, pid_index;
        struct i915_symbol_table *table;
        struct i915_symbol_entry *entry;
        char less_than_last;
        
        if (debug) {
                fprintf(stderr, "Finding symbol for pid=%d addr=0x%lx\n",
                        pid, addr);
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
                fprintf(stderr, "WARNING: PID %d does not have GPU symbols.\n", pid);
                return NULL;
        }
        
        /* Find the addr range in this PID's symbol table */
        table = &(debug_i915_info.symtabs[pid_index]);
        for (i = 0; i < table->num_syms; i++) {
                entry = &(table->symtab[i]);
                if (addr < entry->start_addr) {
                        less_than_last = true;
                        continue;
                }
                if (less_than_last && (addr > entry->start_addr)) {
                        return entry->symbol;
                }
        }
        
        return NULL;
}

/* Adds a symbol to the per-PID symbol table.
   XXX: Check for duplicates and throw a warning */
void debug_i915_add_sym(Elf64_Sym *symbol, Elf *elf, int string_table_index, int pid_index)
{
        struct i915_symbol_table *table;
        struct i915_symbol_entry *entry;
        int num_syms;
        size_t len;
        char *name;
        
        table = &(debug_i915_info.symtabs[pid_index]);
        
        /* Grow the symbol table */
        table->num_syms++;
        num_syms = table->num_syms;
        table->symtab = realloc(table->symtab,
                                sizeof(struct i915_symbol_entry) * num_syms);
        /* Add this symbol to the table */
        entry = &(table->symtab[table->num_syms - 1]);
        entry->start_addr = (uint64_t) symbol->st_value;
        name = elf_strptr(elf, string_table_index, symbol->st_name);
        entry->symbol = cplus_demangle(name, DMGL_NO_OPTS | DMGL_PARAMS | DMGL_AUTO);
        
        if (debug) {
                printf("    Symbol 0x%lx:%s\n", entry->start_addr, entry->symbol);
        }
}


void handle_elf_symtab(Elf *elf, Elf_Scn *section, size_t string_table_index, int pid_index)
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
                symbols = (Elf64_Sym *) section_data->d_buf;
                for (i = 0; i < num_symbols; i++) {
                        if (ELF64_ST_TYPE(symbols[i].st_info) == STT_FUNC) {
                                /* Add an entry into our internal symbol tables, and record
                                   the name and address */
                                debug_i915_add_sym(&(symbols[i]), elf, string_table_index, pid_index);
                        }
                }
                
                /* Go to the next buffer of symbols, if applicable */
                section_data = elf_getdata(section, section_data);
        }
}

void handle_elf(unsigned char *data, uint64_t data_size, int pid_index)
{
        Elf *elf;
        Elf64_Ehdr *elf_header;
        Elf_Scn *section;
        Elf64_Shdr *section_header;
        int retval;
        size_t i, num_sections, string_table_index;
        
        /* Initialize the ELF from the buffer */
        elf = elf_memory((char *) data, data_size);
        if (!elf) {
                fprintf(stderr, "WARNING: Error reading an ELF file.\n");
                return;
        }
        
        /* Get the ELF header */
        elf_header = elf64_getehdr(elf);
        if (elf_header == NULL) {
                fprintf(stderr, "WARNING: Failed to get the ELF header.\n");
                goto cleanup;
        }
        
        /* Get the index of the string table section. */
        retval = elf_getshdrstrndx(elf, &string_table_index);
        if (retval != 0) {
                fprintf(stderr, "WARNING: Failed to get the index of the ELF string table.\n");
                goto cleanup;
        }
        
        /* Iterate over ELF sections to find .symbtab sections */
        section = elf_nextscn(elf, NULL);
        while (section != NULL) {
                
                /* Get the section header */
                section_header = elf64_getshdr(section);
                if (section_header == NULL) {
                        fprintf(stderr, "WARNING: There was an error reading the ELF section headers.\n");
                        goto cleanup;
                }
                
                /* Get the string name */
                if (debug) {
                        printf("Section: %s\n", elf_strptr(elf, string_table_index, section_header->sh_name));
                }
                
                /* If this is a .symtab section, it'll be marked as SHT_SYMTAB */
                if (section_header->sh_type == SHT_SYMTAB) {
                        if (debug) {
                                printf("  Symbol table:\n");
                        }
                        handle_elf_symtab(elf, section, string_table_index, pid_index);
                }
                
                /* Next section */
                section = elf_nextscn(elf, section);
        }
        
cleanup:
        retval = elf_end(elf);
        if (retval != 0) {
                fprintf(stderr, "WARNING: Failed to cleanup ELF object.\n");
        }
}

void handle_event_uuid(int debug_fd, struct prelim_drm_i915_debug_event *event, int pid_index)
{
        struct prelim_drm_i915_debug_event_uuid *uuid;
        struct prelim_drm_i915_debug_read_uuid read_uuid = {};
        char uuid_str[37];
        int retval, i;
        unsigned char *data;

        uuid = (struct prelim_drm_i915_debug_event_uuid *) event;

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
        read_uuid.payload_ptr = (uint64_t) malloc(uuid->payload_size);
        retval = ioctl(debug_fd, PRELIM_I915_DEBUG_IOCTL_READ_UUID, &read_uuid);
        
        if (retval != 0) {
                fprintf(stderr, "  Failed to read a UUID!\n");
                goto cleanup;
        }
        
        memcpy(uuid_str, read_uuid.uuid, 37);
        data = (unsigned char *) read_uuid.payload_ptr;
        
        /* Check for the ELF magic bytes */
        if (*((uint32_t *) data) == 0x464c457f) {
                handle_elf(data, read_uuid.payload_size, pid_index);
/*                 dump_buffer((unsigned char *)data, read_uuid.payload_size, 0); */
        }
cleanup:
        free((void *) read_uuid.payload_ptr);
        return;
}


int read_debug_i915_event(int fd, int pid_index)
{
        int retval, ack_retval;
        struct prelim_drm_i915_debug_event_ack ack_event = {};
        struct prelim_drm_i915_debug_event *event;
        
        event = (struct prelim_drm_i915_debug_event *) debug_i915_info.event_buff;
        
        memset(event, 0, sizeof(struct prelim_drm_i915_debug_event) + MAX_EVENT_SIZE);
        event->size = MAX_EVENT_SIZE;
        event->type = PRELIM_DRM_I915_DEBUG_EVENT_READ;
        event->flags = 0;

        retval = ioctl(fd, PRELIM_I915_DEBUG_IOCTL_READ_EVENT, event);

        if (retval != 0) {
                fprintf(stderr, "read_event failed with: %d\n", retval);
                return -1;
        }
        
        /* ACK the event, otherwise the workload will stall. */
        if (event->flags & PRELIM_DRM_I915_DEBUG_EVENT_NEED_ACK) {
                ack_event.type = event->type;
                ack_event.seqno = event->seqno;
                ack_retval = ioctl(fd, PRELIM_I915_DEBUG_IOCTL_ACK_EVENT, &ack_event);
                if (ack_retval != 0) {
                        fprintf(stderr, "  Failed to ACK event!\n");
                        return -1;
                }
        }
        
        if (event->flags & ~(PRELIM_DRM_I915_DEBUG_EVENT_CREATE |
                                    PRELIM_DRM_I915_DEBUG_EVENT_DESTROY |
                                    PRELIM_DRM_I915_DEBUG_EVENT_STATE_CHANGE |
                                    PRELIM_DRM_I915_DEBUG_EVENT_NEED_ACK)) {
                
                return -2;
        }

        if (event->type == PRELIM_DRM_I915_DEBUG_EVENT_UUID) {
                handle_event_uuid(fd, event, pid_index);
        }

        return 0;
}

void read_debug_i915_events(int fd)
{
        int result, max_loops, i, pid_index;
        
        /* First, find the index of the PID that this event came from. */
        for (i = 0; i < debug_i915_info.num_pids; i++) {
                if (debug_i915_info.fds[i] == fd) {
                        pid_index = i;
                        break;
                }
        }
        
        max_loops = 5;
        result = 0;
        do {
                result = read_debug_i915_event(fd, pid_index);
                max_loops--;
        } while ((result == 0) && (max_loops != 0));
}

char *debug_i915_event_to_str(int debug_event)
{
        return debug_events[debug_event];
}
