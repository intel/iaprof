#pragma once

#include <poll.h>
#include <pthread.h>

/******************************************************************************
* debug
* *********
* The debug collector uses the driver's `debugger` interface (via `ioctl`) to
* gather debug symbols from GPU programs that are currently running.
* In order to do this, it must open a per-PID file descriptor, poll on those
* file descriptors, and read events when they're ready.
*
* The ultimate goal is to find an event of type PRELIM_I915_DEBUG_IOCTL_READ_UUID,
* which can potentially contain an ELF object which contains symbols. We then
* use `libelf` to parse the ELF object for the symbols, storing them for later
* printing (e.g. in a Flamegraph).
******************************************************************************/

/******************************************************************************
* Information
* *********
* Keeps track of open debuggers, per-PID
******************************************************************************/
#define MAX_PIDS 64
#define MAX_EVENT_SIZE 4096

struct symbol_entry {
        uint64_t start_addr;
        uint64_t size;
        char *symbol;
        char *filename;
        int linenum;
        
        uint64_t symbol_id, filename_id;
};

struct symbol_table {
        int pid;
        size_t num_syms;
        struct symbol_entry *symtab;
};

struct debug_info_t {
        /* Keep track of PIDs that we've opened with the debug interface,
           as well as their fd */
        int pids[MAX_PIDS];
        struct pollfd pollfds[MAX_PIDS];
        int num_pids;

        /* Store symbols to be printed later, in parallel with the `pids` and
           `fds` arrays above. */
        struct symbol_table symtabs[MAX_PIDS];
};

extern struct debug_info_t debug_info;
extern pthread_rwlock_t debug_info_lock;

struct shader_binary {
        uint64_t      start;
        uint64_t      size;
        unsigned char bytes[];
};

extern pthread_mutex_t debug_shader_binaries_lock;

/******************************************************************************
* Initialization
* **************
* Adds a PID to be profiled with the debugger.
******************************************************************************/

void deinit_debug(int pid);
void init_debug(int fd, int pid);
int read_debug_event(int fd, int pid_index);
void read_debug_events(int fd, int pid_index);
int debug_get_sym(int pid, uint64_t addr, uint64_t *out_symbol_id, uint64_t *out_file_id);

void free_debug();

/* debug_shader_binaries_lock must be locked when calling this and held
 * as long as the returned struct shader_binary pointer may be used. */
struct shader_binary *get_shader_binary(uint64_t gpu_addr);

/******************************************************************************
* Strings
* *********
* Associations between events and strings
******************************************************************************/

/* Given a PRELIM_DRM_I915_DEBUG_EVENT_* macro, returns the string equivalent.
   Caller should free the string. */
static char *debug_events[] = {
        "PRELIM_DRM_I915_DEBUG_EVENT_NONE",
        "PRELIM_DRM_I915_DEBUG_EVENT_READ",
        "PRELIM_DRM_I915_DEBUG_EVENT_CLIENT",
        "PRELIM_DRM_I915_DEBUG_EVENT_CONTEXT",
        "PRELIM_DRM_I915_DEBUG_EVENT_UUID",
        "PRELIM_DRM_I915_DEBUG_EVENT_VM",
        "PRELIM_DRM_I915_DEBUG_EVENT_VM_BIND",
        "PRELIM_DRM_I915_DEBUG_EVENT_CONTEXT_PARAM",
        "PRELIM_DRM_I915_DEBUG_EVENT_EU_ATTENTION",
        "PRELIM_DRM_I915_DEBUG_EVENT_ENGINES",
        "PRELIM_DRM_I915_DEBUG_EVENT_PAGE_FAULT",
};

char *debug_event_to_str(int debug_event);
