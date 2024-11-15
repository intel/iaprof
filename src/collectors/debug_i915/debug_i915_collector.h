#pragma once

#ifdef XE_DRIVER
#include <drm/xe_drm_prelim.h>
#else
#include <drm/i915_drm_prelim.h>
#endif

#include <poll.h>
#include <pthread.h>

/******************************************************************************
* debug_i915
* *********
* The debug_i915 collector uses i915's `debugger` interface (via `ioctl`) to
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
* Keeps track of open i915 debuggers, per-PID
******************************************************************************/
#define MAX_PIDS 64
#define MAX_EVENT_SIZE 4096

struct i915_symbol_entry {
        uint64_t start_addr;
        uint64_t size;
        char *symbol;
        char *filename;
        int linenum;
};

struct i915_symbol_table {
        int pid;
        size_t num_syms;
        struct i915_symbol_entry *symtab;
};

struct debug_i915_info_t {
        /* Keep track of PIDs that we've opened with the debug interface,
           as well as their fd */
        int pids[MAX_PIDS];
        struct pollfd pollfds[MAX_PIDS];
        int num_pids;

        /* Store symbols to be printed later, in parallel with the `pids` and
           `fds` arrays above. */
        struct i915_symbol_table symtabs[MAX_PIDS];
};

extern struct debug_i915_info_t debug_i915_info;
extern pthread_rwlock_t debug_i915_info_lock;

#ifdef SLOW_MODE
extern pthread_cond_t debug_i915_vm_bind_cond;
extern pthread_mutex_t debug_i915_vm_bind_lock;
#endif

struct shader_binary {
        uint64_t      start;
        uint64_t      size;
        unsigned char bytes[];
};

extern pthread_mutex_t debug_i915_shader_binaries_lock;

/******************************************************************************
* Initialization
* **************
* Adds a PID to be profiled with the i915 debugger.
******************************************************************************/

void deinit_debug_i915(int pid);
void init_debug_i915(int i915_fd, int pid);
int read_debug_i915_event(int fd, int pid_index);
void read_debug_i915_events(int fd, int pid_index);
int debug_i915_get_sym(int pid, uint64_t addr, char **out_gpu_symbol, char **out_gpu_file, int *out_gpu_line);

void free_debug_i915();

/* debug_i915_shader_binaries_lock must be locked when calling this and held
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

char *debug_i915_event_to_str(int debug_event);
