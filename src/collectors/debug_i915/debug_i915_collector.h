#pragma once

#include <drm/i915_drm_prelim.h>

/******************************************************************************
* Information
* *********
* Keeps track of open i915 debuggers, per-PID
******************************************************************************/
#define MAX_PIDS 64
#define MAX_EVENT_SIZE 4096

struct debug_i915_info_t {
        int pids[MAX_PIDS];
        int pid_index;
        
        struct prelim_drm_i915_debug_event event_buff[sizeof(struct prelim_drm_i915_debug_event) + MAX_EVENT_SIZE];
};

extern struct debug_i915_info_t debug_i915_info;

/******************************************************************************
* Initialization
* **************
* Adds a PID to be profiled with the i915 debugger.
******************************************************************************/

void init_debug_i915(int i915_fd, int pid);
int read_debug_i915_event(int fd);
void read_debug_i915_events(int fd);

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
