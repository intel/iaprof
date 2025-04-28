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

struct eudebug_info_t {
        /* Keep track of PIDs that we've opened with the debug interface,
           as well as their fd */
        int pids[MAX_PIDS];
        struct pollfd pollfds[MAX_PIDS];
        int num_pids;
};

extern struct eudebug_info_t eudebug_info;
extern pthread_rwlock_t eudebug_info_lock;

/******************************************************************************
* Initialization
* **************
* Adds a PID to be profiled with the debugger.
******************************************************************************/

void deinit_eudebug(int pid);
void init_eudebug(int fd, int pid);
int read_eudebug_event(int fd, int pid_index);
void read_eudebug_events(int fd, int pid_index);

void set_kernel_info(uint64_t addr, uint64_t size, uint64_t symbol_id, uint64_t filename_id, int linenum);
void set_kernel_binary(uint64_t addr, unsigned char *bytes, uint64_t size);

void extract_elf_kernel_info(const unsigned char *elf_data, uint64_t elf_data_size);

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
