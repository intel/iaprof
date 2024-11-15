/***************************************
n* i915 GEM Tracer
*
* The purpose of this eBPF program is to trace, and send to userspace,
* all GEMs that are associated with an executing batchbuffer in the i915
* driver.  This includes at a minimum the virtual address and size of the
* buffer.
*
* This program works by tracing a set of functions on the memory management
* side (functions which are used to create, allocate, bind, and/or write to
* buffers). Each of these callpaths eventually culminates in a virtual
* address and size of a buffer which userspace wants to send to the GPU.
* Once collected, we have no way of knowing if these buffers have actually
* been written to. So, we simply wait until they're referred to by an
* executing batchbuffer.
*
* Memory management is largely a matter of calling some mmap-like interface
* to get an integer ID for the buffer, then later passing it to a call to
* i915_gem_execbuffer2_ioctl. For discrete devices (like Ponte Vecchio),
* this is supplemented by maintaining a separate virtual address space
* (called a VM) using i915_gem_vm_bind_ioctl.
*
* From each function, we get:
*
* A. i915_gem_mmap_ioctl
*    - handle ID
*    - CPU address
*    - size
*
* B. i915_gem_mmap_offset_ioctl
*    - handle ID
*    - file offset (later passed to i915_gem_mmap_ioctl)
*
* C. i915_gem_userptr_ioctl
*    - handle ID
*    - CPU address
*    - size
*
* For discrete devices, we also trace:
*
* A. i915_gem_vm_bind_ioctl
*    - handle ID
*    - GPU address
*    - size
*    - VM ID
*
* B. i915_gem_context_create_ioctl
*    - Context ID
*    - VM ID
***************************************/

#ifdef XE_DRIVER
#include "xe.h"
#else
#include "i915.h"
#endif

/* #include <linux/bpf.h> */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "main.h"
#include "gpu_parsers/bb_parser_defs.h"

#ifdef DEBUG
#define DEBUG_PRINTK(...) bpf_printk(__VA_ARGS__)
#else
#define DEBUG_PRINTK(...) ;
#endif

/***************************************
* HACKY DECLARATIONS
*
* These are definitions of macros that aren't available from the BTF
* dump of the i915 module; for example, those that are defined inside
* structs. Many of these *are* included in the regular uapi headers,
* but including those alongside BPF skeleton headers causes a host of
* compile errors, so this is the path of least resistance.
***************************************/

#ifdef XE_DRIVER

#else
#define MAX_ENGINE_INSTANCE 8
#define I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS (1u << 0)
#define I915_CONTEXT_CREATE_EXT_SETPARAM 0
#define I915_CONTEXT_PARAM_VM 0x9
#endif

int dropped_event;

/***************************************
* RINGBUFFER
*
* This is the "output" map, which userspace reads to get information
* about GPU kernels running on the system.
***************************************/

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, RINGBUF_SIZE);
} buffer_copy_rb SEC(".maps");

/***************************************
* STACKMAP
*
* Used for grabbing stacks in all BPF sub-programs.
***************************************/

struct {
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);
        __uint(key_size, sizeof(u32));
        __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
        __uint(max_entries, 1<<14);
} stackmap SEC(".maps");

/***************************************
* GPU->CPU Map
*
* This map uses `i915_gem_mmap_ioctl`, `i915_gem_mmap_offset_ioctl`, `i915_gem_mmap`
* to maintain a map of GPU addresses to CPU ones.
***************************************/
struct cpu_mapping {
        u64 addr;
        u64 size;
        u32 num_faulted;
};
struct gpu_mapping {
        u64 addr;
        u64 file;
        u32 vm_id;
};
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct gpu_mapping);
        __type(value, struct cpu_mapping);
} gpu_cpu_map SEC(".maps");
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct cpu_mapping);
        __type(value, struct gpu_mapping);
} cpu_gpu_map SEC(".maps");
#ifdef XE_DRIVER
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u64);
        __type(value, u64);
} page_map SEC(".maps");
#endif
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u64);
        __type(value, u32);
} fault_count_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct gpu_mapping);
        __type(value, char);
} known_not_batch_buffers SEC(".maps");

/***************************************
* Buffer Filters
***************************************/

#define DBGAREA_MAGIC 0x61657261676264
#define SBAAREA_MAGIC 0x61657261616273
#define TSSAREA_MAGIC 0x61657261737374

char is_debug_area(void *addr, u64 size)
{
        u64 val;
        struct debug_area_info *info;

        if (size < 8) {
                return 0;
        }

        /* Make a copy of the first 8 bytes, read them to see what the buffer type is */
        bpf_probe_read_user(&val, sizeof(val), addr);

        if (val == DBGAREA_MAGIC ||
            val == SBAAREA_MAGIC ||
            val == TSSAREA_MAGIC) {

                return 1;
        }

        return 0;
}

char send_debug_area_info(struct gpu_mapping *gmapping, int stackid)
{
        u64 status;
        struct debug_area_info *info;

        /* Send a debug area event to userspace */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct debug_area_info), 0);
        if (!info) {
                DEBUG_PRINTK("WARNING: send_debug_area failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 1;
        }

        info->type = BPF_EVENT_TYPE_DEBUG_AREA;
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->gpu_addr = gmapping->addr;
        info->vm_id = gmapping->vm_id;
        info->file = gmapping->file;
        info->stackid = stackid;
        bpf_get_current_comm(info->name, sizeof(info->name));

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 1;
}

int buffer_copy_add(void *addr, u64 size) {
        struct buffer_copy *bcopy;
        void               *buff;
        u64                 status;
        int                 err;
        char                one = 1;

        if (size > MAX_BINARY_SIZE) {
                size = MAX_BINARY_SIZE;
        }

        bcopy = bpf_ringbuf_reserve(&buffer_copy_rb, sizeof(*bcopy), 0);
        if (!bcopy) {
                DEBUG_PRINTK("WARNING: buffer_copy_add failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&buffer_copy_rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 0;
        }

        bcopy->size = size;

        err = bpf_probe_read_user(bcopy->bytes, size, addr);
        if (err) {
                DEBUG_PRINTK("WARNING: Failed to copy from cpu_addr=0x%lx, err=%d", addr, err);
        }

        bpf_ringbuf_submit(bcopy, BPF_RB_FORCE_WAKEUP);

        return 1;
}

#ifdef XE_DRIVER

#include "i915/batchbuffer.bpf.c"
#include "xe/mmap.bpf.c"
#include "xe/vm_bind.bpf.c"
#include "xe/context.bpf.c"
#include "xe/exec.bpf.c"

#else

#include "i915/batchbuffer.bpf.c"
#include "i915/mmap.bpf.c"
#include "i915/context.bpf.c"
#include "i915/vm_bind.bpf.c"
#include "i915/execbuffer.bpf.c"

#endif

char LICENSE[] SEC("license") = "GPL";
