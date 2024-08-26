/***************************************
* i915 GEM Tracer
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

#include "i915.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

/***************************************
* HACKY DECLARATIONS
*
* These are definitions of macros that aren't available from the BTF
* dump of the i915 module; for example, those that are defined inside
* structs. Many of these *are* included in the regular uapi headers,
* but including those alongside BPF skeleton headers causes a host of
* compile errors, so this is the path of least resistance.
***************************************/

#define MAX_ENGINE_INSTANCE 8
#define I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS (1u << 0)
#define I915_CONTEXT_CREATE_EXT_SETPARAM 0
#define I915_CONTEXT_PARAM_VM 0x9

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

/***************************************
* STACKMAP
*
* Used for grabbing stacks in all BPF sub-programs.
***************************************/

struct {
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);
        __uint(key_size, sizeof(u32));
        __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
        __uint(max_entries, 5000);
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
};
struct gpu_mapping {
        u64 addr;
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

#include "mmap.bpf.c"

#include "context.bpf.c"

#include "vm_bind.bpf.c"

#include "execbuffer.bpf.c"

#include "request.bpf.c"

char LICENSE[] SEC("license") = "GPL";
