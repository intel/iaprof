/***************************************
* Kernel GEM Tracer
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
* Tracing is split between two general methods for doing memory management
* in i915:
*   1. Before Ponte Vecchio, memory management can largely be left to the
*      kernel driver; userspace simply calls an mmap-like interface (with
*      some exceptions), then writes to those mapped buffers. For each
*      of these buffers, an integer ID (handle) is generated. These IDs
*      are then passed to a call to the DRM_IOCTL_I915_GEM_EXECBUFFER2
*      ioctl, at which point we send their addresses and sizes to userspace.
*      We trace:
*        (A) i915_gem_pwrite_ioctl
*        (B) i915_gem_mmap_ioctl
*        (C) i915_gem_mmap_offset_ioctl
*        (D) i915_gem_userptr_ioctl
*   2. For Ponte Vecchio, memory management instead involves creating a
*      virtual memory address space (VM), binding buffers to it, and
*      binding that VM to a specific context. That context ID is later
*      passed to the call to DRM_IOCTL_I915_GEM_EXECBUFFER2.
*      Thus, we instead need to trace:
*        (A) i915_gem_vm_bind_ioctl
*        (B) i915_gem_vm_unbind_ioctl
*        (C) i915_gem_context_create_ioctl
*        (D) i915_gem_do_execbuffer
***************************************/

#include "i915.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kernel_writes.h"

/***************************************
* HACKY DECLARATIONS
*
* These are definitions of macros that aren't available from the BTF
* dump of the i915 module; for example, those that are defined inside
* structs. Many of these *are* included in the regular uapi headers,
* but including those alongside BPF skeleton headers causes a host of
* compile errors, so this is the path of least resistance.
***************************************/

#define I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS  (1u << 0)
#define I915_CONTEXT_CREATE_EXT_SETPARAM 0
#define I915_CONTEXT_PARAM_VM    0x9

/***************************************
* OUTPUT MAP
*
* This is the "output" map, which userspace reads to get information
* about GPU kernels running on the system. We fill it with `struct kernel_info`
* values.
***************************************/

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_ENTRIES);
} rb SEC(".maps");

#if 0
/***************************************
* i915_gem_pwrite_ioctl
*
* The i915_gem_pwrite_ioctl system call includes a userspace pointer
* from which the kernel should read, so we can immediately pass that along
* to our userspace profiler to be read.
***************************************/

SEC("kprobe/i915_gem_pwrite_ioctl")
int pwrite_kprobe(struct pt_regs *ctx)
{
  struct drm_i915_gem_pwrite *gem_pwrite = (struct drm_i915_gem_pwrite *) PT_REGS_PARM2(ctx);
  struct kernel_info *kinfo;
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  
  add_to_ringbuf(pid,
                 BPF_CORE_READ(gem_pwrite, handle),
                 BPF_CORE_READ(gem_pwrite, data_ptr),
                 BPF_CORE_READ(gem_pwrite, size),
                 0,
                 0);
  
  return 0;
}
#endif

/***************************************
* mmap_wait_for_exec
*
* This map stores addresses and sizes that have been mapped
* using the `mmap`, `mmap_offset`, or `userptr` ioctls. These
* addresses, having simply been mapped, have not necessarily
* been *written* to, so we must wait until they're executed
* (e.g. being sent to the execbuffer ioctl) to know that data
* has been written into them.
*
* This map stores those pointers so that they can be found
* once executed, further down in this program.
***************************************/

struct mmap_wait_for_exec_key {
  u32 pid;
  u32 handle;
};

struct mmap_wait_for_exec_val {
  __u64 data[MAX_DUPLICATES];
  __u64 data_sz[MAX_DUPLICATES];
};

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key,         struct mmap_wait_for_exec_key);
  __type(value,       struct mmap_wait_for_exec_val);
} mmap_wait_for_exec SEC(".maps");

int mmap_wait_for_exec_insert(u32 pid, u32 handle, u64 data, u64 data_sz)
{
  struct mmap_wait_for_exec_key key = {};
  struct mmap_wait_for_exec_val val = {};
  struct mmap_wait_for_exec_val *val_ptr = NULL;
  int retval;
  unsigned int i;
  
  key.pid = pid;
  key.handle = handle;
  
  val_ptr = bpf_map_lookup_elem(&mmap_wait_for_exec, &key);
  if(val_ptr) {
    /* This particular pid/handle combination is already in the map,
       so we're going to add a pointer and size to the arrays. */
    for(i = 0; i < MAX_DUPLICATES; i++) {
      if((val_ptr->data[i] == 0) && (val_ptr->data_sz[i] == 0)) {
        /* This is an uninitialized element, so fill it in */
        val_ptr->data[i] = data;
        val_ptr->data_sz[i] = data_sz;
        return 0;
      }
    }
    return -1;
  }
  
  /* This pid/handle combination has not been seen, so add it */
  bpf_printk("Adding data=%llx data_sz=%llu to mmap_wait_for_exec", data, data_sz);
  val.data[0] = data;
  val.data_sz[0] = data_sz;
  retval = bpf_map_update_elem(&mmap_wait_for_exec, &key, &val, 1);
  if(retval < 0) {
    /* We failed to insert into the map, so... bail out? */
    return -1;
  }
  
  return 0;
}

/***************************************
* i915_gem_mmap_ioctl
*
* The i915_gem_mmap_ioctl includes a GEM handle that the kernel
* should map for a userspace application to read. All we have to do
* is wait for this function to return, grab the pointer that it returns,
* and pass that along to our userspace profiler.
***************************************/

struct wait_for_ret_val {
  struct drm_i915_gem_mmap *gem_mmap;
};

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key,         u32);
  __type(value,       struct wait_for_ret_val);
} mmap_ioctl_wait_for_ret SEC(".maps");


/* Capture any pointers that userspace has mmap'd. */
SEC("kprobe/i915_gem_mmap_ioctl")
int mmap_ioctl_kprobe(struct pt_regs *ctx)
{
  struct drm_i915_gem_mmap *gem_mmap = (struct drm_i915_gem_mmap *) PT_REGS_PARM2(ctx);
  
  u32 cpu = bpf_get_smp_processor_id();
  
  /* Pass two arguments to the kretprobe */
  struct wait_for_ret_val val = {};
  val.gem_mmap = gem_mmap;
  
  bpf_map_update_elem(&mmap_ioctl_wait_for_ret, &cpu, &val, 0);
}

/* We have to wait for this function to return to read its address */
SEC("kretprobe/i915_gem_mmap_ioctl")
int mmap_ioctl_kretprobe(struct pt_regs *ctx)
{
  int retval;
  
  /* First, see if we've got the element from when this call first started */
  u32 cpu = bpf_get_smp_processor_id();
  void *arg = bpf_map_lookup_elem(&mmap_ioctl_wait_for_ret, &cpu);
  if(!arg) {
    return 1;
  }
  
  struct wait_for_ret_val val = *((struct wait_for_ret_val *) arg);
  struct drm_i915_gem_mmap *gem_mmap = val.gem_mmap;
  
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 handle = BPF_CORE_READ(gem_mmap, handle);
  u64 data = BPF_CORE_READ(gem_mmap, addr_ptr);
  u64 data_sz = BPF_CORE_READ(gem_mmap, size);
  
  /* DEBUG */
  bpf_printk("mmap_ioctl_kretprobe handle=%u addr_ptr=0x%llx size=0x%llx", handle, data, data_sz);
  
  retval = mmap_wait_for_exec_insert(pid, handle, data, data_sz);
  if(retval < 0) {
    return 1;
  }
  
  return 0;
}

/***************************************
* i915_gem_mmap_offset_ioctl and i915_gem_mmap
*
* If we see that an application has mmap'd a GEM to write it later, let's record that in an
* internal map, then output it to userspace after we know that it has been written (which is
* when i915_gem_do_execbuffer is called).
* This codepath differs from i915_gem_mmap_ioctl because it requires tracing i915_gem_mmap_offset_ioctl
* to get the GEM's handle, then i915_gem_mmap to see it get mmap'd.
***************************************/

struct mmap_wait_for_ret_val {
  struct vm_area_struct *vma;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, u64);
} mmap_offset_ioctl_wait_for_ret SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64);
  __type(value, u32);
} mmap_offset_ioctl_wait_for_mmap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct mmap_wait_for_ret_val);
} mmap_wait_for_ret SEC(".maps");

/* Capture any pointers that userspace has mmap'd. */
SEC("kprobe/i915_gem_mmap_offset_ioctl")
int mmap_offset_ioctl_kprobe(struct pt_regs *ctx)
{
  u64 arg = (u64) PT_REGS_PARM2(ctx);
  u32 cpu = bpf_get_smp_processor_id();
  bpf_map_update_elem(&mmap_offset_ioctl_wait_for_ret, &cpu, &arg, 0);
  
  /* DEBUG */
  bpf_printk("mmap_offset_ioctl_kprobe on cpu %u", cpu);
  
  return 0;
}

/* We have to wait for this function to return to read its address */
SEC("kretprobe/i915_gem_mmap_offset_ioctl")
int mmap_offset_ioctl_kretprobe(struct pt_regs *ctx)
{
  /* First, see if we've got the element from when this call first started */
  u32 cpu = bpf_get_smp_processor_id();
  void *arg = bpf_map_lookup_elem(&mmap_offset_ioctl_wait_for_ret, &cpu);
  if(!arg) {
    return 1;
  }
  
  /* At this point, this pointer to a drm_i915_gem_mmap_offset contains a handle
     and a fake offset. Let's store them and read them when the mmap actually happens. */
  struct drm_i915_gem_mmap_offset *gem_mmap = *((struct drm_i915_gem_mmap_offset **) arg);
  u64 fake_offset = BPF_CORE_READ(gem_mmap, offset);
  u32 handle = BPF_CORE_READ(gem_mmap, handle);
  bpf_map_update_elem(&mmap_offset_ioctl_wait_for_mmap, &fake_offset, &handle, 0);
  
  /* DEBUG */
  bpf_printk("mmap_offset_ioctl_kretprobe fake_offset=0x%lx handle=%u", fake_offset, handle);
  
  return 0;
}

/* At this point we've seen the i915_gem_mmap_offset_ioctl call for this GEM, from
   which we extracted the handle and the fake offset. Let's use the offset as a key,
   and from i915_gem_mmap get the virtual address of the mapping. */
SEC("kprobe/i915_gem_mmap")
int mmap_kprobe(struct pt_regs *ctx)
{
  struct vm_area_struct *vma = (struct vm_area_struct *) PT_REGS_PARM2(ctx);
  
  /* We're just going to immediately send this to the kretprobe */
  u32 cpu = bpf_get_smp_processor_id();
  struct mmap_wait_for_ret_val val = {};
  val.vma = vma;
  bpf_map_update_elem(&mmap_wait_for_ret, &cpu, &val, 0);
  
  /* DEBUG */
  bpf_printk("mmap_kprobe vma=0x%llx", vma);
  
  return 0;
}

SEC("kretprobe/i915_gem_mmap")
int mmap_kretprobe(struct pt_regs *ctx)
{
  /* Get the vma from the kprobe */
  u32 cpu = bpf_get_smp_processor_id();
  void *arg = bpf_map_lookup_elem(&mmap_wait_for_ret, &cpu);
  if(!arg) {
    return 1;
  }
  struct mmap_wait_for_ret_val val = *((struct mmap_wait_for_ret_val *) arg);
  struct vm_area_struct *vma = val.vma;
  
  u32 PAGE_SHIFT = 12;
  u64 vm_pgoff = BPF_CORE_READ(vma, vm_pgoff);
  u64 vm_start = BPF_CORE_READ(vma, vm_start);
  u64 vm_end = BPF_CORE_READ(vma, vm_end);
  vm_pgoff = vm_pgoff << PAGE_SHIFT;
  
  /* Get the GEM handle from the previous i915_gem_mmap_offset_ioctl call. */
  arg = bpf_map_lookup_elem(&mmap_offset_ioctl_wait_for_mmap, &vm_pgoff);
  if(!arg) {
    return 1;
  }
  
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 handle = *((u32 *) arg);
  u64 data = vm_start;
  u64 data_sz = vm_end - vm_start;
  
  /* DEBUG */
  bpf_printk("mmap_kretprobe handle=%u vm_pgoff=0x%lx vm_start=0x%lx", handle, vm_pgoff, vm_start);
  
  int retval = mmap_wait_for_exec_insert(pid, handle, data, data_sz);
  if(retval < 0) {
    return 1;
  }
  
  return 0;
}

/***************************************
* i915_gem_userptr_ioctl
*
* Userspace can give the kernel driver a pointer (and size) to some allocated memory,
* which the kernel will then create a GEM from.
***************************************/

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, u64);
} userptr_ioctl_wait_for_ret SEC(".maps");

SEC("kprobe/i915_gem_userptr_ioctl")
int userptr_ioctl_kprobe(struct pt_regs *ctx)
{
  u64 arg = (u64) PT_REGS_PARM2(ctx);
  u32 cpu = bpf_get_smp_processor_id();
  
  bpf_map_update_elem(&userptr_ioctl_wait_for_ret, &cpu, &arg, 0);
}

SEC("kretprobe/i915_gem_userptr_ioctl")
int userptr_ioctl_kretprobe(struct pt_regs *ctx)
{
  /* Get the pointer to the arguments from the kprobe */
  u32 cpu = bpf_get_smp_processor_id();
  void *arg = bpf_map_lookup_elem(&userptr_ioctl_wait_for_ret, &cpu);
  if(!arg) {
    return 1;
  }
  struct drm_i915_gem_userptr *gem_userptr = *((struct drm_i915_gem_userptr **) arg);
  
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 handle = BPF_CORE_READ(gem_userptr, handle);
  u64 data = BPF_CORE_READ(gem_userptr, user_ptr);
  u64 data_sz = BPF_CORE_READ(gem_userptr, user_size);
  
  /* DEBUG */
  bpf_printk("userptr_ioctl_kretprobe handle=%u data=0x%llx data_sz=%llu", handle, data, data_sz);
  
  int retval = mmap_wait_for_exec_insert(pid, handle, data, data_sz);
  if(retval < 0) {
    return 1;
  }
  
  return 0;
}

/***************************************
* vm_bind_wait_for_exec
*
* Similar to mmap_wait_for_exec above, this map stores
* addresses that need to be "seen" at execution time before
* they can be sent to userspace to be parsed. This map, though,
* stores addresses and sizes keyed on the VM that they've been
* bound to, so that later, a lookup can be done to obtain all
* buffers associated with a particular VM ID.
*
* I'm a little wary about this implementation, since it requires
* a static maximum number of addresses that can be bound into a VM.
* Since I have no way of knowing how workloads are going to use this feature,
* there's no good heuristic for determining a value here.
***************************************/

/* Representing a single VM (as created by the DRM_I915_GEM_VM_CREATE ioctl),
   this stores multiple pointers and sizes that need to eventually be sent
   to userspace. */
struct vm_bind_wait_for_exec_val {
  __u64 data_sz;
  __u32 handle;
};

struct vm_bind_wait_for_exec_key {
  __u32 vm_id;
  __u64 data;
};

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key,         struct vm_bind_wait_for_exec_key);
  __type(value,       struct vm_bind_wait_for_exec_val);
} vm_bind_wait_for_exec SEC(".maps");

int vm_bind_wait_for_exec_insert(u32 vm_id, u64 data, u64 data_sz, u32 handle)
{
  struct vm_bind_wait_for_exec_val val;
  struct vm_bind_wait_for_exec_key key;
  int retval;
  
  __builtin_memset(&key, 0, sizeof(struct vm_bind_wait_for_exec_key));
  __builtin_memset(&val, 0, sizeof(struct vm_bind_wait_for_exec_val));
  
  key.vm_id = vm_id;
  key.data = data;
  val.data_sz = data_sz;
  val.handle = handle;
  
  retval = bpf_map_update_elem(&vm_bind_wait_for_exec, &key, &val, 0);
  if(retval < 0) {
    /* We failed to insert into the map, so... bail out? */
    return -1;
  }
  
  return 0;
}

/***************************************
* i915_gem_context_create_ioctl
*
* Look for gem contexts getting created, in order to see the association
* between VM ID and context ID.
***************************************/

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key,         u32);
  __type(value,       u64);
} context_create_wait_for_ret SEC(".maps");

/* The struct that execbuffer will use to lookup VM IDs */
struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key,         u32);
  __type(value,       u32);
} context_create_wait_for_exec SEC(".maps");

SEC("kprobe/i915_gem_context_create_ioctl")
int context_create_ioctl_kprobe(struct pt_regs *ctx)
{
  u64 arg = (u64) PT_REGS_PARM2(ctx);
  u32 cpu = bpf_get_smp_processor_id();
  
  bpf_map_update_elem(&context_create_wait_for_ret, &cpu, &arg, 0);
}

SEC("kretprobe/i915_gem_context_create_ioctl")
int context_create_ioctl_kretprobe(struct pt_regs *ctx)
{
  u32 cpu, i, ctx_id, vm_id, name;
  u64 param;
  void *arg;
  struct drm_i915_gem_context_create_ext *create_ext;
  struct i915_user_extension *ext;
  struct drm_i915_gem_context_create_ext_setparam *setparam_ext;

  /* Get the pointer to the arguments from the kprobe */
  cpu = bpf_get_smp_processor_id();
  arg = bpf_map_lookup_elem(&context_create_wait_for_ret, &cpu);
  if(!arg) {
    return 1;
  }
  
  /* Look for CONTEXT_CREATE extensions */
  create_ext = *((struct drm_i915_gem_context_create_ext **) arg);
  ctx_id = BPF_CORE_READ(create_ext, ctx_id);
  
  if(BPF_CORE_READ(create_ext, flags) & I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS) {
    ext = (struct i915_user_extension *) BPF_CORE_READ(create_ext, extensions);
    
    #pragma clang loop unroll(full)
    for(i = 0; i < 64; i++) {
      if(!ext) break;
      
      name = BPF_CORE_READ_USER(ext, name);
      if(name == I915_CONTEXT_CREATE_EXT_SETPARAM) {
        setparam_ext = (struct drm_i915_gem_context_create_ext_setparam *) ext;
        param = BPF_CORE_READ_USER(setparam_ext, param).param;
        if(param == I915_CONTEXT_PARAM_VM) {
          /* Someone is trying to set the VM for this context, let's store it */
          vm_id = BPF_CORE_READ_USER(setparam_ext, param).value;
          bpf_printk("context_create_ioctl ctx_id=%u vm_id=%u", ctx_id, vm_id);
          bpf_map_update_elem(&context_create_wait_for_exec, &ctx_id, &vm_id, 0);
        }
      }
      
      ext = (struct i915_user_extension *) BPF_CORE_READ_USER(ext, next_extension);
    }
  }
}

/***************************************
* i915_gem_vm_bind_ioctl
*
* Look for virtual addresses that userspace is trying to [un]bind.
***************************************/

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key,         u32);
  __type(value,       u64);
} vm_bind_ioctl_wait_for_ret SEC(".maps");

SEC("kprobe/i915_gem_vm_bind_ioctl")
int vm_bind_ioctl_kprobe(struct pt_regs *ctx)
{
  u64 arg = (u64) PT_REGS_PARM2(ctx);
  u32 cpu = bpf_get_smp_processor_id();
  
  bpf_map_update_elem(&vm_bind_ioctl_wait_for_ret, &cpu, &arg, 0);
}

SEC("kretprobe/i915_gem_vm_bind_ioctl")
int vm_bind_ioctl_kretprobe(struct pt_regs *ctx)
{
  /* Grab the argument from the kprobe */
  u32 cpu = bpf_get_smp_processor_id();
  void *arg = bpf_map_lookup_elem(&vm_bind_ioctl_wait_for_ret, &cpu);
  if(!arg) {
    return -1;
  }
  struct prelim_drm_i915_gem_vm_bind *vm_bind = *((struct prelim_drm_i915_gem_vm_bind **) arg);
  
  u32 vm_id = BPF_CORE_READ(vm_bind, vm_id);
  u32 handle = BPF_CORE_READ(vm_bind, handle);
  u64 start = BPF_CORE_READ(vm_bind, start);
  u64 offset = BPF_CORE_READ(vm_bind, offset);
  u64 length = BPF_CORE_READ(vm_bind, length);
  bpf_printk("vm_bind_ioctl_kretprobe vm_id=%u handle=%u start=%llx", vm_id, handle, start);
  bpf_printk("                        offset=%llx length=%llx", offset, length);
  
  /* Add this address to the map, to wait for execution */
  int retval = vm_bind_wait_for_exec_insert(vm_id, start, length, handle);
  if(retval < 0) {
    return -1;
  }
}

/* SEC("kprobe/i915_gem_vm_unbind_ioctl") */
/* int vm_unbind_ioctl_kprobe(struct pt_regs *ctx) */
/* { */
/*    */
/* } */

/***************************************
* i915_gem_do_execbuffer
*
* Now we've got a map of GEM handles that have been mmap'd. Look through the
* GEM handles that are going to be executed, and send them to userspace.
***************************************/

struct each_batch_ctx {
  unsigned int batch_index;
  struct drm_i915_gem_exec_object2 *exec;
  u32 vm_id, pid;
};

/* This function runs for each batch in the execbuffer.
   It's formatted this way to allow for easy porting over to the
   bpf_loop interface at a later date. */
static long each_batch_callback(u32 index, struct each_batch_ctx *ctx)
{
  struct kernel_info *kinfo;
  
  struct mmap_wait_for_exec_val *mmap_val_ptr = NULL;
  struct vm_bind_wait_for_exec_val *vm_bind_val_ptr = NULL;
  
  struct vm_bind_wait_for_exec_key vm_bind_key;
  struct mmap_wait_for_exec_key mmap_key;
  
  struct drm_i915_gem_exec_object2 *exec;
  unsigned int i, batch_index;
  u64 data, data_sz, offset;
  u32 handle, pid;
  
  if(!ctx) {
    return 1;
  }
  exec = ctx->exec;
  batch_index = ctx->batch_index;
  pid = ctx->pid;
  handle = BPF_CORE_READ(exec, handle);
  offset = BPF_CORE_READ(exec, offset);
  
  bpf_printk("  handle=%u offset=%u vm_id=%u", handle, offset, ctx->vm_id);
  
  if(handle) {
    #if 0
    /* If the handle is valid, we can look it up in mmap_wait_for_exec. */
    mmap_key.handle = handle;
    mmap_key.pid = pid;
    mmap_val_ptr = bpf_map_lookup_elem(&mmap_wait_for_exec, &mmap_key);
    if(!mmap_val_ptr) {
      return 0;
    }
    #endif
    return 0;
  } else {
    /* If the handle is zero, it should be bound into the VM associated with this context.
       In this case, exec->offset should contain the address, but we'll have to lookup
       the size of the buffer from the vm_bind family of functions. */
    if((ctx->vm_id == 0) || (offset == 0)) {
      /* We can't perform a lookup without both of these */
      return 0;
    }
    __builtin_memset(&vm_bind_key, 0, sizeof(struct vm_bind_wait_for_exec_key));
    vm_bind_key.vm_id = ctx->vm_id;
    vm_bind_key.data = offset;
    bpf_printk("Looking to see vm_id=%u data=%u", vm_bind_key.vm_id, vm_bind_key.data);
    vm_bind_val_ptr = bpf_map_lookup_elem(&vm_bind_wait_for_exec, &vm_bind_key);
    if(!vm_bind_val_ptr) {
      return 0;
    }
    
    data = offset;
    data_sz = vm_bind_val_ptr->data_sz;
    offset = 0;
  }
  
  kinfo = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_info), 0);
  if(!kinfo) {
    return 0;
  }

  kinfo->pid = pid;
  kinfo->handle = handle;
  kinfo->data = data;
  kinfo->data_sz = data_sz;
  kinfo->offset = offset;
  kinfo->is_bb = (index == batch_index);
  bpf_get_current_comm(kinfo->name, sizeof(kinfo->name));

  bpf_ringbuf_submit(kinfo, BPF_RB_FORCE_WAKEUP);
  
#if 0
  /* The element exists, and could have multiple data pointers. Iterate over them
     and send them all into the ringbuffer. */
  #pragma clang loop unroll(full)
  for(i = 0; i < MAX_DUPLICATES; i++) {
    
    data = val_ptr->data[i];
    data_sz = val_ptr->data_sz[i];
    
    if((data == 0) || (data_sz == 0)) {
      break;
    }
    
    kinfo = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_info), 0);
    if(!kinfo) {
      return 0;
    }
  
    kinfo->pid = ctx->key.pid;
    kinfo->handle = ctx->handle;
    kinfo->data = data;
    kinfo->data_sz = data_sz;
    kinfo->offset = BPF_CORE_READ(&exec[batch_index], offset);
    kinfo->is_bb = (index == batch_index);
    bpf_get_current_comm(kinfo->name, sizeof(kinfo->name));
  
    bpf_ringbuf_submit(kinfo, BPF_RB_FORCE_WAKEUP);
  }
#endif
  
  return 0;
}

SEC("kprobe/i915_gem_do_execbuffer")
int do_execbuffer_kprobe(struct pt_regs *ctx)
{
  struct each_batch_ctx callback_ctx = {};
  unsigned int num_batches, i;
  struct drm_i915_gem_execbuffer2 *args = (struct drm_i915_gem_execbuffer2 *) PT_REGS_PARM3(ctx);
  struct drm_i915_gem_exec_object2 *exec;
  u32 ctx_id, vm_id;
  u64 data, data_sz;
  void *val_ptr;
  struct vm_bind_wait_for_exec_val *vm_binds;
  struct kernel_info *kinfo;
  
  exec = (struct drm_i915_gem_exec_object2 *) PT_REGS_PARM4(ctx);
  
  /* Look up the VM ID based on the context ID (which is in exec->rsvd1) */
  ctx_id = (u32) BPF_CORE_READ(args, rsvd1);
  vm_id = 0;
  if(ctx_id) {
    val_ptr = bpf_map_lookup_elem(&context_create_wait_for_exec, &ctx_id);
    if(val_ptr) {
      vm_id = *((u32 *) val_ptr);
    }
  }
  
  num_batches = BPF_CORE_READ(args, buffer_count);
  callback_ctx.vm_id = vm_id;
  callback_ctx.exec = exec;
  callback_ctx.pid = bpf_get_current_pid_tgid() >> 32;
  callback_ctx.batch_index = (BPF_CORE_READ(args, flags) & I915_EXEC_BATCH_FIRST) ? 0 : BPF_CORE_READ(args, buffer_count) - 1;
  
  /* DEBUG */
  bpf_printk("do_execbuffer_kprobe pid=%u buffer_count=%u batch_start_offset=%u", callback_ctx.pid, num_batches, BPF_CORE_READ(args, batch_start_offset));
  
  /* Here, we can't use bpf_loop because we want it to work on kernels
     older than those that support this. */
  #pragma clang loop unroll(full)
  for(i = 0; i < 32; i++) {
    if(i == num_batches)  break;
    
    if(each_batch_callback(i, &callback_ctx) != 0) {
      return 1;
    }
  }
  
  
  #if 0
  
  /* We're going to look up all of the buffers that are bound to this VM,
     and send them to userspace. */
  bpf_printk("execbuffer got ctx_id=%u vm_id=%u", ctx_id, vm_id);
  vm_binds = bpf_map_lookup_elem(&vm_bind_wait_for_exec, &vm_id);
  if(!vm_binds) {
    return 0;
  }
  
  /* Iterate over the VM addrs that were collected */
  #pragma clang loop unroll(full)
  for(i = 0; i < MAX_VM_ADDRS; i++) {
    
    data = vm_binds->data[i];
    data_sz = vm_binds->data_sz[i];
    handle = vm_binds->handle[i];
    
    if((data == 0) || (data_sz == 0)) {
      break;
    }
    
    kinfo = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_info), 0);
    if(!kinfo) {
      return 0;
    }
  
    kinfo->pid = callback_ctx.key.pid;
    kinfo->handle = handle;
    kinfo->data = data;
    kinfo->data_sz = data_sz;
    kinfo->offset = 0;
    kinfo->is_bb = 0;
    bpf_get_current_comm(kinfo->name, sizeof(kinfo->name));
  
    bpf_ringbuf_submit(kinfo, BPF_RB_FORCE_WAKEUP);
  }
  #endif
  
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
