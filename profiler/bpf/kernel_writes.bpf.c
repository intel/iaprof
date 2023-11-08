#include "i915.h"
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kernel_writes.h"

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
  struct drm_file *file = (struct drm_file *) PT_REGS_PARM3(ctx);
  struct drm_i915_gem_pwrite *gem_pwrite = (struct drm_i915_gem_pwrite *) PT_REGS_PARM2(ctx);
  struct kernel_info *kinfo;
  
  kinfo = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_info), 0);
  if(!kinfo) {
    return 1;
  }
  
  kinfo->pid = bpf_get_current_pid_tgid() >> 32;
  kinfo->handle = BPF_CORE_READ(gem_pwrite, handle);
  kinfo->file = file;
  kinfo->data = BPF_CORE_READ(gem_pwrite, data_ptr);
  kinfo->data_sz = BPF_CORE_READ(gem_pwrite, size);
  bpf_get_current_comm(kinfo->name, sizeof(kinfo->name));
  
  bpf_ringbuf_submit(kinfo, 0);
  
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

struct wait_for_exec_key {
  u32 pid;
  u32 handle;
};

struct wait_for_ret_val {
  struct drm_file *file;
  struct drm_i915_gem_mmap *gem_mmap;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct wait_for_exec_key);
  __type(value, struct kernel_info);
} mmap_wait_for_exec SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct wait_for_ret_val);
} mmap_ioctl_wait_for_ret SEC(".maps");

/* Capture any pointers that userspace has mmap'd. */
SEC("kprobe/i915_gem_mmap_ioctl")
int mmap_ioctl_kprobe(struct pt_regs *ctx)
{
  struct drm_i915_gem_mmap *gem_mmap = (struct drm_i915_gem_mmap *) PT_REGS_PARM2(ctx);
  struct drm_file *file = (struct drm_file *) PT_REGS_PARM3(ctx);
  
  u32 cpu = bpf_get_smp_processor_id();
  
  /* Pass two arguments to the kretprobe */
  struct wait_for_ret_val val = {};
  val.file = file;
  val.gem_mmap = gem_mmap;
  
  bpf_map_update_elem(&mmap_ioctl_wait_for_ret, &cpu, &val, 0);
}

/* We have to wait for this function to return to read its address */
SEC("kretprobe/i915_gem_mmap_ioctl")
int mmap_ioctl_kretprobe(struct pt_regs *ctx)
{
  /* First, see if we've got the element from when this call first started */
  u32 cpu = bpf_get_smp_processor_id();
  void *arg = bpf_map_lookup_elem(&mmap_ioctl_wait_for_ret, &cpu);
  if(!arg) {
    return 1;
  }
  
  struct wait_for_ret_val val = *((struct wait_for_ret_val *) arg);
  struct drm_i915_gem_mmap *gem_mmap = val.gem_mmap;
  
  /* Construct the key: `struct wait_for_exec` */
  struct wait_for_exec_key key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  key.handle = BPF_CORE_READ(gem_mmap, handle);
  
  /* Construct the value: an incomplete `struct kernel_info`. */
  struct kernel_info kinfo = {};
  kinfo.pid = bpf_get_current_pid_tgid() >> 32;
  kinfo.handle = BPF_CORE_READ(gem_mmap, handle);
  kinfo.data = BPF_CORE_READ(gem_mmap, addr_ptr);
  kinfo.data_sz = BPF_CORE_READ(gem_mmap, size);
  bpf_get_current_comm(kinfo.name, sizeof(kinfo.name));
  
  bpf_map_update_elem(&mmap_wait_for_exec, &key, &kinfo, 0);
  
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
  struct drm_file *file;
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
  struct drm_file *file = (struct drm_file *) PT_REGS_PARM3(ctx);
  
  /* We're just going to immediately send this to the kretprobe */
  u32 cpu = bpf_get_smp_processor_id();
  struct mmap_wait_for_ret_val val = {};
  val.file = file;
  val.vma = vma;
  bpf_map_update_elem(&mmap_wait_for_ret, &cpu, &val, 0);
  
  /* DEBUG */
  bpf_printk("mmap_kprobe file=0x%llx vma=0x%llx", file, vma);
  
  return 0;
}

SEC("kretprobe/i915_gem_mmap")
int mmap_kretprobe(struct pt_regs *ctx)
{
  /* Get the vma and drm_file from the kprobe */
  u32 cpu = bpf_get_smp_processor_id();
  void *arg = bpf_map_lookup_elem(&mmap_wait_for_ret, &cpu);
  if(!arg) {
    return 1;
  }
  struct mmap_wait_for_ret_val val = *((struct mmap_wait_for_ret_val *) arg);
  struct vm_area_struct *vma = val.vma;
  struct drm_file *file = val.file;
  
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
  u32 handle = *((u32 *) arg);
  
  struct wait_for_exec_key key = {};
  key.handle = handle;
  key.pid = bpf_get_current_pid_tgid() >> 32;
  
  struct kernel_info kinfo = {};
  kinfo.pid = bpf_get_current_pid_tgid() >> 32;
  kinfo.handle = handle;
  kinfo.file = file;
  kinfo.data = vm_start;
  kinfo.data_sz = vm_end - vm_start;
  bpf_get_current_comm(kinfo.name, sizeof(kinfo.name));
  
  bpf_map_update_elem(&mmap_wait_for_exec, &key, &kinfo, 0);
  
  /* DEBUG */
  bpf_printk("mmap_kretprobe file=0x%llx vma=0x%llx handle=%u vm_pgoff=0x%lx vm_start=0x%lx vm_end=0x%lx", file, vma, handle, vm_pgoff, vm_start, vm_end);
  
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
  
  /* Now that the ioctl is returning, we can read the GEM handle and
     pass it along to i915_gem_do_execbuffer. */
  struct wait_for_exec_key key = {};
  key.handle = BPF_CORE_READ(gem_userptr, handle);
  key.pid = bpf_get_current_pid_tgid() >> 32;
  
  struct kernel_info kinfo = {};
  kinfo.pid = bpf_get_current_pid_tgid() >> 32;
  kinfo.handle = key.handle;
  kinfo.data = BPF_CORE_READ(gem_userptr, user_ptr);
  kinfo.data_sz = BPF_CORE_READ(gem_userptr, user_size);
  bpf_get_current_comm(kinfo.name, sizeof(kinfo.name));
  
  bpf_map_update_elem(&mmap_wait_for_exec, &key, &kinfo, 0);
  
  /* DEBUG */
  bpf_printk("userptr_ioctl_kretprobe pid=%u handle=%u data=0x%llx data_sz=%llu", kinfo.pid, kinfo.handle, kinfo.data, kinfo.data_sz);
}

/***************************************
* i915_gem_do_execbuffer
*
* Now we've got a map of GEM handles that have been mmap'd. Look through the
* GEM handles that are going to be executed, and send them to userspace.
***************************************/

SEC("kprobe/i915_gem_do_execbuffer")
int do_execbuffer_kprobe(struct pt_regs *ctx)
{
  struct kernel_info *elem;
  unsigned int batch_index, num_batches;
  struct kernel_info *kinfo;
  u64 data_ptr;
  struct drm_file *file = (struct drm_file *) PT_REGS_PARM2(ctx);
  struct drm_i915_gem_execbuffer2 *args = (struct drm_i915_gem_execbuffer2 *) PT_REGS_PARM3(ctx);
  struct drm_i915_gem_exec_object2 *exec = (struct drm_i915_gem_exec_object2 *) PT_REGS_PARM4(ctx);
  struct wait_for_exec_key key = {};
  key.pid = bpf_get_current_pid_tgid() >> 32;
  
  /* Loop over the drm_i915_gem_exec_object2 structs */
  num_batches = BPF_CORE_READ(args, buffer_count);
  bpf_printk("do_execbuffer_kprobe pid=%u buffer_count=%u batch_start_offset=%u", key.pid, num_batches, BPF_CORE_READ(args, batch_start_offset));
  
  /* Determine where the batch buffer is */
  batch_index = (BPF_CORE_READ(args, flags) & I915_EXEC_BATCH_FIRST) ? 0 : BPF_CORE_READ(args, buffer_count) - 1;
  
  /* If we find the handle in our internal map, this means that it
      was previously mmap'd, so add it to the output map */
  key.handle = BPF_CORE_READ(&exec[batch_index], handle);
    
  /* DEBUG */
  bpf_printk("do_execbuffer_kprobe handle=%u pid=%u", key.handle, key.pid);
    
  elem = (struct kernel_info *) bpf_map_lookup_elem(&mmap_wait_for_exec, &key);
  if(elem) {
    /* If we find a match, that means that we've seen a previous mmap for this GEM handle
        with this drm_file pointer. Go ahead and send it all to userspace. */
    kinfo = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_info), 0);
    if(!kinfo) {
      return 1;
    }
    kinfo->pid = elem->pid;
    kinfo->handle = elem->handle;
    kinfo->file = file;
    kinfo->data = elem->data;
    kinfo->data_sz = elem->data_sz;
    kinfo->offset = BPF_CORE_READ(&exec[batch_index], offset);
    bpf_get_current_comm(kinfo->name, sizeof(kinfo->name));
    bpf_ringbuf_submit(kinfo, BPF_RB_FORCE_WAKEUP);
  }
}

char LICENSE[] SEC("license") = "GPL";
