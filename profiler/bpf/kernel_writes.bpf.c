#include "i915.h"
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kernel_writes.h"

/* This is the "output" map, which userspace reads to get information
   about GPU kernels running on the system. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_ENTRIES);
} rb SEC(".maps");

/* If we see a pwrite ioctl call, we can just pass that pointer to userspace. */
SEC("kprobe/i915_gem_pwrite_ioctl")
int pwrite_kprobe(struct pt_regs *ctx)
{
  struct drm_i915_gem_pwrite *arg = (struct drm_i915_gem_pwrite *) PT_REGS_PARM2(ctx);
  struct kernel_info *kinfo;
  
  kinfo = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_info), 0);
  if(!kinfo) {
    return 1;
  }
  
  kinfo->pid = bpf_get_current_pid_tgid() >> 32;
  kinfo->handle = BPF_CORE_READ(arg, handle);
  kinfo->data = BPF_CORE_READ(arg, data_ptr);
  kinfo->data_sz = BPF_CORE_READ(arg, size);
  bpf_get_current_comm(kinfo->name, sizeof(kinfo->name));
  
  bpf_ringbuf_submit(kinfo, 0);
  
  return 0;
}

/* If we see that an application has mmap'd a GEM to write it later, let's record that in an
   internal map, then output it to userspace after we know that it has been written. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct kernel_info);
} mmap_wait_for_exec SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, u64);
} mmap_wait_for_ret SEC(".maps");

/* Capture any pointers that userspace has mmap'd. */
SEC("kprobe/i915_gem_mmap_ioctl")
int mmap_kprobe(struct pt_regs *ctx)
{
  u64 arg = PT_REGS_PARM2(ctx);
  u32 cpu = bpf_get_smp_processor_id();
  bpf_map_update_elem(&mmap_wait_for_ret, &cpu, &arg, 0);
}

/* We have to wait for this function to return to read its address */
SEC("kretprobe/i915_gem_mmap_ioctl")
int mmap_kretprobe(struct pt_regs *ctx)
{
  /* First, see if we've got the element from when this call first started */
  u32 cpu = bpf_get_smp_processor_id();
  void *arg = bpf_map_lookup_elem(&mmap_wait_for_ret, &cpu);
  if(!arg) {
    return 1;
  }
  
  struct drm_i915_gem_mmap *gem_mmap = *((struct drm_i915_gem_mmap **) arg);
  struct kernel_info kinfo = {};
  
  kinfo.pid = bpf_get_current_pid_tgid() >> 32;
  kinfo.handle = BPF_CORE_READ(gem_mmap, handle);
  kinfo.data = BPF_CORE_READ(gem_mmap, addr_ptr);
  kinfo.data_sz = BPF_CORE_READ(gem_mmap, size);
  bpf_get_current_comm(kinfo.name, sizeof(kinfo.name));
  
  bpf_map_update_elem(&mmap_wait_for_exec, &(kinfo.handle), &kinfo, 0);
  
  return 0;
}

SEC("kprobe/i915_gem_do_execbuffer")
int do_execbuffer_kprobe(struct pt_regs *ctx)
{
  struct kernel_info *elem;
  unsigned int bound, i, lookup;
  struct kernel_info *kinfo;
  struct drm_i915_gem_execbuffer2 *args = (struct drm_i915_gem_execbuffer2 *) PT_REGS_PARM3(ctx);
  struct drm_i915_gem_exec_object2 *exec = (struct drm_i915_gem_exec_object2 *) PT_REGS_PARM4(ctx);
  
  /* Loop over the drm_i915_gem_exec_object2 structs */
  bound = BPF_CORE_READ(args, buffer_count);
  if(bound > 64) {
    bound = 64;
  }
  for(i = 0; i < bound; i++) {
    /* If we find the handle in our internal map, this means that it
       was previously mmap'd, so add it to the output map */
    lookup = BPF_CORE_READ(exec, handle);
    elem = (struct kernel_info *) bpf_map_lookup_elem(&mmap_wait_for_exec, &lookup);
    if(elem) {
      bpf_printk("Added handle %u to the map\n", elem->handle);
      kinfo = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_info), 0);
      if(!kinfo) {
        return 1;
      }
      kinfo->pid = elem->pid;
      kinfo->handle = elem->handle;
      kinfo->data = elem->data;
      kinfo->data_sz = elem->data_sz;
      bpf_get_current_comm(kinfo->name, sizeof(kinfo->name));
      bpf_ringbuf_submit(kinfo, 0);
    }
    
    exec++;
  }
}

char LICENSE[] SEC("license") = "GPL";
