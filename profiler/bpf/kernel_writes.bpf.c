#include "i915.h"
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kernel_writes.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_ENTRIES);
} rb SEC(".maps");

SEC("kprobe/i915_gem_pwrite_ioctl")
int pwrite_kprobe(struct pt_regs *ctx)
{
  u32 cpu;
  struct drm_i915_gem_pwrite *arg = (void *) PT_REGS_PARM1(ctx);
  
  struct kernel_info *kinfo;
  
  kinfo = bpf_ringbuf_reserve(&rb, sizeof(struct kernel_info), 0);
  if(!kinfo) {
    return 1;
  }
  
  kinfo->pid = bpf_get_current_pid_tgid() >> 32;
  /*
  kinfo->data = (void *) bpf_core_read(arg, sizeof(arg->data_ptr), arg->data_ptr);
  */
  kinfo->data_sz = bpf_core_read(arg, sizeof(arg->size), arg->size);
  bpf_get_current_comm(kinfo->name, sizeof(kinfo->name));
  
  bpf_ringbuf_submit(kinfo, 0);
  
  return 0;
}
