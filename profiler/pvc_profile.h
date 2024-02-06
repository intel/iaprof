#pragma once

#include <asm/types.h>
#include <linux/bpf.h>
#include "bpf/gem_collector.h"
#include "utils/hash_table.h"
#include "utils/utils.h"

use_hash_table(uint64_t, uint64_t);

extern char debug;

/** 101 bits
  * Bits    Field
  * 0  to 28  IP (addr)
  * 29 to 36  active count
  * 37 to 44  other count
  * 45 to 52  control count
  * 53 to 60  pipestall count
  * 61 to 68  send count
  * 69 to 76  dist_acc count
  * 77 to 84  sbid count
  * 85 to 92  sync count
  * 93 to 100  inst_fetch count
**/
struct __attribute__ ((__packed__)) eustall_sample {
  unsigned int ip : 29;
  unsigned short active : 8;
  unsigned short other : 8;
  unsigned short control : 8;
  unsigned short pipestall : 8;
  unsigned short send : 8;
  unsigned short dist_acc : 8;
  unsigned short sbid : 8;
  unsigned short sync : 8;
  unsigned short inst_fetch : 8;
};

/**
  * Reason     Description
  ************************
  * Active     At least one instruction is dispatching into a pipeline.
  * Other      Other factors stalled the instruction's execution.
  * Control    The instruction was waiting for a Branch unit to become
  *            available.
  * Pipestall  The instruction won arbitration but could not be dispatched
  *            into a Floating-Point or Extended Math unit. This can occur
  *            due to a bank conflict with the General Register File (GRF).
  * Send       The instruction was waiting for a Send unit to become available.
  * Dist/Acc   The instruction was waiting for a Distance or Architecture
  *            Register File (ARF) dependency to resolve.
  * SBID       The instruction was waiting for a Software Scoreboard
  *            dependency to resolve.
  * Sync       The instruction was waiting for a thread synchronization
  *            dependency to resolve.
  * Inst Fetch The XVE (Xe Vector Engine) was waiting for an instruction to 
  *            be returned from the instruction cache.
**/

struct offset_profile {
  unsigned int active;
  unsigned int other;
  unsigned int control;
  unsigned int pipestall;
  unsigned int send;
  unsigned int dist_acc;
  unsigned int sbid;
  unsigned int sync;
  unsigned int inst_fetch;
};
  
struct shader_profile {
  /* The EU stalls. Key is the offset into the binary,
     value is a pointer to the struct of EU stall counts */
  hash_table(uint64_t, uint64_t) counts;
};

struct buffer_profile {
  struct vm_bind_info vm_bind_info;
  struct mapping_info mapping_info;
  struct execbuf_start_info exec_info;
  
  /* A copy of the buffer bytes itself */
  uint64_t buff_sz;
  unsigned char *buff;
  
  /* The stack where this buffer was execbuffer'd */
  char *execbuf_stack_str;
  
  /* Set if EU stalls are associated with this buffer */
  unsigned char has_stalls;
  struct shader_profile shader_profile;
};

#define GEM_ARR_TYPE struct buffer_profile
extern pthread_rwlock_t gem_lock;
extern GEM_ARR_TYPE *gem_arr;
extern size_t gem_arr_sz, gem_arr_used;

extern char verbose;

struct bpf_info_t {
  struct gem_collector_bpf *obj;
  struct ring_buffer *rb;
  struct bpf_map **map;
  
  /* Links to the BPF programs */
  struct bpf_link **links;
  size_t num_links;
  
  /* i915_gem_pwrite_ioctl */
/*   struct bpf_program *pwrite_ioctl_prog; */
  
  /* i915_gem_mmap_ioctl */
  struct bpf_program *mmap_ioctl_prog;
  struct bpf_program *mmap_ioctl_ret_prog;
  
  /* i915_gem_mmap_offset_ioctl and friends */
  struct bpf_program *mmap_offset_ioctl_prog;
  struct bpf_program *mmap_offset_ioctl_ret_prog;
  struct bpf_program *mmap_prog;
  struct bpf_program *mmap_ret_prog;
  
  /* i915_gem_userptr_ioctl */
/*   struct bpf_program *userptr_ioctl_prog; */
/*   struct bpf_program *userptr_ioctl_ret_prog; */
  
  /* i915_gem_vm_bind_ioctl */
  struct bpf_program *vm_bind_ioctl_prog;
  struct bpf_program *vm_bind_ioctl_ret_prog;
  
  /* i915_gem_vm_unbind_ioctl */
  struct bpf_program *vm_unbind_ioctl_prog;
  
  /* i915_gem_context_create_ioctl */
  struct bpf_program *context_create_ioctl_prog;
  struct bpf_program *context_create_ioctl_ret_prog;
  
  /* i915_gem_do_execbuffer */
  struct bpf_program *do_execbuffer_prog;
  struct bpf_program *do_execbuffer_ret_prog;
  
  /* munmap */
  struct bpf_program *munmap_prog;
  
  /* vm_close */
/*   struct bpf_program *vm_close_prog; */
};
extern struct bpf_info_t bpf_info;
