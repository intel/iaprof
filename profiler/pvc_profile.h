#pragma once

#include <asm/types.h>
#include "bpf/gem_collector.h"
#include "utils/hash_table.h"
#include "utils/utils.h"

use_hash_table(uint64_t, uint64_t);

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

struct gem_profile {
  struct buffer_info kinfo;
  
  uint64_t buff_sz;
  unsigned char *buff;
  
  unsigned char is_shader;
  struct shader_profile shader_profile;
} __attribute__((packed));

#define GEM_ARR_TYPE struct gem_profile
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
