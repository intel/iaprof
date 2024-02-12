#pragma once

/***************************************
* GEM Collector
***************
* This file receives samples from the BPF programs'
* ringbuffer. Its primary purpose is maintaining
* a global array of `struct buffer_profile`, which
* represents the accumulated information that we know
* about each buffer.
*
* Each of the `handle_*` functions handles a different
* type of struct that the ringbuffer contains.
***************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#include <iga/iga.h>
#include "bpf/gem_collector.h"
#include "bpf/gem_collector.skel.h"
#include "printer.h"

/***************************************
* Buffer Profile Array
**********************
* These functions simply maintain a global array
* of type `struct buffer_profile`.
***************************************/

/* Return -1 if not found, otherwise the index of the buffer_profile */
int get_buffer_profile(uint64_t file, uint32_t handle) {
  int n;
  struct buffer_profile *gem;
  
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    if((gem->mapping_info.handle == handle) &&
       (gem->mapping_info.file   == file)) {
      return n;
    }
  }
  
  return -1;
}

/* Return -1 if not found, otherwise the index of the buffer_profile */
int get_buffer_profile_by_binding(uint64_t file, uint32_t handle) {
  int n;
  struct buffer_profile *gem;
  
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    if((gem->vm_bind_info.handle == handle) &&
       (gem->vm_bind_info.file   == file)) {
      return n;
    }
  }
  
  return -1;
}

/* Return -1 if not found, otherwise the index of the buffer_profile */
int get_buffer_profile_by_gpu_addr(uint64_t gpu_addr) {
  int n;
  struct buffer_profile *gem;
  
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    if(gem->vm_bind_info.gpu_addr == gpu_addr) {
      return n;
    }
  }
  
  return -1;
}

/* Ensure that we have enough room to place a newly-seen sample, and place it.
   Does NOT grab the lock, so the caller should. */
uint64_t grow_buffer_profiles() {
  size_t old_size;
  struct buffer_profile *gem;
  
  /* Ensure there's enough room in the array */
  if(buffer_profile_size == buffer_profile_used) {
    /* Not enough room in the array */
    old_size = buffer_profile_size;
    buffer_profile_size += 64;
    buffer_profile_arr = realloc(buffer_profile_arr, buffer_profile_size * sizeof(struct buffer_profile));
    memset(buffer_profile_arr + buffer_profile_used, 0, (buffer_profile_size - old_size) * sizeof(struct buffer_profile));
  }
  
  buffer_profile_used++;
  return buffer_profile_used - 1;
}

int handle_mapping(void *data_arg) {
  struct buffer_profile *gem;
  int index;
  struct mapping_info *info;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct mapping_info *) data_arg;
  if(debug) {
    print_mapping(info);
  }
  
  /* First, check to see if this mapping has already had vm_bind
     called on it. */
  index = get_buffer_profile_by_binding(info->file, info->handle);
  if(index == -1) {
    index = get_buffer_profile(info->file, info->handle);
    if(index == -1) {
      index = grow_buffer_profiles();
    } else {
      fprintf(stderr, "WARNING: Detected churn on file=0x%llx handle=%u\n", info->file, info->handle);
    }
  }
  
  gem = &buffer_profile_arr[index];
  memcpy(&(gem->mapping_info), info, sizeof(struct mapping_info));
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
    return -1;
  }
  
  return 0;
}

/***************************************
* BPF Handlers
**********************
* These functions each handle a different struct
* which the BPF programs' ringbuffer can contain.
***************************************/

int handle_binary(void *data_arg) {
  struct binary_info *info;
  uint64_t size;
  int index;
  struct buffer_profile *gem;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct binary_info *) data_arg;
  if(debug) {
    print_binary(info);
  }
  
  index = get_buffer_profile(info->file, info->handle);
  if(index == -1) {
    fprintf(stderr, "WARNING: handle_binary called on a mapping that hasn't happened yet.\n");
    if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
      fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
      return -1;
    }
    return 0;
  }
  gem = &(buffer_profile_arr[index]);
  size = info->size;
  if(size > MAX_BINARY_SIZE) {
    size = MAX_BINARY_SIZE;
  }
  gem->buff = calloc(size, sizeof(unsigned char));
  gem->buff_sz = size;
  memcpy(gem->buff, info->buff, size);
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  return 0;
}

int handle_vm_bind(void *data_arg) {
  struct buffer_profile *gem;
  int index;
  struct vm_bind_info *info;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct vm_bind_info *) data_arg;
  if(debug) {
    print_vm_bind(info);
  }
  
  /* Check to see if we've seen mmap get called on this file/handle pair
     yet. If so, use that index, but if not, allocate a new one. */
  index = get_buffer_profile(info->file, info->handle);
  if(index == -1) {
    index = grow_buffer_profiles();
  }
  
  /* Copy the vm_bind_info into the buffer's profile. */
  gem = &(buffer_profile_arr[index]);
  memcpy(&(gem->vm_bind_info), info, sizeof(struct vm_bind_info));
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  return 0;
}

int handle_vm_unbind(void *data_arg) {
  struct buffer_profile *gem;
  struct vm_unbind_info *info;
  int index;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct vm_unbind_info *) data_arg;
  if(debug) {
    print_vm_unbind(info);
  }
  
  /* Try to find the buffer that this is unbinding. Note that
     info->handle is going to be 0 here, so we need to use
     the GPU address to look it up. */
  index = get_buffer_profile_by_gpu_addr(info->gpu_addr);
  if(index == -1) {
    if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
      fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
      return -1;
    }
    fprintf(stderr, "WARNING: Got a vm_unbind on gpu_addr=0x%llx for which there wasn't a vm_bind!\n", info->gpu_addr);
    return 0;
  }
  
  /* Zero out the vm_bind_info of the buffer that we've found.
     Note that after this is done, EU stalls can no longer be
     associated with it. */
  gem = &(buffer_profile_arr[index]);
  memset(&(gem->vm_bind_info), 0, sizeof(struct vm_bind_info));
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  return 0;
}

int handle_execbuf_start(void *data_arg) {
  struct buffer_profile *gem;
  uint32_t vm_id, pid;
  int n;
  struct execbuf_start_info *info;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct execbuf_start_info *) data_arg;
  if(debug) {
    print_execbuf_start(info);
  }
  
  /* This execbuffer call needs to be associated with all GEMs that
     are referenced by this call. Buffers can be referenced in two ways:
     1. Directly in the execbuffer call.
     2. Through the ctx_id (which has an associated vm_id).
     
     Here, we'll iterate over all buffers in the given vm_id. */
  vm_id = info->vm_id;
  pid = info->pid;
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    if((gem->vm_bind_info.vm_id == vm_id) &&
       (gem->vm_bind_info.pid == pid)) {
      memcpy(&(gem->exec_info), info, sizeof(struct execbuf_start_info));
    }
    if(gem->execbuf_stack_str == NULL) {
      store_stack(info->pid, info->stackid, &(gem->execbuf_stack_str));
    }
  }
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
    return -1;
  }

  return 0;
}

int handle_execbuf_end(void *data_arg) {
  struct execbuf_end_info *info;
  info = (struct execbuf_end_info *) data_arg;
  if(debug) {
    print_execbuf_end(info);
  }
  
  return 0;
}

/* Runs each time a sample from the ringbuffer is collected.
   Samples can be one of four types:
   1. struct mapping_info. This is a struct collected when an `execbuffer` call is made,
      and represents a buffer that is either directly referenced by the `execbuffer`
      call, or a buffer that's in the "VM" assigned to the context that's executing.
   2. struct binary_info. This is a struct collected when `munmap` is called on a
      VMA that was mapped by i915. Assuming we've seen the associated `mmap` call
      from i915, the buffer is then copied into the ringbuffer (along with some
      metadata).
   3. struct execbuf_start_info. Basic metadata collected at the beginning of an
      execbuffer call.
   4. struct execbuffer_end_info. Basic metadata collected at the end of an
      execbuffer call. */
static int handle_sample(void *ctx, void *data_arg, size_t data_sz) {
  unsigned char *data;
  
  
  if(data_sz == sizeof(struct mapping_info)) {
    return handle_mapping(data_arg);
  } else if(data_sz == sizeof(struct binary_info)) {
    return handle_binary(data_arg);
  } else if(data_sz == sizeof(struct vm_bind_info)) {
    return handle_vm_bind(data_arg);
  } else if(data_sz == sizeof(struct vm_unbind_info)) {
    return handle_vm_unbind(data_arg);
  } else if(data_sz == sizeof(struct execbuf_start_info)) {
    return handle_execbuf_start(data_arg);
  } else if(data_sz == sizeof(struct execbuf_end_info)) {
    return handle_execbuf_start(data_arg);
  } else {
    fprintf(stderr, "Unknown data size when handling a sample: %lu\n", data_sz);
    return -1;
  }
  
  return 0;
}

/***************************************
* BPF Setup
**********************
* These functions set up the kprobes and tracepoints
* in the BPF program.
***************************************/

int attach_kprobe(const char *func, struct bpf_program *prog, int ret) {
  bpf_info.num_links++;
  bpf_info.links = realloc(bpf_info.links, sizeof(struct bpf_link *) * bpf_info.num_links);
  if(!bpf_info.links) {
    fprintf(stderr, "Failed to allocate memory for the BPF links! Aborting.\n");
    return -1;
  }
  bpf_info.links[bpf_info.num_links - 1] = bpf_program__attach_kprobe(prog, ret, func);
  if(libbpf_get_error(bpf_info.links[bpf_info.num_links - 1])) {
    fprintf(stderr, "Failed to attach the BPF program to a kprobe: %s\n", func);
    /* Set this pointer to NULL, since it's undefined what it will be */
    bpf_info.links[bpf_info.num_links - 1] = NULL;
    return -1;
  }
  
  return 0;
}

int attach_tracepoint(const char *category, const char *func, struct bpf_program *prog) {
  bpf_info.num_links++;
  bpf_info.links = realloc(bpf_info.links, sizeof(struct bpf_link *) * bpf_info.num_links);
  if(!bpf_info.links) {
    fprintf(stderr, "Failed to allocate memory for the BPF links! Aborting.\n");
    return -1;
  }
  bpf_info.links[bpf_info.num_links - 1] = bpf_program__attach_tracepoint(prog, category, func);
  if(libbpf_get_error(bpf_info.links[bpf_info.num_links - 1])) {
    fprintf(stderr, "Failed to attach the BPF program to a tracepoint: %s:%s\n", category, func);
    /* Set this pointer to NULL, since it's undefined what it will be */
    bpf_info.links[bpf_info.num_links - 1] = NULL;
    return -1;
  }
  
  return 0;
}

int deinit_bpf_prog() {
  uint64_t i;
  int retval;
  
  for(i = 0; i < bpf_info.num_links; i++) {
    retval = bpf_link__detach(bpf_info.links[i]);
    if(retval == -1) {
      return retval;
    }
  }
  free(bpf_info.links);
  
  bpf_program__unload(bpf_info.mmap_ioctl_prog);
  bpf_program__unload(bpf_info.mmap_ioctl_ret_prog);
  
  bpf_program__unload(bpf_info.mmap_offset_ioctl_prog);
  bpf_program__unload(bpf_info.mmap_offset_ioctl_ret_prog);
  bpf_program__unload(bpf_info.mmap_prog);
  bpf_program__unload(bpf_info.mmap_ret_prog);
  
  bpf_program__unload(bpf_info.vm_bind_ioctl_prog);
  bpf_program__unload(bpf_info.vm_bind_ioctl_ret_prog);
  
  bpf_program__unload(bpf_info.vm_unbind_ioctl_prog);
  
  bpf_program__unload(bpf_info.context_create_ioctl_prog);
  bpf_program__unload(bpf_info.context_create_ioctl_ret_prog);
  
  bpf_program__unload(bpf_info.do_execbuffer_prog);
  bpf_program__unload(bpf_info.do_execbuffer_ret_prog);
  
  bpf_program__unload(bpf_info.munmap_prog);
  
  gem_collector_bpf__destroy(bpf_info.obj);
  
  return 0;
}

int init_bpf_prog() {
  int err;
  struct bpf_object_open_opts opts = {0};

  opts.sz = sizeof(struct bpf_object_open_opts);
  #if 0
  if(pw_opts.btf_custom_path) {
    opts.btf_custom_path = pw_opts.btf_custom_path;
  }
  #endif

  bpf_info.obj = gem_collector_bpf__open_opts(&opts);
  if(!bpf_info.obj) {
    fprintf(stderr, "ERROR: Failed to get BPF object.\n");
    fprintf(stderr, "       Most likely, one of two things are true:\n");
    fprintf(stderr, "       1. You're not root.\n");
    fprintf(stderr, "       2. You don't have a kernel that supports BTF type information.\n");
    return -1;
  }
  err = gem_collector_bpf__load(bpf_info.obj);
  if(err) {
    fprintf(stderr, "Failed to load BPF object!\n");
    return -1;
  }

/*   bpf_info.pwrite_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.pwrite_kprobe; */
  
  bpf_info.mmap_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_ioctl_kprobe;
  bpf_info.mmap_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_ioctl_kretprobe;
  
  bpf_info.mmap_offset_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_offset_ioctl_kprobe;
  bpf_info.mmap_offset_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_offset_ioctl_kretprobe;
  bpf_info.mmap_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_kprobe;
  bpf_info.mmap_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_kretprobe;
  
/*   bpf_info.userptr_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.userptr_ioctl_kprobe; */
/*   bpf_info.userptr_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.userptr_ioctl_kretprobe; */
  
  bpf_info.vm_bind_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.vm_bind_ioctl_kprobe;
  bpf_info.vm_bind_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.vm_bind_ioctl_kretprobe;
  
  bpf_info.vm_unbind_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.vm_unbind_ioctl_kprobe;
  
  bpf_info.context_create_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.context_create_ioctl_kprobe;
  bpf_info.context_create_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.context_create_ioctl_kretprobe;
  
  bpf_info.do_execbuffer_prog = (struct bpf_program *) bpf_info.obj->progs.do_execbuffer_kprobe;
  bpf_info.do_execbuffer_ret_prog = (struct bpf_program *) bpf_info.obj->progs.do_execbuffer_kretprobe;
  
  bpf_info.munmap_prog = (struct bpf_program *) bpf_info.obj->progs.munmap_tp;
  
/*   bpf_info.vm_close_prog = (struct bpf_program *) bpf_info.obj->progs.vm_close_kprobe; */
  
  bpf_info.rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.rb), handle_sample, NULL, NULL);
  if(!(bpf_info.rb)) {
    fprintf(stderr, "Failed to create a new ring buffer. You're most likely not root.\n");
    return -1;
  }
  
  /* i915_gem_pwrite_ioctl */
/*   err = attach_kprobe("i915_gem_pwrite_ioctl", bpf_info.pwrite_ioctl_prog, 0); */
/*   if(err != 0) { */
/*     fprintf(stderr, "Failed to attach a kprobe!\n"); */
/*     return -1; */
/*   } */
  
  /* i915_gem_mmap_ioctl */
  err = attach_kprobe("i915_gem_mmap_ioctl", bpf_info.mmap_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_mmap_ioctl", bpf_info.mmap_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_mmap_offset_ioctl and friends */
  err = attach_kprobe("i915_gem_mmap_offset_ioctl", bpf_info.mmap_offset_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_mmap_offset_ioctl", bpf_info.mmap_offset_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_mmap", bpf_info.mmap_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_mmap", bpf_info.mmap_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_userptr_ioctl */
/*   err = attach_kprobe("i915_gem_userptr_ioctl", bpf_info.userptr_ioctl_prog, 0); */
/*   if(err != 0) { */
/*     fprintf(stderr, "Failed to attach a kprobe!\n"); */
/*     return -1; */
/*   } */
/*   err = attach_kprobe("i915_gem_userptr_ioctl", bpf_info.userptr_ioctl_ret_prog, 1); */
/*   if(err != 0) { */
/*     fprintf(stderr, "Failed to attach a kprobe!\n"); */
/*     return -1; */
/*   } */
  
  /* i915_gem_vm_bind_ioctl */
  err = attach_kprobe("i915_gem_vm_bind_ioctl", bpf_info.vm_bind_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_vm_bind_ioctl", bpf_info.vm_bind_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_vm_unbind_ioctl */
  err = attach_kprobe("i915_gem_vm_unbind_ioctl", bpf_info.vm_unbind_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_context_create_ioctl */
  err = attach_kprobe("i915_gem_context_create_ioctl", bpf_info.context_create_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_context_create_ioctl", bpf_info.context_create_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_do_execbuffer */
  err = attach_kprobe("i915_gem_do_execbuffer", bpf_info.do_execbuffer_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_do_execbuffer", bpf_info.do_execbuffer_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* munmap */
  err = attach_tracepoint("syscalls", "sys_enter_munmap", bpf_info.munmap_prog);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a tracepoint!\n");
    return -1;
  }
  
  /* vm_close */
/*   err = attach_kprobe("vm_close", bpf_info.vm_close_prog, 0); */
/*   if(err != 0) { */
/*     fprintf(stderr, "Failed to attach a kprobe!\n"); */
/*     return -1; */
/*   } */
  
  return 0;
}

/*******************
*      DEBUG       *
*******************/
void print_ringbuf_stats() {
  uint64_t size, avail;
  
  avail = ring__avail_data_size(ring_buffer__ring(bpf_info.rb, 0));
  size = ring__size(ring_buffer__ring(bpf_info.rb, 0));
  printf("GEM ringbuf usage: %lu / %lu\n", avail, size);
}
