#pragma once

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

/* Ensure that we have enough room to place a newly-seen sample, and return
   the index in which we should place it. 
   Does NOT grab the lock, so the caller should. */
uint64_t grow_sample_arr(uint32_t handle, uint64_t file) {
  size_t old_size;
  GEM_ARR_TYPE *gem;
  uint64_t n;
  
  /* First, search for it already being in here, and do some
     sanity checks. */
  for(n = 0; n < gem_arr_used; n++) {
    gem = &gem_arr[n];
    if((gem->kinfo.handle == handle) &&
       (gem->kinfo.file   == file)) {
      return n;
    }
  }
  
  /* Ensure there's enough room in the array */
  if(gem_arr_sz == gem_arr_used) {
    /* Not enough room in the array */
    old_size = gem_arr_sz;
    gem_arr_sz += 64;
    gem_arr = realloc(gem_arr, gem_arr_sz * sizeof(GEM_ARR_TYPE));
    memset(gem_arr + gem_arr_used, 0, (gem_arr_sz - old_size) * sizeof(GEM_ARR_TYPE));
  }
  
  gem_arr_used++;
  return gem_arr_used - 1;
}

/* Runs each time a sample from the ringbuffer is collected.
   Samples can be one of four types:
   1. struct buffer_info. This is a struct collected when an `execbuffer` call is made,
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
  struct buffer_info *kinfo;
  struct binary_info *binary_info;
  struct execbuf_start_info *start_info;
  struct execbuf_end_info *end_info;
  unsigned char *data;
  uint64_t index, file, size;
  uint32_t handle;
  GEM_ARR_TYPE *gem;
  
  if(pthread_rwlock_wrlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to acquire the gem_lock!\n");
    return -1;
  }
  
  if(data_sz == sizeof(struct buffer_info)) {
    kinfo = (struct buffer_info *) data_arg;
    handle = kinfo->handle;
    file = kinfo->file;
    print_buffer(kinfo);
  } else if(data_sz == sizeof(struct binary_info)) {
    binary_info = (struct binary_info *) data_arg;
    handle = binary_info->handle;
    file = binary_info->file;
  } else if(data_sz == sizeof(struct execbuf_start_info)) {
    start_info = (struct execbuf_start_info *) data_arg;
    print_execbuf_start(start_info);
  } else if(data_sz == sizeof(struct execbuf_end_info)) {
    end_info = (struct execbuf_end_info *) data_arg;
    print_execbuf_end(end_info);
  } else {
    if(pthread_rwlock_unlock(&gem_lock) != 0) {
      fprintf(stderr, "Failed to unlock the gem_lock!\n");
      return -1;
    }
    fprintf(stderr, "Unknown data size when handling a sample!\n");
    return -1;
  }
  
  /* Make room! */
  index = grow_sample_arr(handle, file);
  gem = &gem_arr[index];
  
  if(data_sz == sizeof(struct buffer_info)) {
    memcpy(&(gem->kinfo), kinfo, sizeof(struct buffer_info));
  } else if(data_sz == sizeof(struct binary_info)) {
    size = binary_info->end - binary_info->start;
    if(size > MAX_BINARY_SIZE) {
      size = MAX_BINARY_SIZE;
    }
    gem->buff = calloc(size, sizeof(unsigned char));
    gem->buff_sz = size;
    memcpy(gem->buff, binary_info->buff, size);
  }
  
  if(pthread_rwlock_unlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to unlock the gem_lock!\n");
    return -1;
  }
  
  return 0;
}

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
