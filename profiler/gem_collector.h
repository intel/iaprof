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

int store_sample(struct gem_info *kinfo) {
  size_t old_size;
  GEM_ARR_TYPE *gem;
  uint64_t n;
  
  if(pthread_rwlock_wrlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to acquire the gem_lock!\n");
    return -1;
  }
  
  /* Ensure it's not a duplicate */
  for(n = 0; n < gem_arr_used; n++) {
    gem = &gem_arr[n];
    if((gem->kinfo.handle == kinfo->handle) &&
       (gem->kinfo.file   == kinfo->file)) {
      if(pthread_rwlock_unlock(&gem_lock) != 0) {
        fprintf(stderr, "Failed to unlock the gem_lock!\n");
        return -1;
      }
      return 0;
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
  
  /* Place this new element */
  memcpy(&(gem_arr[gem_arr_used].kinfo), kinfo, sizeof(struct gem_info));
  gem_arr_used++;
  
  if(pthread_rwlock_unlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to unlock the gem_lock!\n");
    return -1;
  }
  
  return 0;
}

static int handle_sample(void *ctx, void *data_arg, size_t data_sz) {
  struct gem_info *kinfo;
  unsigned char *data;
  
  kinfo = (struct gem_info *) data_arg;
  
  printf("handle_sample addr=0x%llx gpu_addr=0x%llx size=%llu batch_start_offset=%u length=%llu pid=%u comm=%s handle=%u offset=%llx\n", kinfo->addr, kinfo->gpu_addr, kinfo->size, kinfo->batch_start_offset, kinfo->batch_len, kinfo->pid, kinfo->name, kinfo->handle, kinfo->offset);
  
  store_sample(kinfo);
  
  return 0;
}

static int handle_binary(void *ctx, void *data_arg, size_t data_sz) {
  struct binary_info *binary_info;
  GEM_ARR_TYPE *gem;
  uint64_t n, start, end, size;
  char found;
  
  binary_info = (struct binary_info *) data_arg;
  
  printf("handle_binary start=0x%llx end=%llu\n", binary_info->start, binary_info->end);
  
  if(pthread_rwlock_wrlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to acquire the gem_lock!\n");
    return -1;
  }
  
  found = 0;
  for(n = 0; n < gem_arr_used; n++) {
    gem = &gem_arr[n];
    start = gem->kinfo.addr;
    end = gem->kinfo.addr + gem->kinfo.size;
    if((binary_info->start >= start) && (binary_info->end <= end)) {
      size = binary_info->end - binary_info->start;
      gem->buff = calloc(size, sizeof(unsigned char));
      gem->buff_sz = size;
      memcpy(gem->buff, binary_info->buff, size);
      found = 1;
      break;
    }
  }
  
  if(pthread_rwlock_unlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to unlock the gem_lock!\n");
    return -1;
  }
  
  if(found == 0) {
    return -1;
  }
  return 0;
}

struct bpf_info_t {
  struct gem_collector_bpf *obj;
  struct ring_buffer *rb;
  struct ring_buffer *binary_rb;
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
static struct bpf_info_t bpf_info = {};

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
  
  bpf_info.binary_rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.binary_rb), handle_binary, NULL, NULL);
  if(!(bpf_info.binary_rb)) {
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
