#pragma once

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

struct bpf_info_t {
  struct kernel_writes_bpf *obj;
  struct ring_buffer *rb;
  struct bpf_map **map;
  
  /* Links to the BPF programs */
  struct bpf_link **links;
  size_t num_links;
  
  /* Programs for the kprobes */
  struct bpf_program *pwrite_prog;
  struct bpf_program *mmap_prog;
  struct bpf_program *mmap_ret_prog;
  struct bpf_program *do_execbuffer_prog;
};
static struct bpf_info_t bpf_info = {};

static int handle_sample(void *ctx, void *data, size_t data_sz) {
  struct kernel_info *kinfo;
  unsigned int *ptr;
  __u64 size;
  int i;
  FILE *mem_file;
  char filename[256];
  unsigned char *kernel;
  size_t num_read;
  
  kinfo = (struct kernel_info *) data;
  printf("Got a sample %p of size %llu from PID %u (%s)\n", kinfo->data, kinfo->data_sz, kinfo->pid, kinfo->name);
  
  #if 0
  /* Open the memory map */
  sprintf(filename, "/proc/%u/maps", kinfo->pid);
  mem_file = fopen(filename, "r");
  if(!mem_file) {
    fprintf(stderr, "Failed to open %s!\n", filename);
    return -1;
  }
  
  /* Read the proper number of bytes */
  fseeko(mem_file, kinfo->data, SEEK_SET);
  num_read = fread(kernel, sizeof(unsigned char), kinfo->data_sz, mem_file);
  if(ferror(mem_file)) {
    fprintf(stderr, "Failed to read %s at offset %llu\n", filename, kinfo->data);
    return -1;
  } else if(feof(mem_file)) {
    fprintf(stderr, "Hit the end of the file in %s at offset %llu\n", filename, kinfo->data);
    return -1;
  }
  printf("Successfully read %llu bytes\n", num_read);
  #endif
  
  struct iovec remote[1];
  struct iovec local[1];
  kernel = calloc(kinfo->data_sz, sizeof(unsigned char));
  
  local[0].iov_base = kernel;
  local[0].iov_len = kinfo->data_sz;
  remote[0].iov_base = (void *) kinfo->data;
  remote[0].iov_len = kinfo->data_sz;
  process_vm_readv(kinfo->pid, local, 1, remote, 1, 0);
  
  /* Print the data that we read */
  for(i = 0; i < kinfo->data_sz; i++) {
    printf("0x%2x\n", kernel[i]);
  }
  printf("\n");
  
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

int init_bpf_prog() {
  int err;
  struct bpf_object_open_opts opts = {0};

  opts.sz = sizeof(struct bpf_object_open_opts);
  #if 0
  if(pw_opts.btf_custom_path) {
    opts.btf_custom_path = pw_opts.btf_custom_path;
  }
  #endif

  bpf_info.obj = kernel_writes_bpf__open_opts(&opts);
  if(!bpf_info.obj) {
    fprintf(stderr, "ERROR: Failed to get BPF object.\n");
    fprintf(stderr, "       Most likely, one of two things are true:\n");
    fprintf(stderr, "       1. You're not root.\n");
    fprintf(stderr, "       2. You don't have a kernel that supports BTF type information.\n");
    return -1;
  }
  err = kernel_writes_bpf__load(bpf_info.obj);
  if(err) {
    fprintf(stderr, "Failed to load BPF object!\n");
    return -1;
  }

  bpf_info.pwrite_prog = (struct bpf_program *) bpf_info.obj->progs.pwrite_kprobe;
  bpf_info.mmap_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_kprobe;
  bpf_info.mmap_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_kretprobe;
  bpf_info.do_execbuffer_prog = (struct bpf_program *) bpf_info.obj->progs.do_execbuffer_kprobe;
  
  bpf_info.rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.rb), handle_sample, NULL, NULL);
  if(!(bpf_info.rb)) {
    fprintf(stderr, "Failed to create a new ring buffer. You're most likely not root.\n");
    return -1;
  }
  
  err = attach_kprobe("i915_gem_pwrite_ioctl", bpf_info.pwrite_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  err = attach_kprobe("i915_gem_mmap_ioctl", bpf_info.mmap_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  err = attach_kprobe("i915_gem_do_execbuffer", bpf_info.do_execbuffer_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  err = attach_kprobe("i915_gem_mmap_ioctl", bpf_info.mmap_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  return 0;
}
