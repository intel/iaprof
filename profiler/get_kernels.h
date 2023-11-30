#pragma once

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#include "bb_parser.h"

void print_map(pid_t pid) {
  FILE *mem_file;
  char filename[256];

  /* Open the memory map */
  sprintf(filename, "/proc/%ld/maps", (long) pid);
  mem_file = fopen(filename, "r");
  if(!mem_file) {
    fprintf(stderr, "Failed to open %s!\n", filename);
    return;
  }

  char line[256];
  while(fgets(line, sizeof(line), mem_file)) {
    printf("%s", line);
  }
  fclose(mem_file);
  fflush(stdout);
}

unsigned char *copy_buffer(__u32 pid, __u64 ptr, __u64 size) {
  size_t num_read;
  FILE *mem_file;
  char filename[256];
  int retval;
  unsigned char *data;
  
  /* Open the memory map */
  sprintf(filename, "/proc/%ld/mem", pid);
  mem_file = fopen(filename, "r");
  if(!mem_file) {
    fprintf(stderr, "Failed to open %s!\n", filename);
    return NULL;
  }
  
  /* Read the proper number of bytes */
  retval = fseeko(mem_file, ptr, SEEK_SET);
  if(retval != 0) {
    fprintf(stderr, "Failed to seek in the memory map! Error: %s\n", strerror(errno));
    exit(1);
  }
  data = calloc(sizeof(unsigned char), size);
  num_read = fread(data, sizeof(unsigned char), size, mem_file);
  if(ferror(mem_file)) {
    fprintf(stderr, "Failed to read %s at offset 0x%llx: %s\n", filename, ptr, strerror(errno));
    return NULL;
  } else if(feof(mem_file)) {
    fprintf(stderr, "Hit the end of the file in %s at offset 0x%llx\n", filename, ptr);
    return NULL;
  }
  fclose(mem_file);
  
  return data;
}

void dump_kernel(unsigned char *kernel, __u64 size, __u32 id) {
  char filename[256];
  FILE *tmpfile;
  
  sprintf(filename, "/tmp/kernel_%u.krn9", id);
  if(fopen(filename, "r")) {
    sprintf(filename, "/tmp/kernel_%u_2.krn9", id);
    if(fopen(filename, "r")) {
      fprintf(stderr, "Too many duplicate handles (%u) to dump!\n", id);
      return;
    }
  }
  
  tmpfile = fopen(filename, "w");
  if(!tmpfile) {
    fprintf(stderr, "WARNING: Failed to open %s\n", filename);
    return;
  }
  fwrite(kernel, sizeof(unsigned char), size, tmpfile);
  fclose(tmpfile);
}

struct bpf_info_t {
  struct kernel_writes_bpf *obj;
  struct ring_buffer *rb;
  struct bpf_map **map;
  
  /* Links to the BPF programs */
  struct bpf_link **links;
  size_t num_links;
  
  /* i915_gem_pwrite_ioctl */
  struct bpf_program *pwrite_ioctl_prog;
  
  /* i915_gem_mmap_ioctl */
  struct bpf_program *mmap_ioctl_prog;
  struct bpf_program *mmap_ioctl_ret_prog;
  
  /* i915_gem_mmap_offset_ioctl and friends */
  struct bpf_program *mmap_offset_ioctl_prog;
  struct bpf_program *mmap_offset_ioctl_ret_prog;
  struct bpf_program *mmap_prog;
  struct bpf_program *mmap_ret_prog;
  
  /* i915_gem_userptr_ioctl */
  struct bpf_program *userptr_ioctl_prog;
  struct bpf_program *userptr_ioctl_ret_prog;
  
  /* i915_gem_do_execbuffer */
  struct bpf_program *do_execbuffer_prog;
};
static struct bpf_info_t bpf_info = {};

static int handle_sample(void *ctx, void *data_arg, size_t data_sz) {
  struct kernel_info *kinfo;
  unsigned char *data;
  struct bb_parser *parser;
  
  kinfo = (struct kernel_info *) data_arg;
  
  printf("Got a sample: addr=%llx size=%llu pid=%u comm=%s handle=%u offset=%llx\n", kinfo->data, kinfo->data_sz, kinfo->pid, kinfo->name, kinfo->handle, kinfo->offset);
  
  if(strcmp(kinfo->name, "level_zero_test") == 0) {
    data = copy_buffer(kinfo->pid, kinfo->data, kinfo->data_sz);
    dump_kernel(data, kinfo->data_sz, kinfo->handle);
  }
  
  /* We don't want to copy/parse anything but batch buffers */
  if(!(kinfo->is_bb) ||
     !(kinfo->data) ||
     !(kinfo->data_sz) ||
     !(kinfo->pid)) {
    return 0;
  }
  
  data = copy_buffer(kinfo->pid, kinfo->data, kinfo->data_sz);
  parser = bb_parser_init();
  bb_parser_parse(parser, data, kinfo->data_sz);
  printf("Instruction Base Address:   %lx\n", parser->iba);
  printf("System Instruction Pointer: %lx\n", parser->sip);
  fflush(stdout);
  
  /* Once the parser finds a kernel pointer, here we should immediately
     do a lookup on pointers we've seen before, and if we find it, 
     call dump_kernel. */
     
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

  bpf_info.pwrite_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.pwrite_kprobe;
  
  bpf_info.mmap_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_ioctl_kprobe;
  bpf_info.mmap_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_ioctl_kretprobe;
  
  bpf_info.mmap_offset_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_offset_ioctl_kprobe;
  bpf_info.mmap_offset_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_offset_ioctl_kretprobe;
  bpf_info.mmap_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_kprobe;
  bpf_info.mmap_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_kretprobe;
  
  bpf_info.userptr_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.userptr_ioctl_kprobe;
  bpf_info.userptr_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.userptr_ioctl_kretprobe;
  
  bpf_info.do_execbuffer_prog = (struct bpf_program *) bpf_info.obj->progs.do_execbuffer_kprobe;
  
  bpf_info.rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.rb), handle_sample, NULL, NULL);
  if(!(bpf_info.rb)) {
    fprintf(stderr, "Failed to create a new ring buffer. You're most likely not root.\n");
    return -1;
  }
  
  /* i915_gem_pwrite_ioctl */
  err = attach_kprobe("i915_gem_pwrite_ioctl", bpf_info.pwrite_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
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
  err = attach_kprobe("i915_gem_userptr_ioctl", bpf_info.userptr_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_userptr_ioctl", bpf_info.userptr_ioctl_ret_prog, 1);
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
  
  return 0;
}
