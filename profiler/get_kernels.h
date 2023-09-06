#pragma once

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

struct bpf_info_t {
  struct kernel_writes_bpf *obj;
  struct ring_buffer *rb;
  struct bpf_program *prog;
  struct bpf_map **map;
};
static struct bpf_info_t bpf_info = {};

static int handle_sample(void *ctx, void *data, size_t data_sz) {
  
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

  bpf_info.prog = (struct bpf_program *) bpf_info.obj->progs.pwrite_kprobe;
  
  bpf_info.rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.rb), handle_sample, NULL, NULL);
  if(!(bpf_info.rb)) {
    fprintf(stderr, "Failed to create a new ring buffer. You're most likely not root.\n");
    return -1;
  }
}
