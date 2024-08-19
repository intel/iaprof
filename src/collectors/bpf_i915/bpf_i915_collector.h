#pragma once

/***************************************
* bpf_i915
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

#include <sys/types.h>
#include <bpf/libbpf.h>

#include "bpf/main.h"
#include "gpu_parsers/shader_decoder.h"

/* Global IBA, or Instruction Base Address, which is found by
 * parsing batchbuffer commands. */
extern uint64_t iba;

/***************************************
* BPF Handlers
**********************
* These functions each handle a different struct
* which the BPF programs' ringbuffer can contain.
***************************************/

/* int handle_mapping(void *data_arg); */
int handle_binary(unsigned char **dst, unsigned char *src, uint64_t *dst_sz,
                  uint64_t src_sz);
int handle_unmap(void *data_arg);
int handle_userptr(void *data_arg);
int handle_vm_bind(void *data_arg);
int handle_vm_create(void *data_arg);
int handle_vm_unbind(void *data_arg);
int handle_execbuf_start(void *data_arg);
int handle_execbuf_end(void *data_arg);
static int handle_sample(void *ctx, void *data_arg, size_t data_sz);

/***************************************
* BPF Setup
**********************
* These functions set up the kprobes and tracepoints
* in the BPF program.
***************************************/

int attach_kprobe(const char *func, struct bpf_program *prog, int ret);
int attach_tracepoint(const char *category, const char *func,
                      struct bpf_program *prog);
int deinit_bpf_i915();
int init_bpf_i915();

/* Stores information about the BPF programs, ringbuffer, etc. */
struct bpf_info_t {
        struct main_bpf *obj;
        struct ring_buffer *rb;
        int epoll_fd, rb_fd;
        struct bpf_map **map;

        /* Links to the BPF programs */
        struct bpf_link **links;
        size_t num_links;

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

        /* i915_gem_vm_create_ioctl */
        struct bpf_program *vm_create_ioctl_prog;
        struct bpf_program *vm_create_ioctl_ret_prog;

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

        /* requests */
        struct bpf_program *request_submit_prog;
        struct bpf_program *request_retire_prog;
        struct bpf_program *request_in_prog;
        struct bpf_program *request_out_prog;
/*         struct bpf_program *request_retire_kprobe_prog; */

        /* vm_close */
        /*   struct bpf_program *vm_close_prog; */
};
extern struct bpf_info_t bpf_info;

/***************************************
* BPF Types
**********************
* These types are passed to userspace via
* the ringbuffer. The only way to identify them
* on the userspace side is by their size, so make sure
* their size is unique.
***************************************/

void check_bpf_type_sizes();
