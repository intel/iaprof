#pragma once

/***************************************
* bpf
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
extern _Atomic uint64_t iba;

/***************************************
* BPF Handlers
**********************
* These functions each handle a different struct
* which the BPF programs' ringbuffer can contain.
***************************************/

/***************************************
* BPF Setup
**********************
* These functions set up the kprobes and tracepoints
* in the BPF program.
***************************************/

int deinit_bpf();
int init_bpf();

/* Stores information about the BPF programs, ringbuffer, etc. */
struct bpf_info_t {
        struct main_bpf *obj;
        struct ring_buffer *rb;
        int epoll_fd, rb_fd, stackmap_fd;
        struct bpf_map **map;

        /* Links to the BPF programs */
        struct bpf_link **links;
        size_t num_links;


        int *dropped_event;
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
