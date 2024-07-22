#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/types.h>
#include <pthread.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "gpu_parsers/shader_decoder.h"

/***************************************
* Buffer Profile Array
**********************
* These functions simply maintain a global array
* of type `struct buffer_profile`.
***************************************/

int get_buffer_profile(uint64_t file, uint32_t handle);
int get_buffer_profile_by_binding(uint64_t file, uint32_t handle);
int get_buffer_profile_by_gpu_addr(uint64_t gpu_addr);
uint64_t grow_buffer_profiles();

/* Stores information about a single buffer */
struct buffer_profile {
	struct vm_bind_info vm_bind_info;
	struct mapping_info mapping_info;
	struct execbuf_start_info exec_info;

        /* i915 differentiates a buffer by the file pointer (or ctx_id)
           and its integer handle, so we will too. */
        uint32_t handle, vm_id;
        uint64_t file;
        char mapped;

	/* A copy of the buffer bytes itself */
	uint64_t buff_sz;
	unsigned char *buff;
        char parsed;

	/* The IBA (Instruction Base Address) associated with this buffer */
	uint64_t iba;

	/* The stack where this buffer was execbuffer'd */
	char *execbuf_stack_str;

	/* Set if EU stalls are associated with this buffer */
	unsigned char has_stalls;
	struct shader_profile shader_profile;
        struct kv_t *kv;
};

void update_buffer_copy(struct buffer_profile *gem);

/* Global array, including a lock, size, and "used" counter,
   of buffer profiles. */
extern pthread_rwlock_t buffer_profile_lock;
extern struct buffer_profile *buffer_profile_arr;
extern size_t buffer_profile_size, buffer_profile_used;
