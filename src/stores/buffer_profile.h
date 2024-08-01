#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/types.h>
#include <pthread.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "gpu_parsers/shader_decoder.h"

#include "utils/hash_table.h"

/***************************************
* Buffer Profile Array
**********************
* These functions simply maintain a global array
* of type `struct buffer_profile`.
***************************************/

int get_buffer_profile_by_binding(uint32_t vm_id, uint64_t gpu_addr);
int get_buffer_profile_by_mapping(uint64_t file, uint32_t handle);
void free_buffer_profiles();
uint64_t grow_buffer_profiles();
void clear_interval_profiles();
void print_buffer_profiles();

/* Stores information about a single buffer. We overwrite and accumulate
   these interval after interval. */
struct buffer_profile {
        struct vm_bind_info vm_bind_info;
        struct execbuf_start_info exec_info;

        /* Mapping info */
        uint64_t cpu_addr;
        uint32_t handle;
        uint64_t file;
        char mapped;
        
        /* Binding info */
        uint32_t vm_id;

        /* A copy of the buffer bytes itself */
        uint64_t buff_sz;
        unsigned char *buff;
        char parsed;

        /* The IBA (Instruction Base Address) associated with this buffer */
        uint64_t iba;

        /* The stack where this buffer was execbuffer'd */
        char *execbuf_stack_str;

        /* Set if EU stalls are associated with this buffer */
        struct kv_t *kv;
};

/* Global array, including a lock, size, and "used" counter,
   of buffer profiles. */
extern pthread_rwlock_t buffer_profile_lock;
extern struct buffer_profile *buffer_profile_arr;
extern size_t buffer_profile_size, buffer_profile_used;

/***************************************
* Interval Profile Array
**********************
* An array of per-buffer profiles. Get cleared on each interval.
***************************************/

void free_interval_profiles();

use_hash_table(uint64_t, uint64_t);

/* Stores per-interval profiles. */
struct interval_profile {
        unsigned char has_stalls;

        /* The EU stalls. Key is the offset into the binary,
           value is a pointer to the struct of EU stall counts */
        hash_table(uint64_t, uint64_t) counts;
};

extern struct interval_profile *interval_profile_arr;

/***************************************
* VM Profile Array
**********************
* The index into this array is the vm_id. Stores
* requests that are currently active for this VM.
***************************************/

#define MAX_OPEN_REQUESTS 1024

struct vm_profile *get_vm_profile(uint32_t vm_id);
void request_submit(uint32_t vm_id, uint32_t seqno, uint32_t gem_ctx);
void request_retire(uint32_t seqno, uint32_t gem_ctx);
void clear_retired_requests();
void mark_vms_active();

struct request_profile {
        uint32_t seqno;
        uint32_t gem_ctx;
        char retired;
};

struct vm_profile {
        char active;
        uint32_t num_requests;
        struct request_profile requests[MAX_OPEN_REQUESTS];
};

extern struct vm_profile *vm_profile_arr;
extern uint32_t num_vms;
