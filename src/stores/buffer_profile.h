#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/types.h>
#include <pthread.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "gpu_parsers/shader_decoder.h"

#include "utils/hash_table.h"
#include "utils/tree.h"

use_hash_table(uint64_t, uint64_t);

void clear_interval_profiles();
void clear_unbound_buffers();
void print_buffer_profiles();

/* Stores information about a single buffer. We overwrite and accumulate
   these interval after interval. */
struct buffer_profile {
        char name[TASK_COMM_LEN];
        uint64_t time;
        uint32_t cpu;
        uint32_t tid;
        uint32_t ctx_id;

        uint64_t file;
        uint32_t handle;

        /* Binding info */
        uint32_t pid;
        uint32_t vm_id;
        uint64_t gpu_addr;
        uint64_t bind_size;
        int      unbound;

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

        /* The EU stalls. Key is the offset into the binary,
           value is a pointer to the struct of EU stall counts */
        hash_table(uint64_t, uint64_t) stall_counts;
};

typedef struct buffer_profile buffer_profile_struct;

use_tree(uint64_t, buffer_profile_struct);


void init_profiles();
struct buffer_profile *get_buffer_profile(uint32_t vm_id, uint64_t gpu_addr);
struct buffer_profile *get_or_create_buffer_profile(uint32_t vm_id, uint64_t gpu_addr);
struct buffer_profile *get_containing_buffer_profile(uint32_t vm_id, uint64_t gpu_addr);
void delete_buffer_profile(uint32_t vm_id, uint64_t gpu_addr);
void free_profiles();

struct vm_profile *create_vm_profile(uint32_t vm_id);
struct vm_profile *get_vm_profile(uint32_t vm_id);
struct vm_profile *get_or_create_vm_profile(uint32_t vm_id);
void request_submit(uint32_t vm_id, uint32_t seqno, uint32_t gem_ctx, uint16_t class, uint16_t instance);
void request_retire(uint32_t seqno, uint32_t gem_ctx);
void clear_retired_requests();
void mark_vms_active();

struct request_profile_list {
        struct request_profile_list *next;
        uint32_t seqno;
        uint32_t gem_ctx;
        char retired;
        uint16_t class, instance;
};

struct vm_profile {
        char active;
        tree(uint64_t, buffer_profile_struct) buffer_profiles;
        uint32_t num_requests;
        struct request_profile_list *request_list;
};


typedef struct vm_profile *vm_profile_ptr;
use_hash_table(uint64_t, vm_profile_ptr);

extern hash_table(uint64_t, vm_profile_ptr) vm_profiles;


#define FOR_BUFFER_PROFILE(gem, ...)                           \
do {                                                           \
        uint32_t _vm_id;                                       \
        struct vm_profile **_vmp;                              \
        tree_it(uint64_t, buffer_profile_struct) _it;          \
        hash_table_traverse(vm_profiles, _vm_id, _vmp) {       \
                (void)_vm_id;                                  \
                (void)_vmp;                                    \
                tree_traverse((*_vmp)->buffer_profiles, _it) { \
                        gem = &tree_it_val(_it);               \
                        __VA_ARGS__                            \
                }                                              \
        }                                                      \
} while (0)


