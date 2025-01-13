#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/types.h>
#include <pthread.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "gpu_parsers/shader_decoder.h"
#include "collectors/eustall/eustall_collector.h"

#include "utils/hash_table.h"
#include "utils/tree.h"

typedef struct offset_profile offset_profile_struct;
use_hash_table(uint64_t, offset_profile_struct);

void clear_interval_profiles();
void clear_unbound_buffers();
void print_buffer_profiles();

enum buffer_type {
        BUFFER_TYPE_UNKNOWN = 0,
        BUFFER_TYPE_BATCHBUFFER,
        BUFFER_TYPE_SHADER,
        BUFFER_TYPE_SYSTEM_ROUTINE,
        BUFFER_TYPE_DEBUG_AREA,
};

struct buffer_binding {
        enum buffer_type type;

        uint64_t file;
        uint32_t handle;

        char name[TASK_COMM_LEN];
        uint64_t time;
        uint32_t cpu;
        uint32_t pid;
        uint32_t tid;
        uint32_t ctx_id;

        /* Binding info */
        uint32_t vm_id;
        uint64_t gpu_addr;
        uint64_t bind_size;
        uint32_t vm_bind_order;
        int      unbound;

        /* The stack where this buffer was execbuffer'd */
        const char *execbuf_ustack_str;
        const char *execbuf_kstack_str;

        /* Set if EU stalls are associated with this buffer */
        struct kv_t *kv;

        /* The EU stalls. Key is the offset into the binary,
           value is a pointer to the struct of EU stall counts */
        hash_table(uint64_t, offset_profile_struct) stall_counts;
};

typedef struct buffer_binding buffer_binding_struct;

use_tree(uint64_t, buffer_binding_struct);


struct vm_profile {
        uint64_t file;
        uint32_t vm_id;
        uint32_t vm_order;
        uint64_t debugger_vm_id;
        pthread_mutex_t lock;
        _Atomic pthread_t lock_holder;
        char active;
        tree(uint64_t, buffer_binding_struct) bindings;
};

struct file_vm_pair {
        uint64_t file;
        uint32_t vm_id;
};

typedef struct file_vm_pair file_vm_pair_struct;
typedef struct vm_profile *vm_profile_ptr;

int file_vm_pair_cmp(struct file_vm_pair a, struct file_vm_pair b);

use_tree_c(file_vm_pair_struct, vm_profile_ptr, file_vm_pair_cmp);

extern tree(file_vm_pair_struct, vm_profile_ptr) vm_profiles;
extern pthread_rwlock_t vm_profiles_lock;

void init_profiles();
struct buffer_binding *get_binding(struct vm_profile *vm, uint64_t gpu_addr);
struct buffer_binding *get_ordered_binding(uint32_t vm_bind_order);
struct buffer_binding *get_or_create_binding(struct vm_profile *vm, uint64_t gpu_addr);
struct buffer_binding *get_containing_binding(struct vm_profile *vm, uint64_t gpu_addr);
void delete_binding(struct vm_profile *vm, uint64_t gpu_addr);
void free_profiles();

void create_vm_profile(uint64_t file, uint32_t vm_id);

/* This function does not lock the vm_profile! */
struct vm_profile *get_vm_profile(uint64_t file, uint32_t vm_id);

void lock_vm_profile(struct vm_profile *vm);
void unlock_vm_profile(struct vm_profile *vm);

struct vm_profile *acquire_vm_profile(uint64_t file, uint32_t vm_id);
struct vm_profile *acquire_ordered_vm_profile(uint64_t file, uint32_t vm_order);
void release_vm_profile(struct vm_profile *vm);


#define FOR_VM(vm, ...)                                             \
do {                                                                \
        tree_it(file_vm_pair_struct, vm_profile_ptr) _it;           \
        pthread_rwlock_rdlock(&vm_profiles_lock);                   \
        tree_traverse(vm_profiles, _it) {                           \
                (vm) = tree_it_val(_it);                            \
                lock_vm_profile((vm));                              \
                __VA_ARGS__                                         \
                unlock_vm_profile((vm));                            \
        }                                                           \
        pthread_rwlock_unlock(&vm_profiles_lock);                   \
} while (0)

#define FOR_VM_CLEANUP()                                            \
do {                                                                \
        unlock_vm_profile(*_vmp);                                   \
        pthread_rwlock_unlock(&vm_profiles_lock);                   \
} while (0)

#define FOR_BINDING(vm, bind, ...)                                  \
do {                                                                \
        tree_it(file_vm_pair_struct, vm_profile_ptr) _vit;          \
        tree_it(uint64_t, buffer_binding_struct)     _bit;          \
        pthread_rwlock_rdlock(&vm_profiles_lock);                   \
        tree_traverse(vm_profiles, _vit) {                          \
                (vm) = tree_it_val(_vit);                           \
                lock_vm_profile((vm));                              \
                tree_traverse((vm)->bindings, _bit) {               \
                        (bind) = &tree_it_val(_bit);                \
                        __VA_ARGS__                                 \
                }                                                   \
                unlock_vm_profile((vm));                            \
        }                                                           \
        pthread_rwlock_unlock(&vm_profiles_lock);                   \
} while (0)

#define FOR_BINDING_CLEANUP()                                       \
do {                                                                \
        unlock_vm_profile(tree_it_val(_vit));                       \
        pthread_rwlock_unlock(&vm_profiles_lock);                   \
} while (0)
