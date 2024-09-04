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

enum buffer_type {
        BUFFER_TYPE_UNKNOWN = 0,
        BUFFER_TYPE_BATCHBUFFER,
        BUFFER_TYPE_SHADER,
        BUFFER_TYPE_DEBUG_AREA,
};

/* Stores information about a single buffer. We overwrite and accumulate
   these interval after interval. */
struct buffer_object {
        uint64_t file;
        uint32_t handle;

        uint64_t buff_sz;
        unsigned char *buff;

        pthread_mutex_t lock;
        _Atomic pthread_t lock_holder;
};

typedef struct buffer_object buffer_object_struct;
typedef struct file_handle_pair file_handle_pair_struct;

static inline int file_handle_pair_cmp(file_handle_pair_struct a, file_handle_pair_struct b) {
        if (a.file < b.file) {
                return -1;
        }
        if (a.file > b.file) {
                return 1;
        }
        if (a.handle < b.handle) {
                return -1;
        }
        if (a.handle > b.handle) {
                return 1;
        }

        return 0;
}


use_tree_c(file_handle_pair_struct, buffer_object_struct, file_handle_pair_cmp);

extern tree(file_handle_pair_struct, buffer_object_struct) buffer_objects;
extern pthread_rwlock_t buffer_objects_lock;

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
        char *execbuf_stack_str;

        /* Set if EU stalls are associated with this buffer */
        struct kv_t *kv;

        /* The EU stalls. Key is the offset into the binary,
           value is a pointer to the struct of EU stall counts */
        hash_table(uint64_t, uint64_t) stall_counts;
};

typedef struct buffer_binding buffer_binding_struct;

use_tree(uint64_t, buffer_binding_struct);


struct vm_profile {
        uint32_t vm_id;
        uint64_t debugger_vm_id;
        uint32_t vm_order;
        pthread_mutex_t lock;
        _Atomic pthread_t lock_holder;
        char active;
        tree(uint64_t, buffer_binding_struct) bindings;
};


typedef struct vm_profile *vm_profile_ptr;
use_hash_table(uint64_t, vm_profile_ptr);

extern hash_table(uint64_t, vm_profile_ptr) vm_profiles;
extern pthread_rwlock_t vm_profiles_lock;

void init_profiles();
struct buffer_binding *get_binding(struct vm_profile *vm, uint64_t gpu_addr);
struct buffer_binding *get_ordered_binding(uint32_t vm_bind_order);
struct buffer_binding *get_or_create_binding(struct vm_profile *vm, uint64_t gpu_addr);
struct buffer_binding *get_containing_binding(struct vm_profile *vm, uint64_t gpu_addr);
void delete_binding(struct vm_profile *vm, uint64_t gpu_addr);
void free_profiles();

void create_vm_profile(uint32_t vm_id);

/* This function does not lock the vm_profile! */
struct vm_profile *get_vm_profile(uint32_t vm_id);

void lock_vm_profile(struct vm_profile *vm);
void unlock_vm_profile(struct vm_profile *vm);

struct vm_profile *acquire_vm_profile(uint32_t vm_id);
struct vm_profile *acquire_ordered_vm_profile(uint32_t vm_order);
void release_vm_profile(struct vm_profile *vm);


void lock_buffer(struct buffer_object *bo);
void unlock_buffer(struct buffer_object *bo);
struct buffer_object *create_buffer(uint64_t file, uint32_t handle);
struct buffer_object *acquire_buffer(uint64_t file, uint32_t handle);
struct buffer_object *acquire_or_create_buffer(uint64_t file, uint32_t handle);
void release_buffer(struct buffer_object *bo);




#define FOR_VM(vm, ...)                                             \
do {                                                                \
        uint32_t _vm_id;                                            \
        struct vm_profile **_vmp;                                   \
        pthread_rwlock_rdlock(&vm_profiles_lock);                   \
        hash_table_traverse(vm_profiles, _vm_id, _vmp) {            \
                (void)_vmp;                                         \
                (vm) = get_vm_profile(_vm_id);                      \
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
        uint32_t _vm_id;                                            \
        struct vm_profile **_vmp;                                   \
        tree_it(uint64_t, buffer_binding_struct) _it;               \
        pthread_rwlock_rdlock(&vm_profiles_lock);                   \
        hash_table_traverse(vm_profiles, _vm_id, _vmp) {            \
                (void)_vmp;                                         \
                (vm) = get_vm_profile(_vm_id);                      \
                lock_vm_profile((vm));                              \
                tree_traverse((*_vmp)->bindings, _it) {             \
                        (bind) = &tree_it_val(_it);                 \
                        __VA_ARGS__                                 \
                }                                                   \
                unlock_vm_profile((vm));                            \
        }                                                           \
        pthread_rwlock_unlock(&vm_profiles_lock);                   \
} while (0)

#define FOR_BINDING_CLEANUP()                                       \
do {                                                                \
        unlock_vm_profile(*_vmp);                                   \
        pthread_rwlock_unlock(&vm_profiles_lock);                   \
} while (0)

#define FOR_BUFFER(bo, ...)                                         \
do {                                                                \
        tree_it(file_handle_pair_struct, buffer_object_struct) _it; \
        pthread_rwlock_rdlock(&buffer_objects_lock);                \
        tree_traverse(buffer_objects, _it) {                        \
                (bo) = &tree_it_val(_it);                           \
                __VA_ARGS__                                         \
        }                                                           \
        pthread_rwlock_unlock(&buffer_objects_lock);                \
} while (0)

#define FOR_BUFFER_CLEANUP()                                        \
do {                                                                \
        pthread_rwlock_unlock(&buffer_objects_lock);                \
} while (0)

