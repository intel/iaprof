/*
Copyright 2025 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/types.h>
#include <pthread.h>

#include "collectors/eustall/eustall_collector.h"
#include "collectors/bpf/bpf/main.h"

#include "utils/hash_table.h"
#include "utils/tree.h"

typedef struct offset_profile offset_profile_struct;
use_hash_table(uint64_t, offset_profile_struct);

void clear_interval_profiles();

struct kv_t;

enum shader_type {
        SHADER_TYPE_UNKNOWN = 0,
        SHADER_TYPE_SHADER,
        SHADER_TYPE_SYSTEM_ROUTINE,
        SHADER_TYPE_DEBUG_AREA,
};

#define SHADER_ADDRESS_NBITS (32ull)
#define SHADER_ADDRESS_MASK ((1ull << SHADER_ADDRESS_NBITS) - 1ull)

struct shader {
        pthread_mutex_t lock;

        uint64_t gpu_addr;
        uint64_t size;

        enum shader_type type;

        uint32_t pid;
        uint64_t proc_name_id;
        uint64_t ustack_id;
        uint64_t kstack_id;
        uint64_t symbol_id;
        uint64_t filename_id;
        int linenum;

        unsigned char *binary;

        /* Set if EU stalls are associated with this shader */
        struct kv_t *kv;

        /* The EU stalls. Key is the offset into the binary,
           value is a pointer to the struct of EU stall counts */
        hash_table(uint64_t, offset_profile_struct) stall_counts;
};

typedef struct shader shader_struct;

use_tree(uint64_t, shader_struct);

extern tree(uint64_t, shader_struct) shaders;
extern pthread_rwlock_t shaders_lock;

void init_profiles();
struct shader *acquire_or_create_shader(uint64_t gpu_addr);
struct shader *acquire_shader(uint64_t gpu_addr);
struct shader *acquire_containing_shader(uint64_t gpu_addr);
void release_shader(struct shader *shader);
void free_profiles();

#define FOR_SHADER(shader_ptr, ...)               \
do {                                              \
        tree_it(uint64_t, shader_struct) _it;     \
        pthread_rwlock_rdlock(&shaders_lock);     \
        tree_traverse(shaders, _it) {             \
                (shader_ptr) = &tree_it_val(_it); \
                __VA_ARGS__                       \
        }                                         \
        pthread_rwlock_unlock(&shaders_lock);     \
} while (0)
