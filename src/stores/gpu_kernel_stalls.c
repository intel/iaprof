#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <stdbool.h>

#include "iaprof.h"
#include "printers/debug/debug_printer.h"
#include "gpu_kernel_stalls.h"

_Atomic uint64_t iba = 0;

tree(uint64_t, shader_struct) shaders;
pthread_rwlock_t              shaders_lock = PTHREAD_RWLOCK_INITIALIZER;

void init_profiles() {
        shaders = tree_make(uint64_t, shader_struct);
}

struct shader *acquire_shader(uint64_t gpu_addr) {
        tree_it(uint64_t, shader_struct) it;

        pthread_rwlock_rdlock(&shaders_lock);

        it = tree_lookup(shaders, gpu_addr);
        if (!tree_it_good(it)) {
                pthread_rwlock_unlock(&shaders_lock);
                return NULL;
        }

        return &tree_it_val(it);
}

struct shader *acquire_containing_shader(uint64_t gpu_addr) {
        tree_it(uint64_t, shader_struct) it;
        struct shader *shader;

        pthread_rwlock_rdlock(&shaders_lock);

        it = tree_gtr(shaders, gpu_addr);
        tree_it_prev(it);
        if (!tree_it_good(it)) { goto err; }

        shader = &tree_it_val(it);

        if ((gpu_addr < shader->gpu_addr)) {
                /* XXX: WARNING: We do NOT check the size of the shader, since we have no
                   way of knowing it. This can lead to mis-association if we don't know
                   the addresses of ALL shaders. */

                goto err;
        }

        return shader;

err:
        pthread_rwlock_unlock(&shaders_lock);
        return NULL;
}

void release_shader(struct shader *shader) {
        if (shader == NULL) { return; }

        pthread_rwlock_unlock(&shaders_lock);
}

struct shader *create_and_acquire_shader(uint64_t gpu_addr) {
        tree_it(uint64_t, shader_struct) it;
        struct shader new_shader;

        pthread_rwlock_wrlock(&shaders_lock);

        memset(&new_shader, 0, sizeof(new_shader));
        new_shader.gpu_addr = gpu_addr;

        tree_insert(shaders, gpu_addr, new_shader);

        pthread_rwlock_unlock(&shaders_lock);
        pthread_rwlock_rdlock(&shaders_lock);

        it = tree_lookup(shaders, gpu_addr);
        assert(tree_it_good(it) && "shader deleted from another thread immediately after creation");

        return &tree_it_val(it);
}

static void clear_stalls(struct shader *shader) {
        if (shader->stall_counts != NULL) {
                hash_table_free(shader->stall_counts);
                shader->stall_counts = NULL;
        }
}

static void free_shader(struct shader *shader) {
        clear_stalls(shader);

        if (shader->kv != NULL) {
            iga_fini(shader->kv);
            shader->kv = NULL;
        }
}

static void free_shaders() {
}

void free_profiles() {
        tree_it(uint64_t, shader_struct) it;

        pthread_rwlock_wrlock(&shaders_lock);

        tree_traverse(shaders, it) {
                free_shader(&tree_it_val(it));
        }

        tree_free(shaders);

        shaders = NULL;

        /* Keep the write lock locked. No one should be touching shaders
         * past this point. */
}


void clear_interval_profiles()
{
        struct shader *shader;

        FOR_SHADER(shader,
                clear_stalls(shader);
        );
}
