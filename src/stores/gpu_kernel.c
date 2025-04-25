#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <stdbool.h>

#include "iaprof.h"
#include "printers/debug/debug_printer.h"
#include "gpu_kernel.h"

tree(uint64_t, shader_struct) shaders;
pthread_rwlock_t              shaders_lock = PTHREAD_RWLOCK_INITIALIZER;

void init_profiles() {
        shaders = tree_make(uint64_t, shader_struct);
}

static uint64_t uint64_t_hash(uint64_t i) { return i; }


struct shader *acquire_shader(uint64_t gpu_addr) {
        tree_it(uint64_t, shader_struct)  it;
        struct shader                    *shader;

        pthread_rwlock_rdlock(&shaders_lock);

        it = tree_lookup(shaders, gpu_addr);
        if (!tree_it_good(it)) {
                pthread_rwlock_unlock(&shaders_lock);
                return NULL;
        }

        shader = &tree_it_val(it);

        pthread_mutex_lock(&shader->lock);

        return shader;
}

struct shader *acquire_containing_shader(uint64_t gpu_addr) {
        tree_it(uint64_t, shader_struct)  it;
        struct shader                    *shader;

        pthread_rwlock_rdlock(&shaders_lock);

        it = tree_gtr(shaders, gpu_addr);
        tree_it_prev(it);
        if (!tree_it_good(it)) { goto err; }

        shader = &tree_it_val(it);

        if ((shader->size != 0) && (gpu_addr >= (shader->gpu_addr + shader->size))) {
                /* XXX: WARNING: We do NOT check the size of all shaders, since we have no
                   way of knowing it in some cases. This can lead to mis-association 
                   if we don't know the addresses of ALL shaders. */
                goto err;
        }
        if ((gpu_addr < shader->gpu_addr)) {

                goto err;
        }

        pthread_mutex_lock(&shader->lock);

        return shader;

err:
        pthread_rwlock_unlock(&shaders_lock);
        return NULL;
}

void release_shader(struct shader *shader) {
        if (shader == NULL) { return; }

        pthread_mutex_unlock(&shader->lock);

        pthread_rwlock_unlock(&shaders_lock);
}

struct shader *acquire_or_create_shader(uint64_t gpu_addr) {
        tree_it(uint64_t, shader_struct) it;
        struct shader                    new_shader;

        pthread_rwlock_rdlock(&shaders_lock);

        it = tree_lookup(shaders, gpu_addr);
        if (tree_it_good(it)) {
                return &tree_it_val(it);
        }

        pthread_rwlock_unlock(&shaders_lock);
        pthread_rwlock_wrlock(&shaders_lock);

        memset(&new_shader, 0, sizeof(new_shader));
        pthread_mutex_init(&new_shader.lock, NULL);
        new_shader.gpu_addr = gpu_addr;

        new_shader.stall_counts = hash_table_make(uint64_t, offset_profile_struct, uint64_t_hash);

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

        shader->stall_counts = hash_table_make(uint64_t, offset_profile_struct, uint64_t_hash);
}

static void free_shader(struct shader *shader) {
        clear_stalls(shader);
        hash_table_free(shader->stall_counts);
        shader->stall_counts = NULL;

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
