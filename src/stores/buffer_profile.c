#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

#include "iaprof.h"
#include "buffer_profile.h"

static uint64_t vm_id_hash(uint64_t vm_id) { return vm_id; }

hash_table(uint64_t, vm_profile_ptr) vm_profiles;
pthread_rwlock_t vm_profiles_lock = PTHREAD_RWLOCK_INITIALIZER;

void init_profiles() {
        vm_profiles = hash_table_make(uint64_t, vm_profile_ptr, vm_id_hash);
}

struct buffer_profile *get_buffer_profile(struct vm_profile *vm, uint64_t gpu_addr) {
        tree_it(uint64_t, buffer_profile_struct) it;

        assert(vm->lock_holder == pthread_self()
                && "get_buffer_profile called, but vm->lock not held by this thread!");

        it = tree_lookup(vm->buffer_profiles, gpu_addr);
        if (tree_it_good(it)) {
                return &tree_it_val(it);
        }

        return NULL;
}

struct buffer_profile *get_or_create_buffer_profile(struct vm_profile *vm, uint64_t gpu_addr) {
        tree_it(uint64_t, buffer_profile_struct) it;
        struct buffer_profile new_profile;

        assert(vm->lock_holder == pthread_self()
                && "get_or_create_buffer_profile called, but vm->lock not held by this thread!");

        it = tree_lookup(vm->buffer_profiles, gpu_addr);
        if (tree_it_good(it)) {
                goto found;
        }

        memset(&new_profile, 0, sizeof(new_profile));
        new_profile.vm_id = vm->vm_id;
        new_profile.gpu_addr = gpu_addr;
        it = tree_insert(vm->buffer_profiles, gpu_addr, new_profile);

found:;
        return &tree_it_val(it);
}

struct buffer_profile *get_containing_buffer_profile(struct vm_profile *vm, uint64_t gpu_addr) {
        tree_it(uint64_t, buffer_profile_struct) it;
        struct buffer_profile *gem;

        assert(vm->lock_holder == pthread_self()
                && "get_containing_buffer_profile called, but vm->lock not held by this thread!");

        it = tree_gtr(vm->buffer_profiles, gpu_addr);
        tree_it_prev(it);

        if (!tree_it_good(it)) {
                return NULL;
        }

        gem = &tree_it_val(it);

        if (gpu_addr <  gem->gpu_addr
        ||  gpu_addr >= gem->gpu_addr + gem->bind_size) {

                return NULL;
        }

        return gem;
}

static void clear_stalls(struct buffer_profile *gem) {
        uint64_t offset, *tmp;
        struct offset_profile **found;

        if (gem->stall_counts != NULL) {
                hash_table_traverse(gem->stall_counts,
                                        offset, tmp)
                {
                        (void)offset;
                        found = (struct offset_profile **)tmp;
                        free(*found);
                }
                hash_table_free(gem->stall_counts);
                gem->stall_counts = NULL;
        }
}

void free_buffer_profile(struct buffer_profile *gem) {
        clear_stalls(gem);
        if (gem->buff != NULL) {
                free(gem->buff);
                gem->buff = NULL;
        }

        if (gem->execbuf_stack_str != NULL) {
            free(gem->execbuf_stack_str);
            gem->execbuf_stack_str = NULL;
        }

        if (gem->kv != NULL) {
            iga_fini(gem->kv);
            gem->kv = NULL;
        }
}

void free_buffer_profiles(tree(uint64_t, buffer_profile_struct) buffer_profiles) {
        tree_it(uint64_t, buffer_profile_struct) it;

        tree_traverse(buffer_profiles, it) {
                free_buffer_profile(&tree_it_val(it));
        }

        tree_free(buffer_profiles);
}

void free_profiles() {
        uint64_t                      vm_id;
        struct vm_profile           **vmp;
        struct vm_profile            *vm;

        pthread_rwlock_wrlock(&vm_profiles_lock);

        hash_table_traverse(vm_profiles, vm_id, vmp) {
                (void)vm_id;

                vm = *vmp;

                free_buffer_profiles(vm->buffer_profiles);

                free(vm);
        }

        hash_table_free(vm_profiles);

        /* Keep the write lock locked. No one should be touching vm_profiles
         * past this point. */
}

void delete_buffer_profile(struct vm_profile *vm, uint64_t gpu_addr) {
        tree_it(uint64_t, buffer_profile_struct) it;

        assert(vm->lock_holder == pthread_self()
                && "delete_buffer_profile called, but vm->lock not held by this thread!");

        it = tree_lookup(vm->buffer_profiles, gpu_addr);
        if (!tree_it_good(it)) {
                return;
        }

        free_buffer_profile(&tree_it_val(it));
        tree_delete(vm->buffer_profiles, gpu_addr);
}

_Atomic uint64_t iba = 0;

void print_buffer_profiles()
{
        struct vm_profile *vm;
        struct buffer_profile *gem;

        if (!debug)
                return;

        printf( "==== BUFFER_PROFILE_ARR =====\n");

        FOR_BUFFER_PROFILE(vm, gem, {
                printf(
                        "vm_id=%u gpu_addr=0x%lx buff_sz=%zu\n",
                        gem->vm_id, gem->gpu_addr, gem->buff_sz);
        });
}

void clear_interval_profiles()
{
        struct vm_profile *vm;
        struct buffer_profile *gem;

        FOR_BUFFER_PROFILE(vm, gem, {
                clear_stalls(gem);
        });
}

void clear_unbound_buffers()
{
        struct vm_profile *vm;
        struct buffer_profile *gem;

again:;
        FOR_BUFFER_PROFILE(vm, gem, {
                if (gem->unbound) {
                        delete_buffer_profile(vm, gem->gpu_addr);

                        /* Iterator is invalid due to deletion. Start search again. */

                        /* An alternative approach would be to store all to-be-deleted
                         * buffer IDs in an array and then call delete_buffer_profile()
                         * for each of those. This seems simpler. */

                        /* The FOR_BUFFER_PROFILE macro locks both the vm_profiles_lock
                         * and the vm_profile itself, but if we break like this, it won't
                         * have a chance to release them. Do that manually. */

                        unlock_vm_profile(vm);
                        pthread_rwlock_unlock(&vm_profiles_lock);

                        goto again;
                }
        });
}

static struct vm_profile *_get_vm_profile(uint32_t vm_id, int create) {
        struct vm_profile **vmp;
        struct vm_profile  *vm;

        vmp = hash_table_get_val(vm_profiles, (uint64_t)vm_id);

        if (vmp != NULL) {
                return *vmp;
        }

        if (!create) {
                return NULL;
        }

        vm = malloc(sizeof(*vm));
        memset(vm, 0, sizeof(*vm));

        pthread_mutex_init(&vm->lock, NULL);
        vm->vm_id = vm_id;
        vm->buffer_profiles = tree_make(uint64_t, buffer_profile_struct);

        hash_table_insert(vm_profiles, (uint64_t)vm_id, vm);

        return vm;
}

void create_vm_profile(uint32_t vm_id) {
        pthread_rwlock_wrlock(&vm_profiles_lock);
        _get_vm_profile(vm_id, 1);
        pthread_rwlock_unlock(&vm_profiles_lock);
}

struct vm_profile *get_vm_profile(uint32_t vm_id) {
        return _get_vm_profile(vm_id, 0);
}

void lock_vm_profile(struct vm_profile *vm) {
        pthread_mutex_lock(&vm->lock);
        vm->lock_holder = pthread_self();
}

void unlock_vm_profile(struct vm_profile *vm) {
        assert(vm->lock_holder == pthread_self()
                && "attempt to unlock a vm_profile by a thread that does not own the lock!");
        vm->lock_holder = 0;
        pthread_mutex_unlock(&vm->lock);
}

struct vm_profile *acquire_vm_profile(uint32_t vm_id) {
        struct vm_profile *vm;

        pthread_rwlock_rdlock(&vm_profiles_lock);

        vm = _get_vm_profile(vm_id, 0);

        if (vm == NULL) {
                pthread_rwlock_unlock(&vm_profiles_lock);
                return NULL;
        }

        lock_vm_profile(vm);

        return vm;
}

void release_vm_profile(struct vm_profile *vm) {
        unlock_vm_profile(vm);
        pthread_rwlock_unlock(&vm_profiles_lock);
}
