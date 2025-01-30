#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <stdbool.h>

#include "iaprof.h"
#include "printers/debug/debug_printer.h"
#include "buffer_profile.h"

_Atomic uint64_t iba = 0;

tree(file_vm_pair_struct, vm_profile_ptr) vm_profiles;
pthread_rwlock_t vm_profiles_lock = PTHREAD_RWLOCK_INITIALIZER;

int file_vm_pair_cmp(struct file_vm_pair a, struct file_vm_pair b) {
        if (a.file < b.file) {
                return -1;
        }
        if (a.file > b.file) {
                return 1;
        }
        if (a.vm_id < b.vm_id) {
                return -1;
        }
        if (a.vm_id > b.vm_id) {
                return 1;
        }
        return 0;
}

void init_profiles() {
        vm_profiles = tree_make(file_vm_pair_struct, vm_profile_ptr);
}

struct buffer_binding *get_binding(struct vm_profile *vm, uint64_t gpu_addr) {
        tree_it(uint64_t, buffer_binding_struct) it;

        assert(vm->lock_holder == pthread_self()
                && "get_binding called, but vm->lock not held by this thread!");

        it = tree_lookup(vm->bindings, gpu_addr);
        if (tree_it_good(it)) {
                return &tree_it_val(it);
        }

        return NULL;
}

struct buffer_binding *get_or_create_binding(struct vm_profile *vm, uint64_t gpu_addr) {
        tree_it(uint64_t, buffer_binding_struct) it;
        struct buffer_binding new_bind;

        assert(vm->lock_holder == pthread_self()
                && "get_or_create_binding called, but vm->lock not held by this thread!");

        it = tree_lookup(vm->bindings, gpu_addr);
        if (tree_it_good(it)) {
                goto found;
        }

        memset(&new_bind, 0, sizeof(new_bind));
        new_bind.vm_id = vm->vm_id;
        new_bind.gpu_addr = gpu_addr;
        it = tree_insert(vm->bindings, gpu_addr, new_bind);

found:;
        return &tree_it_val(it);
}

struct buffer_binding *get_containing_binding(struct vm_profile *vm, uint64_t gpu_addr) {
        tree_it(uint64_t, buffer_binding_struct) it;
        struct buffer_binding *bind;

        assert(vm->lock_holder == pthread_self()
                && "get_containing_binding called, but vm->lock not held by this thread!");

        it = tree_gtr(vm->bindings, gpu_addr);
        tree_it_prev(it);

        if (!tree_it_good(it)) {
                return NULL;
        }

        bind = &tree_it_val(it);

        if (gpu_addr <  bind->gpu_addr
        ||  gpu_addr >= bind->gpu_addr + bind->bind_size) {

                return NULL;
        }

        return bind;
}

static void clear_stalls(struct buffer_binding *bind) {
        if (bind->stall_counts != NULL) {
                hash_table_free(bind->stall_counts);
                bind->stall_counts = NULL;
        }
}

static void free_binding(struct buffer_binding *bind) {
        clear_stalls(bind);

        if (bind->kv != NULL) {
            iga_fini(bind->kv);
            bind->kv = NULL;
        }
}

static void free_bindings(tree(uint64_t, buffer_binding_struct) buffer_bindings) {
        tree_it(uint64_t, buffer_binding_struct) it;

        tree_traverse(buffer_bindings, it) {
                free_binding(&tree_it_val(it));
        }

        tree_free(buffer_bindings);
}

void free_profiles() {
        tree_it(file_vm_pair_struct, vm_profile_ptr)  it;
        struct vm_profile                            *vm;

        pthread_rwlock_wrlock(&vm_profiles_lock);

        tree_traverse(vm_profiles, it) {
                vm = tree_it_val(it);

                free_bindings(vm->bindings);

                free(vm);
        }

        hash_table_free(vm_profiles);

        /* Keep the write lock locked. No one should be touching vm_profiles
         * past this point. */
}

void delete_binding(struct vm_profile *vm, uint64_t gpu_addr) {
        tree_it(uint64_t, buffer_binding_struct) it;

        assert(vm->lock_holder == pthread_self()
                && "delete_binding called, but vm->lock not held by this thread!");

        it = tree_lookup(vm->bindings, gpu_addr);
        if (!tree_it_good(it)) {
                return;
        }

        free_binding(&tree_it_val(it));
        tree_delete(vm->bindings, gpu_addr);
}

void print_bindings()
{
        struct vm_profile *vm;
        struct buffer_binding *bind;

        debug_printf( "==== BINDINGS ====\n");

        FOR_BINDING(vm, bind, {
                debug_printf(
                        "vm_id=%u gpu_addr=0x%lx\n",
                        bind->vm_id, bind->gpu_addr);
        });
}

void clear_interval_profiles()
{
        struct vm_profile *vm;
        struct buffer_binding *bind;

        FOR_BINDING(vm, bind, {
                clear_stalls(bind);
        });
}

void clear_unbound_buffers()
{
        struct vm_profile *vm;
        struct buffer_binding *bind;

again:;
        FOR_BINDING(vm, bind, {
                if (bind->unbound) {
                        delete_binding(vm, bind->gpu_addr);

                        /* Iterator is invalid due to deletion. Start search again. */

                        /* An alternative approach would be to store all to-be-deleted
                         * buffer IDs in an array and then call delete_binding()
                         * for each of those. This seems simpler. */
                        FOR_BINDING_CLEANUP(); goto again;
                }
        });
}

static struct vm_profile *_get_vm_profile(uint64_t file, uint32_t vm_id, int create) {
        struct file_vm_pair                           pair;
        tree_it(file_vm_pair_struct, vm_profile_ptr)  lookup;
        struct vm_profile                            *vm;

        pair   = (struct file_vm_pair){ .file = file, .vm_id = vm_id };
        lookup = tree_lookup(vm_profiles, pair);

        if (tree_it_good(lookup)) {
                return tree_it_val(lookup);
        }

        if (!create) {
                return NULL;
        }

        vm = malloc(sizeof(*vm));
        memset(vm, 0, sizeof(*vm));

        pthread_mutex_init(&vm->lock, NULL);
        vm->vm_id    = vm_id;
        vm->file     = file;
        vm->bindings = tree_make(uint64_t, buffer_binding_struct);

        tree_insert(vm_profiles, pair, vm);

        return vm;
}

void create_vm_profile(uint64_t file ,uint32_t vm_id) {
        pthread_rwlock_wrlock(&vm_profiles_lock);
        _get_vm_profile(file, vm_id, 1);
        pthread_rwlock_unlock(&vm_profiles_lock);
}

struct vm_profile *get_vm_profile(uint64_t file ,uint32_t vm_id) {
        return _get_vm_profile(file, vm_id, 0);
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

struct vm_profile *acquire_vm_profile(uint64_t file ,uint32_t vm_id) {
        struct vm_profile *vm;

        pthread_rwlock_rdlock(&vm_profiles_lock);

        vm = _get_vm_profile(file, vm_id, 0);

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
