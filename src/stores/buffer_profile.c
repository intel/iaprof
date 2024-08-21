#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "iaprof.h"
#include "buffer_profile.h"

static uint64_t vm_id_hash(uint64_t vm_id) { return vm_id; }

hash_table(uint64_t, vm_profile_ptr) vm_profiles;


void init_profiles() {
        vm_profiles = hash_table_make(uint64_t, vm_profile_ptr, vm_id_hash);
}

struct buffer_profile *get_buffer_profile(uint32_t vm_id, uint64_t gpu_addr) {
        struct vm_profile *vm;
        tree_it(uint64_t, buffer_profile_struct) it;

        vm = get_vm_profile(vm_id);
        if (vm == NULL) {
                return NULL;
        }

        it = tree_lookup(vm->buffer_profiles, gpu_addr);
        if (tree_it_good(it)) {
                return &tree_it_val(it);
        }

        return NULL;
}

struct buffer_profile *get_or_create_buffer_profile(uint32_t vm_id, uint64_t gpu_addr) {
        struct vm_profile *vm;
        tree_it(uint64_t, buffer_profile_struct) it;
        struct buffer_profile new_profile;

        vm = get_vm_profile(vm_id);
        if (vm == NULL) {
                return NULL;
        }

        it = tree_lookup(vm->buffer_profiles, gpu_addr);
        if (tree_it_good(it)) {
                goto found;
        }

        memset(&new_profile, 0, sizeof(new_profile));
        new_profile.vm_id = vm_id;
        new_profile.gpu_addr = gpu_addr;
        it = tree_insert(vm->buffer_profiles, gpu_addr, new_profile);

found:;
        return &tree_it_val(it);
}

struct buffer_profile *get_containing_buffer_profile(uint32_t vm_id, uint64_t gpu_addr) {
        struct vm_profile *vm;
        tree_it(uint64_t, buffer_profile_struct) it;
        struct buffer_profile *gem;

        vm = get_vm_profile(vm_id);
        if (vm == NULL) {
                return NULL;
        }

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
        struct request_profile_list  *rq;
        struct request_profile_list  *next_rq;

        hash_table_traverse(vm_profiles, vm_id, vmp) {
                (void)vm_id;

                vm = *vmp;

                free_buffer_profiles(vm->buffer_profiles);

                rq      = vm->request_list;
                next_rq = NULL;
                while (rq != NULL) {
                        next_rq = rq->next;
                        free(rq);
                        rq = next_rq;
                }

                free(vm);
        }

        hash_table_free(vm_profiles);
}

void delete_buffer_profile(uint32_t vm_id, uint64_t gpu_addr) {
        struct vm_profile *vm;
        tree_it(uint64_t, buffer_profile_struct) it;

        vm = get_vm_profile(vm_id);
        if (vm == NULL) {
                return;
        }

        it = tree_lookup(vm->buffer_profiles, gpu_addr);
        if (!tree_it_good(it)) {
                return;
        }

        free_buffer_profile(&tree_it_val(it));
        tree_delete(vm->buffer_profiles, gpu_addr);
}

uint64_t iba = 0;

void print_buffer_profiles()
{
        struct buffer_profile *gem;

        if (!debug)
                return;

        printf( "==== BUFFER_PROFILE_ARR =====\n");

        FOR_BUFFER_PROFILE(gem, {
                printf(
                        "vm_id=%u gpu_addr=0x%lx buff_sz=%zu\n",
                        gem->vm_id, gem->gpu_addr, gem->buff_sz);
        });
}

void clear_interval_profiles()
{
        struct buffer_profile *gem;

        FOR_BUFFER_PROFILE(gem, {
                clear_stalls(gem);
        });
}

void clear_unbound_buffers()
{
        struct buffer_profile *gem;

again:;
        FOR_BUFFER_PROFILE(gem, {
                if (gem->unbound) {
                        delete_buffer_profile(gem->vm_id, gem->gpu_addr);

                        /* Iterator is invalid due to deletion. Start search again. */

                        /* An alternative approach would be to store all to-be-deleted
                         * buffer IDs in an array and then call delete_buffer_profile()
                         * for each of those. This seems simpler. */
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

        vm->buffer_profiles = tree_make(uint64_t, buffer_profile_struct);

        hash_table_insert(vm_profiles, (uint64_t)vm_id, vm);

        return vm;
}

struct vm_profile *create_vm_profile(uint32_t vm_id) {
        return _get_vm_profile(vm_id, 1);
}

struct vm_profile *get_vm_profile(uint32_t vm_id) {
        return _get_vm_profile(vm_id, 0);
}

void request_submit(uint32_t vm_id, uint32_t seqno, uint32_t gem_ctx, uint16_t class, uint16_t instance)
{
        struct vm_profile *vm;
        struct request_profile_list *rq;

        vm = get_vm_profile(vm_id);
        if (!vm) {
                fprintf(stderr,
                        "WARNING: Can't store a request for a vm that hasn't been created! (vm_id = %u)\n",
                        vm_id);
                return;
        }

        rq = malloc(sizeof(*rq));

        rq->next    = vm->request_list;
        rq->seqno   = seqno;
        rq->gem_ctx = gem_ctx;
        rq->retired = 0;
        rq->class = class;
        rq->instance = instance;

        vm->request_list = rq;
        vm->num_requests += 1;
}

/* Mark a request as "retired." It'll be deleted after this interval is entirely over. */
void request_retire(uint32_t seqno, uint32_t gem_ctx)
{
        uint64_t vm_id;
        struct vm_profile **vmp;
        struct vm_profile *vm;
        struct request_profile_list *rq;

        hash_table_traverse(vm_profiles, vm_id, vmp) {
                vm = *vmp;

                (void)vm_id;

                for (rq = vm->request_list; rq != NULL; rq = rq->next) {
                        if ((rq->seqno == seqno) && (rq->gem_ctx == gem_ctx)) {
                                rq->retired = 1;
                                return;
                        }
                }
        }
}

void clear_retired_requests()
{
        uint64_t vm_id;
        struct vm_profile **vmp;
        struct vm_profile *vm;
        struct request_profile_list *rq;
        struct request_profile_list *rq_prev;

        hash_table_traverse(vm_profiles, vm_id, vmp) {
                vm = *vmp;

                (void)vm_id;

                rq_prev = NULL;
                rq      = vm->request_list;
                while (rq != NULL) {
                        if (rq->retired) {
                                if (rq_prev == NULL) {
                                        vm->request_list = rq->next;
                                } else {
                                        rq_prev->next = rq->next;
                                }

                                free(rq);

                                rq = rq_prev == NULL ? vm->request_list : rq_prev->next;

                                vm->num_requests -= 1;
                        } else {
                                rq_prev = rq;
                                rq      = rq->next;
                        }
                }
        }
}

#define I915_ENGINE_CLASS_COMPUTE 4

void mark_vms_active()
{
        uint64_t vm_id;
        struct vm_profile **vmp;
        struct vm_profile *vm;
        char active_requests, compute_engine;
        struct request_profile_list *rq;

        hash_table_traverse(vm_profiles, vm_id, vmp) {
                vm = *vmp;

                (void)vm_id;

                /* Are there any active or retired requests this interval? */
                active_requests = 0;
                compute_engine = 0;
                for (rq = vm->request_list; rq != NULL; rq = rq->next) {
                        if (rq->seqno && rq->gem_ctx) {
                                active_requests = 1;
                        }
                        if (rq->class == I915_ENGINE_CLASS_COMPUTE) {
                                compute_engine = 1;
                        }
                }

                if (active_requests && compute_engine) {
                        vm->active = 1;
                } else {
                        vm->active = 0;
                }
        }
}
