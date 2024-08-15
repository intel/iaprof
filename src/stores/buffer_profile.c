#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "iaprof.h"
#include "buffer_profile.h"


int buffer_ID_cmp(const struct buffer_ID a, const struct buffer_ID b) {
        if (a.vm_id < b.vm_id)       { return -1; }
        if (a.vm_id > b.vm_id)       { return  1; }
        if (a.gpu_addr < b.gpu_addr) { return -1; }
        if (a.gpu_addr > b.gpu_addr) { return  1; }

        return 0;
}

tree(buffer_ID_struct, buffer_profile_struct) buffer_profiles;

struct buffer_profile *get_buffer_profile(uint32_t vm_id, uint64_t gpu_addr);struct buffer_profile *get_buffer_profile(uint32_t vm_id, uint64_t gpu_addr) {
        struct buffer_ID                                 id;
        tree_it(buffer_ID_struct, buffer_profile_struct) it;

        id = (struct buffer_ID){ vm_id, gpu_addr };

        it = tree_lookup(buffer_profiles, id);
        if (tree_it_good(it)) {
                return &tree_it_val(it);
        }

        return NULL;
}

struct buffer_profile *get_or_create_buffer_profile(uint32_t vm_id, uint64_t gpu_addr) {
        struct buffer_ID                                 id;
        tree_it(buffer_ID_struct, buffer_profile_struct) it;
        struct buffer_profile                            new_profile;

        id = (struct buffer_ID){ vm_id, gpu_addr };

        if (buffer_profiles == NULL) {
                buffer_profiles = tree_make(buffer_ID_struct, buffer_profile_struct);
        } else {
                it = tree_lookup(buffer_profiles, id);
                if (tree_it_good(it)) {
                        goto found;
                }
        }

        memset(&new_profile, 0, sizeof(new_profile));
        it = tree_insert(buffer_profiles, id, new_profile);

found:;
        return &tree_it_val(it);
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

        /* @TODO: free execbuf_stack_str? */
        /* @TODO: free kv? */
}

void free_buffer_profiles() {
        tree_it(buffer_ID_struct, buffer_profile_struct) it;

        tree_traverse(buffer_profiles, it) {
                free_buffer_profile(&tree_it_val(it));
        }

        tree_free(buffer_profiles);
        buffer_profiles = NULL;
}

void delete_buffer_profile(uint32_t vm_id, uint64_t gpu_addr) {
        struct buffer_ID                                 id;
        tree_it(buffer_ID_struct, buffer_profile_struct) it;

        id = (struct buffer_ID){ vm_id, gpu_addr };

        it = tree_lookup(buffer_profiles, id);
        if (!tree_it_good(it)) {
                return;
        }

        free_buffer_profile(&tree_it_val(it));
        tree_delete(buffer_profiles, id);
}

/**
  Global array of GEMs that we've seen.
  This is what we'll search through when we get an
  EU stall sample.
**/
pthread_rwlock_t buffer_profile_lock = PTHREAD_RWLOCK_INITIALIZER;
struct buffer_profile *buffer_profile_arr = NULL;
struct interval_profile *interval_profile_arr = NULL;
size_t buffer_profile_size = 0, buffer_profile_used = 0;
uint64_t iba = 0;

/**
  Global array of VMs. Each VM keeps track of requests
  that resulted from execbuffer calls in that VM.
**/
struct vm_profile *vm_profile_arr = NULL;
uint32_t num_vms = 0;

void print_buffer_profiles()
{
        int i;
        struct buffer_profile *gem;

        if (!debug)
                return;

        printf( "==== BUFFER_PROFILE_ARR =====\n");

        for (i = 0; i < buffer_profile_used; i++) {
                gem = &(buffer_profile_arr[i]);

                printf(
                        "vm_id=%u gpu_addr=0x%lx buff_sz=%zu\n",
                        gem->vm_id, gem->gpu_addr, gem->buff_sz);
        }
}

void clear_interval_profiles()
{
        tree_it(buffer_ID_struct, buffer_profile_struct) it;
        struct buffer_profile *gem;

        tree_traverse(buffer_profiles, it) {
                gem = &tree_it_val(it);
                clear_stalls(gem);
        }
}

void clear_unbound_buffers()
{
        tree_it(buffer_ID_struct, buffer_profile_struct) it;
        struct buffer_profile *gem;

again:;
        tree_traverse(buffer_profiles, it) {
                gem = &tree_it_val(it);
                if (gem->unbound) {
                        delete_buffer_profile(gem->vm_id, gem->gpu_addr);

                        /* Iterator is invalid due to deletion. Start search again. */

                        /* An alternative approach would be to store all to-be-deleted
                         * buffer IDs in an array and then call delete_buffer_profile()
                         * for each of those. This seems simpler. */
                        goto again;
                }
        }
}

struct vm_profile *get_vm_profile(uint32_t vm_id)
{
        uint32_t old_size;

        /* The index into the array is vm_id - 1 (since vm_id cannot be zero). */
        if (vm_id == 0) {
                fprintf(stderr, "WARNING: vm_id was zero!\n");
                return NULL;
        }
        if (num_vms < vm_id) {
                old_size = num_vms;
                num_vms = vm_id;
                vm_profile_arr = realloc(vm_profile_arr,
                                         sizeof(struct vm_profile) * num_vms);
                memset(vm_profile_arr + old_size, 0,
                       sizeof(struct vm_profile) * (num_vms - old_size));
        }
        return &(vm_profile_arr[vm_id - 1]);
}

void request_submit(uint32_t vm_id, uint32_t seqno, uint32_t gem_ctx, uint16_t class, uint16_t instance)
{
        struct vm_profile *vm;
        struct request_profile_list *rq;

        vm = get_vm_profile(vm_id);
        if (!vm) {
                fprintf(stderr,
                        "WARNING: Can't store a request for vm_id = 0!\n");
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
        uint32_t vm_index;
        struct vm_profile *vm;
        struct request_profile_list *rq;

        for (vm_index = 0; vm_index < num_vms; vm_index++) {
                vm = &(vm_profile_arr[vm_index]);

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
        uint32_t vm_index;
        struct vm_profile *vm;
        struct request_profile_list *rq;
        struct request_profile_list *rq_prev;

        for (vm_index = 0; vm_index < num_vms; vm_index++) {
                vm = &(vm_profile_arr[vm_index]);

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
        uint32_t vm_index;
        char active_requests, compute_engine;
        struct vm_profile *vm;
        struct request_profile_list *rq;

        for (vm_index = 0; vm_index < num_vms; vm_index++) {
                /* Are there any active or retired requests this interval? */
                active_requests = 0;
                compute_engine = 0;
                vm = &(vm_profile_arr[vm_index]);
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
