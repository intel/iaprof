#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "iaprof.h"
#include "buffer_profile.h"

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
                        "file=0x%lx handle=%u vm_id=%u cpu_addr=0x%lx gpu_addr=0x%llx buff_sz=%zu\n",
                        gem->file, gem->handle, gem->vm_id, gem->cpu_addr,
                        gem->vm_bind_info.gpu_addr, gem->buff_sz);
        }
}

void free_interval_profiles()
{
        int i;
        uint64_t offset, *tmp;
        struct offset_profile **found;

        for (i = 0; i < buffer_profile_used; i++) {
                if (interval_profile_arr[i].counts) {
                        hash_table_traverse(interval_profile_arr[i].counts,
                                            offset, tmp)
                        {
                                found = (struct offset_profile **)tmp;
                                free(*found);
                        }
                        hash_table_free(interval_profile_arr[i].counts);
                }
        }
        free(interval_profile_arr);
}

void clear_interval_profiles()
{
        int i;
        uint64_t offset, *tmp;
        struct offset_profile **found;

        for (i = 0; i < buffer_profile_used; i++) {
                if (interval_profile_arr[i].counts) {
                        hash_table_traverse(interval_profile_arr[i].counts,
                                            offset, tmp)
                        {
                                found = (struct offset_profile **)tmp;
                                free(*found);
                        }
                        hash_table_free(interval_profile_arr[i].counts);
                }
        }

        memset(interval_profile_arr, 0,
               buffer_profile_size * sizeof(struct interval_profile));
}

void free_buffer_profiles()
{
        int n;
        struct buffer_profile *gem;
        
        if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
                fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
                return;
        }


        for (n = 0; n < buffer_profile_used; n++) {
                gem = &(buffer_profile_arr[n]);
                if (gem->buff && gem->buff_sz) {
                        free(gem->buff);
                }
        }
        free(buffer_profile_arr);
        
        if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
                fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
                return;
        }
}

/* Ensure that we have enough room to place a newly-seen sample, and place it.
   Does NOT grab the lock, so the caller should. */
uint64_t grow_buffer_profiles()
{
        size_t old_size;

        /* Ensure there's enough room in the array */
        if (buffer_profile_size == buffer_profile_used) {
                /* Not enough room in the array */
                old_size = buffer_profile_size;

                buffer_profile_size += 64;

                buffer_profile_arr = realloc(
                        buffer_profile_arr,
                        buffer_profile_size * sizeof(struct buffer_profile));
                interval_profile_arr = realloc(
                        interval_profile_arr,
                        buffer_profile_size * sizeof(struct interval_profile));

                memset(buffer_profile_arr + buffer_profile_used, 0,
                       (buffer_profile_size - old_size) *
                               sizeof(struct buffer_profile));
                memset(interval_profile_arr + buffer_profile_used, 0,
                       (buffer_profile_size - old_size) *
                               sizeof(struct interval_profile));

                if (debug)
                        fprintf(stderr, "INFO: Increasing buffer size.\n");
        }

        buffer_profile_used++;
        return buffer_profile_used - 1;
}

/* Looks up a buffer in the buffer_profile_arr by file/handle pair
   (using its mmap call).
   Returns -1 if not found. */
int get_buffer_profile_by_mapping(uint64_t file, uint32_t handle)
{
        int n;
        struct buffer_profile *gem;

        for (n = 0; n < buffer_profile_used; n++) {
                gem = &buffer_profile_arr[n];
                if ((gem->handle == handle) &&
                    (gem->file == file)) {
                        return n;
                }
        }

        return -1;
}

/* Looks up a buffer in the buffer_profile_arr by the vm_id and gpu_addr
   provided by a vm_bind call.
   Returns -1 if not found. */
int get_buffer_profile_by_binding(uint32_t vm_id, uint64_t gpu_addr)
{
        int n;
        struct buffer_profile *gem;

        for (n = 0; n < buffer_profile_used; n++) {
                gem = &buffer_profile_arr[n];
                if ((gem->vm_bind_info.vm_id == vm_id) &&
                    (gem->vm_bind_info.gpu_addr == gpu_addr)) {
                        return n;
                }
        }

        return -1;
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

void request_submit(uint32_t vm_id, uint32_t seqno, uint32_t gem_ctx)
{
        uint32_t rq_index;
        struct vm_profile *vm;
        struct request_profile *rq;
        char found;

        vm = get_vm_profile(vm_id);
        if (!vm) {
                fprintf(stderr,
                        "WARNING: Can't store a request for vm_id = 0!\n");
                return;
        }

        /* Find the first all-zero request_profile in this vm, if extant. */
        found = 0;
        for (rq_index = 0; rq_index < vm->num_requests; rq_index++) {
                rq = &(vm->requests[rq_index]);
                if ((rq->seqno == 0) && (rq->gem_ctx == 0)) {
                        /* This is an empty slot, so use it */
                        found = 1;
                        break;
                }
        }

        if (!found) {
                /* Allocate a new slot */
                if (vm->num_requests >= MAX_OPEN_REQUESTS) {
                        fprintf(stderr,
                                "WARNING: MAX_OPEN_REQUESTS hit. Not recording a request.\n");
                        return;
                }
                vm->num_requests++;
                rq = &(vm->requests[vm->num_requests - 1]);
        }

        /* Fill the slot */
        rq->seqno = seqno;
        rq->gem_ctx = gem_ctx;
        rq->retired = 0;
}

/* Mark a request as "retired." It'll be deleted after this interval is entirely over. */
void request_retire(uint32_t seqno, uint32_t gem_ctx)
{
        uint32_t rq_index, vm_index;
        struct vm_profile *vm;
        struct request_profile *rq;

        for (vm_index = 0; vm_index < num_vms; vm_index++) {
                vm = &(vm_profile_arr[vm_index]);
                for (rq_index = 0; rq_index < vm->num_requests; rq_index++) {
                        rq = &(vm->requests[rq_index]);
                        if ((rq->seqno == seqno) && (rq->gem_ctx == gem_ctx)) {
                                rq->retired = 1;
                                return;
                        }
                }
        }
}

void clear_retired_requests()
{
        uint32_t vm_index, rq_index;
        struct vm_profile *vm;
        struct request_profile *rq;

        for (vm_index = 0; vm_index < num_vms; vm_index++) {
                vm = &(vm_profile_arr[vm_index]);
                for (rq_index = 0; rq_index < vm->num_requests; rq_index++) {
                        rq = &(vm->requests[rq_index]);
                        if (rq->retired) {
                                memset(rq, 0, sizeof(struct request_profile));
                        }
                }
        }
}

void mark_vms_active()
{
        uint32_t vm_index, rq_index;
        char active_requests;
        struct vm_profile *vm;
        struct request_profile *rq;

        for (vm_index = 0; vm_index < num_vms; vm_index++) {
                /* Are there any active or retired requests this interval? */
                active_requests = 0;
                vm = &(vm_profile_arr[vm_index]);
                for (rq_index = 0; rq_index < vm->num_requests; rq_index++) {
                        rq = &(vm->requests[rq_index]);
                        if (rq->seqno && rq->gem_ctx) {
                                active_requests = 1;
                                break;
                        }
                }

                if (active_requests) {
                        vm->active = 1;
                } else {
                        vm->active = 0;
                }
        }
}
