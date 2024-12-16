/***************************************
* Event Collector
***************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#include "iaprof.h"

#include "stores/buffer_profile.h"

#include "printers/stack/stack_printer.h"
#include "printers/printer.h"

#include "gpu_parsers/bb_parser.h"

#include "bpf/main.h"
#include "bpf/main.skel.h"
#include "bpf_i915_collector.h"
#include "collectors/debug_i915/debug_i915_collector.h"

#include "utils/utils.h"

uint32_t global_vm_id = 0;
static uint32_t vm_bind_bpf_counter = 0;

struct buffer_copy_dst {
        unsigned char **addrp;
        uint64_t *sizep;
};
static struct buffer_copy_dst bcopy_dst;

static int handle_buffer_copy(void *ctx, void *data_arg, size_t data_sz) {
        struct buffer_copy *bcopy;

        if (bcopy_dst.addrp == NULL) {
                /* drop this copy */
                goto out;
        }

        bcopy = data_arg;

        if (handle_binary(bcopy_dst.addrp, bcopy->bytes, bcopy_dst.sizep, bcopy->size) != 0) {
                WARN("handle_binary() returned non-zero\n");
        }

out:;
        bcopy_dst.addrp = NULL;
        bcopy_dst.sizep = NULL;
        return 0;
}

static int consume_buffer_from_bpf(unsigned char **addrp, uint64_t *sizep) {
        bcopy_dst.addrp = addrp;
        bcopy_dst.sizep = sizep;

        ring_buffer__consume_n(bpf_info.buffer_copy_rb, 1);

        return 0;
}

static void drop_buffer_from_bpf() {
        consume_buffer_from_bpf(NULL, NULL);
}

static void consume_buffer_from_bpf_into_bo(struct buffer_object *bo) {
        consume_buffer_from_bpf(&(bo->buff), &(bo->buff_sz));
}

/***************************************
* BPF Handlers
***************************************/

int handle_unmap(void *data_arg)
{
        struct unmap_info *info;
        struct buffer_object *bo;

        info = (struct unmap_info *)data_arg;
        if (verbose) {
                print_unmap(info);
        }

        bo = create_buffer(info->file, info->handle);
        consume_buffer_from_bpf_into_bo(bo);
        release_buffer(bo);

        return 0;
}

int handle_userptr(void *data_arg)
{
        struct userptr_info *info;
        struct buffer_object *bo;

        info = (struct userptr_info *)data_arg;
        if (verbose) {
                print_userptr(info);
        }

        bo = create_buffer(info->file, info->handle);
        consume_buffer_from_bpf_into_bo(bo);
        release_buffer(bo);

        return 0;
}

int handle_vm_create(void *data_arg)
{
        struct vm_create_info *info;

        info = (struct vm_create_info *)data_arg;
        if (verbose) {
                print_vm_create(info);
        }

        create_vm_profile(info->file, info->vm_id);

        if (debug_collector) {
                /* Register the PID with the debug_i915 collector */
                init_debug_i915(devinfo.fd, info->pid);
        }

        return 0;
}

int handle_vm_bind(void *data_arg)
{
        struct vm_bind_info *info;
        struct vm_profile *vm;
        struct buffer_binding *bind;
        struct shader_binary *shader_bin;
        struct buffer_object *bo;

        info = (struct vm_bind_info *)data_arg;
        if (verbose) {
                print_vm_bind(info, vm_bind_bpf_counter);
        }

#ifdef SLOW_MODE
        if (debug_collector) {
                pthread_mutex_lock(&debug_i915_vm_bind_lock);
        }
#endif

        pthread_mutex_lock(&debug_i915_shader_binaries_lock);

        vm = acquire_vm_profile(info->file, info->vm_id);

        if (!vm) {
                WARN("Got a vm_bind to vm_id=%u gpu_addr=0x%llx, for which there was no VM.\n",
                     info->vm_id, info->gpu_addr);
                vm_bind_bpf_counter++;
                goto cleanup;
        }

        bind = get_or_create_binding(vm, info->gpu_addr);
        bind->bind_size = info->size;
        bind->pid = info->pid;
        bind->handle = info->handle;
        bind->file = info->file;
        bind->vm_bind_order = vm_bind_bpf_counter;

        /* See if we've saved the shader binary for this address.
         * If so, create a buffer object for it. */
        shader_bin = get_shader_binary(bind->gpu_addr);
        if (shader_bin != NULL) {
                bo = acquire_buffer(bind->file, bind->handle);
                if (bo == NULL) {
                        bo = create_buffer(bind->file, bind->handle);
                        handle_binary(&(bo->buff), shader_bin->bytes, &(bo->buff_sz), shader_bin->size);
                }
                release_buffer(bo);
        }

        release_vm_profile(vm);

cleanup:
        pthread_mutex_unlock(&debug_i915_shader_binaries_lock);

#ifdef SLOW_MODE
        if (debug_collector) {

                /* @TODO: Wait until bpf ring buffer is emtpy. */

                /* Signal the debug_i915 collector that there's a new vm_bind event */
                pthread_cond_signal(&debug_i915_vm_bind_cond);
        }
        pthread_mutex_unlock(&debug_i915_vm_bind_lock);
#endif

        vm_bind_bpf_counter++;

        wakeup_eustall_deferred_attrib_thread();

        return 0;
}

int handle_vm_unbind(void *data_arg)
{
        struct vm_unbind_info *info;
        struct vm_profile *vm;
        struct buffer_binding *bind;

        info = (struct vm_unbind_info *)data_arg;
        if (verbose) {
                print_vm_unbind(info);
        }

        vm = acquire_vm_profile(info->file, info->vm_id);

        bind = get_binding(vm, info->gpu_addr);
        if (bind == NULL) {
                if (debug) {
                        WARN("Got a vm_unbind on gpu_addr=0x%llx for which there wasn't a vm_bind!\n",
                             info->gpu_addr);
                }
                goto cleanup;
        }

        bind->unbound = 1;

cleanup:
        release_vm_profile(vm);

        return 0;
}

int handle_batchbuffer(void *data_arg)
{
        struct batchbuffer_info *info;
        struct vm_profile *vm;
        struct buffer_binding *bind;
        struct buffer_object *bo;

        info = (struct batchbuffer_info *)data_arg;

        if (verbose) {
                print_batchbuffer(info);
        }

        vm = acquire_vm_profile(info->file, info->vm_id);

        /* Find the buffer that this batchbuffer is associated with */
        bind = get_binding(vm, info->gpu_addr);
        if (bind == NULL) {
                if (debug ) {
                        WARN("couldn't find a buffer to store the batchbuffer in.\n");
                }
                drop_buffer_from_bpf();
                goto cleanup;
        }

        bo = create_buffer(bind->file, bind->handle);
        consume_buffer_from_bpf_into_bo(bo);
        release_buffer(bo);

cleanup:
        release_vm_profile(vm);

        return 0;
}

int handle_debug_area(void *data_arg)
{
        struct debug_area_info *info;
        struct vm_profile *vm;
        struct buffer_binding *bind;

        info = (struct debug_area_info *)data_arg;

        if (verbose) {
                print_debug_area(info);
        }

        vm = acquire_vm_profile(info->file, info->vm_id);

        /* Find the buffer that this batchbuffer is associated with */
        bind = get_binding(vm, info->gpu_addr);
        if (bind == NULL) {
                if (debug ) {
                        WARN("couldn't find a buffer to store the debug area in.\n");
                }
                goto cleanup;
        }

        bind->type = BUFFER_TYPE_DEBUG_AREA;
        bind->pid = info->pid;
        memcpy(bind->name, info->name, TASK_COMM_LEN);

cleanup:
        release_vm_profile(vm);

        return 0;
}

int handle_execbuf_end(void *data_arg)
{
        struct execbuf_end_info *info;
        struct vm_profile *vm;
        struct buffer_binding *bind;
        struct buffer_object *bo;
        struct bb_parser parser;
        struct timespec parser_start, parser_end;

        /* First, just print out the execbuf_end */
        info = (struct execbuf_end_info *)data_arg;
        if (verbose) {
                print_execbuf_end(info);
        }

        debug_printf("execbuf stack");
        for (int i = 0; i < MAX_STACK_DEPTH; i += 1) {
                if (info->stack.addrs[i] == 0) { break; }
                debug_printf(" 0x%llx", info->stack.addrs[i]);
        }
        for (int i = 0; i < MAX_STACK_DEPTH; i += 1) {
                if (info->kernel_stack.addrs[i] == 0) { break; }
                debug_printf(" 0x%llx", info->kernel_stack.addrs[i]);
        }
        debug_printf("\n");

        vm = acquire_vm_profile(info->file, info->vm_id);

        if (vm == NULL) {
                WARN("Unable to find a vm_profile for vm_id=%u\n",
                     info->vm_id);
                drop_buffer_from_bpf();
                goto cleanup;
        }

        bind = get_binding(vm, info->bb_offset);

        if (bind == NULL) {
                WARN("Unable to find a buffer for vm_id=%u bb_offset=0x%llx\n",
                     info->vm_id, info->bb_offset);
                drop_buffer_from_bpf();
                goto cleanup;
        }

        bo = create_buffer(bind->file, bind->handle);

        consume_buffer_from_bpf_into_bo(bo);

        if ((!bo->buff) || (!bo->buff_sz)) {
                release_buffer(bo);
                WARN("execbuf_end didn't get a batchbuffer bb_offset=0x%llx.\n", info->bb_offset);
                goto cleanup;
        }

        release_buffer(bo);

        /* Parse the batchbuffer */
        clock_gettime(CLOCK_MONOTONIC, &parser_start);
        bb_parser_init(&parser);
        bb_parser_parse(&parser, vm, bind, info->batch_start_offset,
                        info->batch_len, info->pid, info->tid, &info->stack, &info->kernel_stack, info->name);
        clock_gettime(CLOCK_MONOTONIC, &parser_end);
        if (debug) {
                debug_printf("Parsed %zu dwords in %.5f seconds.\n",
                        parser.num_dwords,
                        ((double)parser_end.tv_sec +
                        1.0e-9 * parser_end.tv_nsec) -
                                ((double)parser_start.tv_sec +
                                1.0e-9 * parser_start.tv_nsec));
        }
        if (parser.iba) {
/*                 assert(iba == 0 && "iba is already set"); */
                if (!iba) {
                        iba = parser.iba;
                        wakeup_eustall_deferred_attrib_thread();
                }
        }

cleanup:
        if (vm != NULL) {
                release_vm_profile(vm);
        }

        return 0;
}

/* Runs each time a sample from the ringbuffer is collected. */
static int handle_sample(void *ctx, void *data_arg, size_t data_sz)
{
/*         print_buffer_profiles(); */

        uint8_t type;

        type = *((uint8_t*)data_arg);

        switch (type) {
                case BPF_EVENT_TYPE_MAPPING:       return 0; /* return handle_mapping(data_arg); */
                case BPF_EVENT_TYPE_UNMAP:         return handle_unmap(data_arg);
                case BPF_EVENT_TYPE_VM_CREATE:     return handle_vm_create(data_arg);
                case BPF_EVENT_TYPE_VM_BIND:       return handle_vm_bind(data_arg);
                case BPF_EVENT_TYPE_VM_UNBIND:     return handle_vm_unbind(data_arg);
                case BPF_EVENT_TYPE_EXECBUF_END:   return handle_execbuf_end(data_arg);
                case BPF_EVENT_TYPE_BATCHBUFFER:   return handle_batchbuffer(data_arg);
                case BPF_EVENT_TYPE_USERPTR:       return handle_userptr(data_arg);
                case BPF_EVENT_TYPE_DEBUG_AREA:       return handle_debug_area(data_arg);
        }

        ERR("Unknown data type when handling a sample: %u\n", type);
        return -1;
}

/***************************************
* BPF Setup
***************************************/

int attach_kprobe(const char *func, struct bpf_program *prog, int ret)
{
        struct bpf_kprobe_opts opts;

        bpf_info.num_links++;
        bpf_info.links = realloc(bpf_info.links, sizeof(struct bpf_link *) *
                                                         bpf_info.num_links);
        if (!bpf_info.links) {
                ERR("Failed to allocate memory for the BPF links! Aborting.\n");
                return -1;
        }

        /* XXX: Experiment with attach_mode parameter.
           Set it to PROBE_ATTACH_MODE_LEGACY so that we can check
           the number of events that we missed.
        */
        memset(&opts, 0, sizeof(opts));
        opts.retprobe = ret;
        opts.sz = sizeof(opts);
        opts.attach_mode = PROBE_ATTACH_MODE_DEFAULT;
        bpf_info.links[bpf_info.num_links - 1] =
                bpf_program__attach_kprobe_opts(prog, func, &opts);
        if (libbpf_get_error(bpf_info.links[bpf_info.num_links - 1])) {
                ERR("Failed to attach the BPF program to a kprobe: %s\n", func);
                /* Set this pointer to NULL, since it's undefined what it will be */
                bpf_info.links[bpf_info.num_links - 1] = NULL;
                return -1;
        }

        return 0;
}

int attach_tracepoint(const char *category, const char *func,
                      struct bpf_program *prog)
{
        bpf_info.num_links++;
        bpf_info.links = realloc(bpf_info.links, sizeof(struct bpf_link *) *
                                                         bpf_info.num_links);
        if (!bpf_info.links) {
                fprintf(stderr,
                        "Failed to allocate memory for the BPF links! Aborting.\n");
                return -1;
        }
        bpf_info.links[bpf_info.num_links - 1] =
                bpf_program__attach_tracepoint(prog, category, func);
        if (libbpf_get_error(bpf_info.links[bpf_info.num_links - 1])) {
                ERR("Failed to attach the BPF program to a tracepoint: %s:%s\n",
                    category, func);
                /* Set this pointer to NULL, since it's undefined what it will be */
                bpf_info.links[bpf_info.num_links - 1] = NULL;
                return -1;
        }

        return 0;
}

int deinit_bpf_i915()
{
        uint64_t i;
        int retval;
        size_t ring_buffer_avail;
        struct ring *ring;

        ring = ring_buffer__ring(bpf_info.rb, 0);
        ring_buffer_avail = ring__avail_data_size(ring);
        debug_printf("Leftover ringbuffer size: %lu\n", ring_buffer_avail);
        ring = ring_buffer__ring(bpf_info.buffer_copy_rb, 0);
        ring_buffer_avail = ring__avail_data_size(ring);
        debug_printf("Leftover buffer copy ringbuffer size: %lu\n", ring_buffer_avail);

        for (i = 0; i < bpf_info.num_links; i++) {
                retval = bpf_link__destroy(bpf_info.links[i]);
                if (retval == -1) {
                        return retval;
                }
        }
        free(bpf_info.links);

        main_bpf__destroy(bpf_info.obj);

        return 0;
}

int init_bpf_i915()
{
        int err;

        bpf_info.obj = main_bpf__open_and_load();
        if (!bpf_info.obj) {
                ERR("Failed to get BPF object.\n"
                    "       Most likely, one of two things are true:\n"
                    "       1. You're not root.\n"
                    "       2. You don't have a kernel that supports BTF type information.\n");
                return -1;
        }

        err = main_bpf__attach(bpf_info.obj);
        if (err) {
                ERR("Failed to attach BPF programs.\n");
                return -1;
        }

        bpf_info.rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.rb),
                                       handle_sample, NULL, NULL);
        if (!(bpf_info.rb)) {
                ERR("Failed to create a new ring buffer. You're most likely not root.\n");
                return -1;
        }

        bpf_info.buffer_copy_rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.buffer_copy_rb),
                                       handle_buffer_copy, NULL, NULL);
        if (!(bpf_info.buffer_copy_rb)) {
                ERR("Failed to create a new ring buffer. You're most likely not root.\n");
                return -1;
        }

        bpf_info.rb_fd = bpf_map__fd(bpf_info.obj->maps.rb);
        bpf_info.buffer_copy_rb_fd = bpf_map__fd(bpf_info.obj->maps.buffer_copy_rb);
        bpf_info.epoll_fd = ring_buffer__epoll_fd(bpf_info.rb);
        bpf_info.dropped_event = &(bpf_info.obj->bss->dropped_event);

        return 0;
}

/*******************
*      DEBUG       *
*******************/
void print_ringbuf_stats()
{
        uint64_t size, avail;

        avail = ring__avail_data_size(ring_buffer__ring(bpf_info.rb, 0));
        size = ring__size(ring_buffer__ring(bpf_info.rb, 0));
        debug_printf("GEM ringbuf usage: %lu / %lu\n", avail, size);
}
