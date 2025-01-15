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

#include "bpf/main.h"
#include "bpf/main.skel.h"
#include "bpf_i915_collector.h"
#include "collectors/debug_i915/debug_i915_collector.h"

#include "utils/utils.h"

uint32_t global_vm_id = 0;
static uint32_t vm_bind_bpf_counter = 0;

/***************************************
* BPF Handlers
***************************************/

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

        info = (struct vm_bind_info *)data_arg;
        if (verbose) {
                print_vm_bind(info, vm_bind_bpf_counter);
        }

#ifdef SLOW_MODE
        if (debug_collector) {
                pthread_mutex_lock(&debug_i915_vm_bind_lock);
        }
#endif

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

        release_vm_profile(vm);

cleanup:

#ifdef SLOW_MODE
        if (debug_collector) {

                /* @TODO: Wait until bpf ring buffer is emtpy. */

                /* Signal the debug_i915 collector that there's a new vm_bind event */
                pthread_cond_signal(&debug_i915_vm_bind_cond);
        }
        pthread_mutex_unlock(&debug_i915_vm_bind_lock);
#endif

        vm_bind_bpf_counter++;

#ifndef XE_DRIVER
        wakeup_eustall_deferred_attrib_thread();
#endif

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

int handle_execbuf(void *data_arg)
{
        struct execbuf_info   *info;
        const char            *ustack_str;
        const char            *kstack_str;
        struct vm_profile     *vm;
        struct buffer_binding *shader_bind;

        info = (struct execbuf_info *)data_arg;

        print_execbuf(info);

        ustack_str = store_ustack(info->pid, &info->ustack);
        kstack_str = store_kstack(&info->kstack);

        vm = acquire_vm_profile(info->file, info->vm_id);
        if (vm == NULL) {
                WARN("Unable to find a vm_profile for vm_id=%u\n",
                     info->vm_id);
                goto cleanup;
        }

        if (info->iba && !iba) {
                debug_printf("  IBA: 0x%llx\n", info->iba);
                iba = info->iba;
        }
        if (info->ksp) {
                shader_bind = get_containing_binding(vm, iba + info->ksp);
                if (shader_bind != NULL) {
                        shader_bind->type               = BUFFER_TYPE_SHADER;
                        shader_bind->pid                = info->pid;
                        shader_bind->execbuf_ustack_str = ustack_str;
                        shader_bind->execbuf_kstack_str = kstack_str;
                        memcpy(shader_bind->name, info->name, TASK_COMM_LEN);
                        debug_printf("  Marked buffer as a shader: vm_id=%u gpu_addr=0x%lx\n",
                                     vm->vm_id, shader_bind->gpu_addr);
                } else {
                        debug_printf("  Did not find the shader for gpu_addr=0x%llx\n", iba + info->ksp);
                }
        }
        if (info->sip) {
                shader_bind = get_containing_binding(vm, iba + info->sip);
                if (shader_bind != NULL) {
                        shader_bind->type               = BUFFER_TYPE_SYSTEM_ROUTINE;
                        shader_bind->pid                = info->pid;
                        shader_bind->execbuf_ustack_str = ustack_str;
                        shader_bind->execbuf_kstack_str = kstack_str;
                        memcpy(shader_bind->name, info->name, TASK_COMM_LEN);
                        debug_printf("  Marked buffer as a SIP shader: vm_id=%u gpu_addr=0x%lx\n",
                                     vm->vm_id, shader_bind->gpu_addr);
                } else {
                        debug_printf("  Did not find the SIP shader for gpu_addr=0x%llx\n", iba + info->sip);
                }
        }

cleanup:;
        if (vm != NULL) {
                release_vm_profile(vm);
        }

        return 0;
}

/* Runs each time a sample from the ringbuffer is collected. */
static int handle_sample(void *ctx, void *data_arg, size_t data_sz)
{
        uint8_t type;

        type = *((uint8_t*)data_arg);

        switch (type) {
                case BPF_EVENT_TYPE_VM_CREATE:  return handle_vm_create(data_arg);
                case BPF_EVENT_TYPE_VM_BIND:    return handle_vm_bind(data_arg);
                case BPF_EVENT_TYPE_VM_UNBIND:  return handle_vm_unbind(data_arg);
                case BPF_EVENT_TYPE_DEBUG_AREA: return handle_debug_area(data_arg);
                case BPF_EVENT_TYPE_EXECBUF:    return handle_execbuf(data_arg);
        }

        ERR("Unknown data type when handling a sample: %u\n", type);
        return -1;
}

/***************************************
* BPF Setup
***************************************/

int deinit_bpf_i915()
{
        uint64_t i;
        int retval;
        size_t ring_buffer_avail;
        struct ring *ring;

        ring = ring_buffer__ring(bpf_info.rb, 0);
        ring_buffer_avail = ring__avail_data_size(ring);
        debug_printf("Leftover ringbuffer size: %lu\n", ring_buffer_avail);

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

        bpf_info.rb_fd = bpf_map__fd(bpf_info.obj->maps.rb);
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
