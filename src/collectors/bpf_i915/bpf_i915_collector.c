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
#include <fcntl.h>

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
#include "utils/hash_table.h"

uint32_t global_vm_id = 0;
static uint32_t vm_bind_bpf_counter = 0;

struct live_execbuf {
        uint64_t    eb_id;
        uint64_t    file;
        uint32_t    vm_id;
        uint32_t    pid;
        char        name[TASK_COMM_LEN];
        const char *ustack_str;
        const char *kstack_str;
};
typedef struct live_execbuf live_execbuf_struct;

static uint64_t hash_eb_id(uint64_t eb_id) { return eb_id; }

use_hash_table(uint64_t, live_execbuf_struct);

static hash_table(uint64_t, live_execbuf_struct) live_execbufs;

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

int handle_execbuf(void *data_arg)
{
        struct execbuf_info *info;
        struct live_execbuf *existing;
        struct live_execbuf  live;

        info = (struct execbuf_info *)data_arg;

        print_execbuf(info);

        existing = hash_table_get_val(live_execbufs, info->eb_id);
        if (existing != NULL) {
                ERR("execbuf info eb_id already seen, eb_id = %llu", info->eb_id);
        }

        live.file       = info->file;
        live.vm_id      = info->vm_id;
        live.pid        = info->pid;
        memcpy(live.name, info->name, TASK_COMM_LEN);
        live.ustack_str = store_ustack(info->pid, &info->ustack);
        live.kstack_str = store_kstack(&info->kstack);

        hash_table_insert(live_execbufs, info->eb_id, live);

        return 0;
}

int handle_execbuf_end(void *data_arg)
{
        struct execbuf_end_info *info;
        struct live_execbuf     *live;

        info = (struct execbuf_end_info *)data_arg;

        live = hash_table_get_val(live_execbufs, info->eb_id);
        if (live == NULL) {
                ERR("execbuf_end for eb_info we've never seen, eb_id = %llu", info->eb_id);
                return 0;
        }

        hash_table_delete(live_execbufs, info->eb_id);

        return 0;
}


int handle_iba(void *data_arg)
{
        struct iba_info       *info;
        struct live_execbuf   *exec;
        struct vm_profile     *vm;
        struct buffer_binding *bind;

        if (iba) { return 0; }

        info = (struct iba_info *)data_arg;
        debug_printf("  IBA: 0x%llx\n", info->addr);
        iba = info->addr;

        exec = hash_table_get_val(live_execbufs, info->eb_id);
        if (exec == NULL) {
                ERR("IBA for exec that is not live");
                return 0;
        }

        /* Debug Area should be in VM 1 */
        vm = acquire_vm_profile(exec->file, 1);
        if (vm == NULL) {
                WARN("Unable to find a vm_profile for vm_id=%u\n",
                     1);
                return 0;
        }

        bind = get_containing_binding(vm, iba);
        if (bind != NULL) {
                bind->type = BUFFER_TYPE_DEBUG_AREA;
                memcpy(bind->name, exec->name, TASK_COMM_LEN);
                debug_printf("  Marked buffer as a Debug Area: vm_id=%u gpu_addr=0x%lx\n",
                                1, bind->gpu_addr);
        }

        release_vm_profile(vm);

        wakeup_eustall_deferred_attrib_thread();

        return 0;
}

int handle_ksp(void *data_arg)
{
        struct ksp_info       *info;
        struct live_execbuf   *exec;
        struct vm_profile     *vm;
        struct buffer_binding *shader_bind;

        info = (struct ksp_info *)data_arg;
        exec = hash_table_get_val(live_execbufs, info->eb_id);
        if (exec == NULL) {
                ERR("KSP for exec that is not live");
                return 0;
        }

        vm = acquire_vm_profile(exec->file, exec->vm_id);
        if (vm == NULL) {
                WARN("Unable to find a vm_profile for vm_id=%u\n",
                     exec->vm_id);
                return 0;
        }

        shader_bind = get_containing_binding(vm, iba + info->addr);
        if (shader_bind != NULL) {
                shader_bind->type               = BUFFER_TYPE_SHADER;
                shader_bind->pid                = exec->pid;
                shader_bind->execbuf_ustack_str = exec->ustack_str;
                shader_bind->execbuf_kstack_str = exec->kstack_str;
                memcpy(shader_bind->name, exec->name, TASK_COMM_LEN);
                debug_printf("  Marked buffer as a shader: vm_id=%u gpu_addr=0x%lx\n",
                                vm->vm_id, shader_bind->gpu_addr);
        } else {
                debug_printf("  Did not find the shader for gpu_addr=0x%llx\n", iba + info->addr);
        }

        release_vm_profile(vm);

        wakeup_eustall_deferred_attrib_thread();

        return 0;
}

int handle_sip(void *data_arg)
{
        struct sip_info       *info;
        struct live_execbuf   *exec;
        struct vm_profile     *vm;
        struct buffer_binding *shader_bind;

        info = (struct sip_info *)data_arg;
        exec = hash_table_get_val(live_execbufs, info->eb_id);
        if (exec == NULL) {
                ERR("SIP for exec that is not live");
                return 0;
        }

        vm = acquire_vm_profile(exec->file, exec->vm_id);
        if (vm == NULL) {
                WARN("Unable to find a vm_profile for vm_id=%u\n",
                     exec->vm_id);
                return 0;
        }

        shader_bind = get_containing_binding(vm, iba + info->addr);
        if (shader_bind != NULL) {
                shader_bind->type               = BUFFER_TYPE_SYSTEM_ROUTINE;
                shader_bind->pid                = exec->pid;
                shader_bind->execbuf_ustack_str = exec->ustack_str;
                shader_bind->execbuf_kstack_str = exec->kstack_str;
                memcpy(shader_bind->name, exec->name, TASK_COMM_LEN);
                debug_printf("  Marked buffer as a SIP shader: vm_id=%u gpu_addr=0x%lx\n",
                                vm->vm_id, shader_bind->gpu_addr);
        } else {
                debug_printf("  Did not find the SIP shader for gpu_addr=0x%llx\n", iba + info->addr);
        }

        release_vm_profile(vm);

        return 0;
}

/* Runs each time a sample from the ringbuffer is collected. */
static int handle_sample(void *ctx, void *data_arg, size_t data_sz)
{
        uint8_t type;

        type = *((uint8_t*)data_arg);

        switch (type) {
                case BPF_EVENT_TYPE_VM_CREATE:   return handle_vm_create(data_arg);
                case BPF_EVENT_TYPE_VM_BIND:     return handle_vm_bind(data_arg);
                case BPF_EVENT_TYPE_VM_UNBIND:   return handle_vm_unbind(data_arg);
                case BPF_EVENT_TYPE_EXECBUF:     return handle_execbuf(data_arg);
                case BPF_EVENT_TYPE_EXECBUF_END: return handle_execbuf_end(data_arg);
                case BPF_EVENT_TYPE_IBA:         return handle_iba(data_arg);
                case BPF_EVENT_TYPE_KSP:         return handle_ksp(data_arg);
                case BPF_EVENT_TYPE_SIP:         return handle_sip(data_arg);
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
        int err, stack_limit;
        FILE *file;

        /* Check the value of kernel.perf_event_max_stack */
        stack_limit = 127;
        file = fopen("/proc/sys/kernel/perf_event_max_stack", "r");
        if (file) {
                /* If we're able to read it from /proc, set it to that
                   value. To be safe, just default to a typical value that
                   we've seen (127). */
                fscanf(file, "%d", &stack_limit);
                fclose(file);
        }
        fprintf(stderr, "Stack limit is now: %d\n", stack_limit);

        bpf_info.stackmap_fd = bpf_map_create(BPF_MAP_TYPE_STACK_TRACE,
                                 "stackmap", 4, sizeof(uintptr_t) * stack_limit,
                                 1<<14, 0);

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


        live_execbufs = hash_table_make(uint64_t, live_execbuf_struct, hash_eb_id);


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
