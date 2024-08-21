/***************************************
* Event Collector
***************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <pthread.h>
#include <time.h>

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

/***************************************
* BPF Handlers
***************************************/

#if 0
/* Handles `struct mapping_info`, which comes from
   `mmap` calls. Includes a CPU pointer. */
int handle_mapping(void *data_arg)
{
        struct buffer_profile *gem;
        int mapping_index, vm_bind_index, index;
        struct mapping_info *info;

        if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
                fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
                return -1;
        }

        info = (struct mapping_info *)data_arg;
        if (verbose) {
                print_mapping(info);
        }

        /* Use an existing buffer_profile if available */
        index = get_buffer_profile_by_mapping(info->file, info->handle);
        if (index == -1) {
                index = grow_buffer_profiles();
        }

        gem = &buffer_profile_arr[index];
        gem->cpu_addr = info->cpu_addr;
        gem->handle = info->handle;
        gem->file = info->file;
        gem->mapped = 1;

        if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
                fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
                return -1;
        }

        return 0;
}
#endif

int handle_unmap(void *data_arg)
{
        return 0;

#if 0
        struct unmap_info *info;
        int index, retval;
        struct buffer_profile *gem;

        retval = 0;
        if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
                fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
                return -1;
        }

        info = (struct unmap_info *)data_arg;
        if (verbose) {
                print_unmap(info);
        }

        index = get_buffer_profile_by_mapping(info->file, info->handle);
        if (index == -1) {
                if (debug ) {
                        fprintf(stderr,
                                "WARNING: unmap called on handle %u without an mmap.\n",
                                info->handle);
                }
                goto cleanup;
        }
        gem = &(buffer_profile_arr[index]);
        gem->mapped = 0;

        handle_binary(&(gem->buff), info->buff, &(gem->buff_sz), info->size, gem->handle);

        if (retval == -1) {
                goto cleanup;
        }

cleanup:
        if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
                fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
                return -1;
        }
        return retval;
#endif
}

int handle_request(void *data_arg)
{
        struct request_info *info;

        info = (struct request_info *)data_arg;
        if (verbose) {
                print_request(info);
        }

        if (info->request_type == REQUEST_SUBMIT) {
                /* Store this request per-VM */
                if (global_vm_id == 0) {
                        fprintf(stderr,
                                "WARNING: global_vm_id is zero. Something fishy is going on.\n");
                        return -1;
                }
                request_submit(global_vm_id, info->seqno, info->gem_ctx, info->class, info->instance);
        } else if (info->request_type == REQUEST_RETIRE) {
                request_retire(info->seqno, info->gem_ctx);
        }

        return 0;
}

int handle_userptr(void *data_arg)
{
        struct userptr_info *info;

        info = (struct userptr_info *)data_arg;
        if (verbose) {
                print_userptr(info);
        }

        return 0;
}

int handle_vm_create(void *data_arg)
{
        struct vm_create_info *info;

        info = (struct vm_create_info *)data_arg;
        if (verbose) {
                print_vm_create(info);
        }

        create_vm_profile(info->vm_id);

        if (gpu_syms) {
                /* Register the PID with the debug_i915 collector */
                init_debug_i915(devinfo.fd, info->pid);
        }

        return 0;
}

int handle_vm_bind(void *data_arg)
{
        struct vm_bind_info *info;
        struct buffer_profile *gem;

        info = (struct vm_bind_info *)data_arg;
        if (verbose) {
                print_vm_bind(info);
        }

        gem = get_or_create_buffer_profile(info->vm_id, info->gpu_addr);
        gem->bind_size = info->size;
        gem->pid = info->pid;

        return 0;
}

int handle_vm_unbind(void *data_arg)
{
        struct vm_unbind_info *info;
        struct buffer_profile *gem;

        info = (struct vm_unbind_info *)data_arg;
        if (verbose) {
                print_vm_unbind(info);
        }

        gem = get_buffer_profile(info->vm_id, info->gpu_addr);
        if (gem == NULL) {
                if (debug) {
                        fprintf(stderr,
                                "WARNING: Got a vm_unbind on gpu_addr=0x%llx for which there wasn't a vm_bind!\n",
                                info->gpu_addr);
                }
                goto cleanup;
        }

        gem->unbound = 1;

cleanup:
        return 0;
}

int handle_batchbuffer(void *data_arg)
{
        struct batchbuffer_info *info;
        struct buffer_profile *gem;

        info = (struct batchbuffer_info *)data_arg;

        if (verbose) {
                print_batchbuffer(info);
        }
        
        /* Find the buffer that this batchbuffer is associated with */
        gem = get_buffer_profile(info->vm_id, info->gpu_addr);
        if (gem == NULL) {
                if (debug ) {
                        fprintf(stderr,
                                "WARNING: couldn't find a buffer to store the batchbuffer in.\n");
                }
                goto cleanup;
        }

        handle_binary(&(gem->buff), info->buff, &(gem->buff_sz),
                      info->buff_sz);

cleanup:
        return 0;
}

int handle_execbuf_start(void *data_arg)
{
        struct buffer_profile *gem;
        uint64_t file;
        uint32_t vm_id, pid;
        struct execbuf_start_info *info;
        struct bb_parser parser;
        struct timespec parser_start, parser_end;

        info = (struct execbuf_start_info *)data_arg;
        if (verbose) {
                print_execbuf_start(info);
        }

        /* Store this vm_id so that requests that get created by this
           execbuffer call can associate themselves with it */
        global_vm_id = info->vm_id;

        /* This execbuffer call needs to be associated with all GEMs that
           are referenced by this call. Buffers can be referenced in two ways:
           1. Directly in the execbuffer call.
           2. Through the ctx_id (which has an associated vm_id).

           Here, we'll iterate over all buffers in the given vm_id. */
        vm_id = info->vm_id;
        pid = info->pid;
        file = info->file;
        FOR_BUFFER_PROFILE(gem, {
                if (gem->vm_id == vm_id) {
                        /* Store the execbuf information */
                        memcpy(gem->name, info->name, TASK_COMM_LEN);
                        gem->time = info->time;
                        gem->cpu = info->cpu;
                        gem->tid = info->tid;
                        gem->ctx_id = info->ctx_id;

                        if (verbose) {
                                print_execbuf_gem(gem);
                        }

                        /* Store the stack */
                        if (gem->execbuf_stack_str == NULL) {
                                store_stack(info->pid, info->stackid,
                                            &(gem->execbuf_stack_str));
                        }
                }
        });

        gem = get_buffer_profile(vm_id, info->bb_offset);
        if (gem == NULL) {
                fprintf(stderr,
                        "WARNING: Unable to find a buffer that matches 0x%llx\n",
                        info->bb_offset);
                goto cleanup;
        }

        /* Copy the batchbuffer that we got from the ringbuffer */
        if (info->buff_sz == 0) {
                /* We didn't get a copy of the batchbuffer from BPF! */
                goto cleanup;
        }
        if (handle_binary(&(gem->buff), info->buff, &(gem->buff_sz),
                      info->buff_sz) != 0) {

                fprintf(stderr,
                        "WARNING: handle_binary() returned non-zero\n");
                goto cleanup;
        }

        if ((!gem->buff) || (!gem->buff_sz)) {
                goto cleanup;
        }

        /* Parse the batchbuffer */
        clock_gettime(CLOCK_MONOTONIC, &parser_start);
        memset(&parser, 0, sizeof(struct bb_parser));
        bb_parser_parse(&parser, gem, info->batch_start_offset,
                        info->batch_len);
        clock_gettime(CLOCK_MONOTONIC, &parser_end);
        if (verbose) {
                printf("Parsed %zu dwords in %.5f seconds.\n",
                        parser.num_dwords,
                        ((double)parser_end.tv_sec +
                        1.0e-9 * parser_end.tv_nsec) -
                                ((double)parser_start.tv_sec +
                                1.0e-9 * parser_start.tv_nsec));
        }
        if (parser.iba) {
                iba = parser.iba;
        }

cleanup:
        if (iba) {
                FOR_BUFFER_PROFILE(gem, {
                        if ((gem->vm_id == vm_id) &&
                            (gem->pid == pid) &&
                            (gem->file == file)) {
                                gem->iba = iba;
                        }
                });
        }

        return 0;
}

int handle_execbuf_end(void *data_arg)
{
        struct execbuf_end_info *info;
        struct buffer_profile *gem;

        /* First, just print out the execbuf_end */
        info = (struct execbuf_end_info *)data_arg;
        if (verbose) {
                print_execbuf_end(info);
        }

        gem = get_buffer_profile(info->vm_id, info->gpu_addr);
        if (gem == NULL) {
                fprintf(stderr,
                        "WARNING: Unable to find a buffer that matches 0x%llx\n",
                        info->gpu_addr);
                goto cleanup;
        }

        /* Copy the batchbuffer that we got from the ringbuffer */
        if (info->buff_sz == 0) {
                goto cleanup;
        }
        handle_binary(&(gem->buff), info->buff, &(gem->buff_sz),
                      info->buff_sz);

cleanup:
        return 0;
}

/* Runs each time a sample from the ringbuffer is collected. */
static int handle_sample(void *ctx, void *data_arg, size_t data_sz)
{
/*         print_buffer_profiles(); */

        uint8_t type;

        type = *((uint8_t*)data_arg);

        switch (type) {
/*                 case BPF_EVENT_TYPE_MAPPING:       return handle_mapping(data_arg); */
                case BPF_EVENT_TYPE_UNMAP:         return handle_unmap(data_arg);
                case BPF_EVENT_TYPE_VM_CREATE:     return handle_vm_create(data_arg);
                case BPF_EVENT_TYPE_VM_BIND:       return handle_vm_bind(data_arg);
                case BPF_EVENT_TYPE_VM_UNBIND:     return handle_vm_unbind(data_arg);
                case BPF_EVENT_TYPE_EXECBUF_START: return handle_execbuf_start(data_arg);
                case BPF_EVENT_TYPE_EXECBUF_END:   return handle_execbuf_end(data_arg);
                case BPF_EVENT_TYPE_BATCHBUFFER:   return handle_batchbuffer(data_arg);
                case BPF_EVENT_TYPE_USERPTR:       return handle_userptr(data_arg);
                case BPF_EVENT_TYPE_REQUEST:       return handle_request(data_arg);
        }

        fprintf(stderr,
                "Unknown data type when handling a sample: %u\n",
                type);
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
                fprintf(stderr,
                        "Failed to allocate memory for the BPF links! Aborting.\n");
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
                fprintf(stderr,
                        "Failed to attach the BPF program to a kprobe: %s\n",
                        func);
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
                fprintf(stderr,
                        "Failed to attach the BPF program to a tracepoint: %s:%s\n",
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

        for (i = 0; i < bpf_info.num_links; i++) {
                retval = bpf_link__destroy(bpf_info.links[i]);
                if (retval == -1) {
                        return retval;
                }
        }
        free(bpf_info.links);

        bpf_program__unload(bpf_info.mmap_ioctl_prog);
        bpf_program__unload(bpf_info.mmap_ioctl_ret_prog);

        bpf_program__unload(bpf_info.mmap_offset_ioctl_prog);
        bpf_program__unload(bpf_info.mmap_offset_ioctl_ret_prog);
        bpf_program__unload(bpf_info.mmap_prog);
        bpf_program__unload(bpf_info.mmap_ret_prog);

        bpf_program__unload(bpf_info.vm_create_ioctl_prog);
        bpf_program__unload(bpf_info.vm_create_ioctl_ret_prog);

        bpf_program__unload(bpf_info.vm_bind_ioctl_prog);
        bpf_program__unload(bpf_info.vm_bind_ioctl_ret_prog);

        bpf_program__unload(bpf_info.vm_unbind_ioctl_prog);

        bpf_program__unload(bpf_info.context_create_ioctl_prog);
        bpf_program__unload(bpf_info.context_create_ioctl_ret_prog);

        bpf_program__unload(bpf_info.do_execbuffer_prog);
        bpf_program__unload(bpf_info.do_execbuffer_ret_prog);

        bpf_program__unload(bpf_info.munmap_prog);

        bpf_program__unload(bpf_info.request_submit_prog);
        bpf_program__unload(bpf_info.request_retire_prog);
        bpf_program__unload(bpf_info.request_in_prog);
        bpf_program__unload(bpf_info.request_out_prog);
        
        main_bpf__destroy(bpf_info.obj);

        return 0;
}

int init_bpf_i915()
{
        int err;
        struct bpf_object_open_opts opts = { 0 };

        opts.sz = sizeof(struct bpf_object_open_opts);
#if 0
  if(pw_opts.btf_custom_path) {
    opts.btf_custom_path = pw_opts.btf_custom_path;
  }
#endif

        bpf_info.obj = main_bpf__open_opts(&opts);
        if (!bpf_info.obj) {
                fprintf(stderr, "ERROR: Failed to get BPF object.\n");
                fprintf(stderr,
                        "       Most likely, one of two things are true:\n");
                fprintf(stderr, "       1. You're not root.\n");
                fprintf(stderr,
                        "       2. You don't have a kernel that supports BTF type information.\n");
                return -1;
        }
        err = main_bpf__load(bpf_info.obj);
        if (err) {
                fprintf(stderr, "Failed to load BPF object!\n");
                return -1;
        }

        bpf_info.mmap_ioctl_prog =
                (struct bpf_program *)bpf_info.obj->progs.mmap_ioctl_kprobe;
        bpf_info.mmap_ioctl_ret_prog =
                (struct bpf_program *)bpf_info.obj->progs.mmap_ioctl_kretprobe;

        bpf_info.mmap_offset_ioctl_prog =
                (struct bpf_program *)
                        bpf_info.obj->progs.mmap_offset_ioctl_kprobe;
        bpf_info.mmap_offset_ioctl_ret_prog =
                (struct bpf_program *)
                        bpf_info.obj->progs.mmap_offset_ioctl_kretprobe;
        bpf_info.mmap_prog =
                (struct bpf_program *)bpf_info.obj->progs.mmap_kprobe;
        bpf_info.mmap_ret_prog =
                (struct bpf_program *)bpf_info.obj->progs.mmap_kretprobe;

        bpf_info.userptr_ioctl_prog =
                (struct bpf_program *)bpf_info.obj->progs.userptr_ioctl_kprobe;
        bpf_info.userptr_ioctl_ret_prog =
                (struct bpf_program *)
                        bpf_info.obj->progs.userptr_ioctl_kretprobe;

        bpf_info.vm_create_ioctl_prog =
                (struct bpf_program *)bpf_info.obj->progs.vm_create_ioctl_kprobe;
        bpf_info.vm_create_ioctl_ret_prog =
                (struct bpf_program *)bpf_info.obj->progs.vm_create_ioctl_kretprobe;

        bpf_info.vm_bind_ioctl_prog =
                (struct bpf_program *)bpf_info.obj->progs.vm_bind_ioctl_kprobe;
        bpf_info.vm_bind_ioctl_ret_prog =
                (struct bpf_program *)
                        bpf_info.obj->progs.vm_bind_ioctl_kretprobe;

        bpf_info.vm_unbind_ioctl_prog =
                (struct bpf_program *)bpf_info.obj->progs.vm_unbind_ioctl_kprobe;

        bpf_info.context_create_ioctl_prog =
                (struct bpf_program *)
                        bpf_info.obj->progs.context_create_ioctl_kprobe;
        bpf_info.context_create_ioctl_ret_prog =
                (struct bpf_program *)
                        bpf_info.obj->progs.context_create_ioctl_kretprobe;

        bpf_info.do_execbuffer_prog =
                (struct bpf_program *)bpf_info.obj->progs.do_execbuffer_kprobe;
        bpf_info.do_execbuffer_ret_prog =
                (struct bpf_program *)
                        bpf_info.obj->progs.do_execbuffer_kretprobe;

        bpf_info.request_submit_prog =
                (struct bpf_program *)bpf_info.obj->progs.request_submit_tp;
        bpf_info.request_retire_prog =
                (struct bpf_program *)bpf_info.obj->progs.request_retire_tp;
        bpf_info.request_in_prog =
                (struct bpf_program *)bpf_info.obj->progs.request_in_tp;
        bpf_info.request_out_prog =
                (struct bpf_program *)bpf_info.obj->progs.request_out_tp;

        bpf_info.munmap_prog =
                (struct bpf_program *)bpf_info.obj->progs.munmap_tp;

        bpf_info.rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.rb),
                                       handle_sample, NULL, NULL);
        if (!(bpf_info.rb)) {
                fprintf(stderr,
                        "Failed to create a new ring buffer. You're most likely not root.\n");
                return -1;
        }

        bpf_info.rb_fd = bpf_map__fd(bpf_info.obj->maps.rb);
        bpf_info.epoll_fd = ring_buffer__epoll_fd(bpf_info.rb);

        /* i915_gem_mmap_ioctl */
        err = attach_kprobe("i915_gem_mmap_ioctl", bpf_info.mmap_ioctl_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_mmap_ioctl", bpf_info.mmap_ioctl_ret_prog,
                            1);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }

        /* i915_gem_mmap_offset_ioctl and friends */
        err = attach_kprobe("i915_gem_mmap_offset_ioctl",
                            bpf_info.mmap_offset_ioctl_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_mmap_offset_ioctl",
                            bpf_info.mmap_offset_ioctl_ret_prog, 1);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_mmap", bpf_info.mmap_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_mmap", bpf_info.mmap_ret_prog, 1);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }

        /* i915_gem_userptr_ioctl */
        err = attach_kprobe("i915_gem_userptr_ioctl",
                            bpf_info.userptr_ioctl_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_userptr_ioctl",
                            bpf_info.userptr_ioctl_ret_prog, 1);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }

        /* i915_gem_vm_create_ioctl */
        err = attach_kprobe("i915_gem_vm_create_ioctl",
                            bpf_info.vm_create_ioctl_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_vm_create_ioctl",
                            bpf_info.vm_create_ioctl_ret_prog, 1);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }

        /* i915_gem_vm_bind_ioctl */
        err = attach_kprobe("i915_gem_vm_bind_ioctl",
                            bpf_info.vm_bind_ioctl_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_vm_bind_ioctl",
                            bpf_info.vm_bind_ioctl_ret_prog, 1);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }

        /* i915_gem_vm_unbind_ioctl */
        err = attach_kprobe("i915_gem_vm_unbind_ioctl",
                            bpf_info.vm_unbind_ioctl_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }

        /* i915_gem_context_create_ioctl */
        err = attach_kprobe("i915_gem_context_create_ioctl",
                            bpf_info.context_create_ioctl_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_context_create_ioctl",
                            bpf_info.context_create_ioctl_ret_prog, 1);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }

        /* i915_gem_do_execbuffer */
        err = attach_kprobe("i915_gem_do_execbuffer",
                            bpf_info.do_execbuffer_prog, 0);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }
        err = attach_kprobe("i915_gem_do_execbuffer",
                            bpf_info.do_execbuffer_ret_prog, 1);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a kprobe!\n");
                return -1;
        }

        /* munmap */
        err = attach_tracepoint("syscalls", "sys_enter_munmap",
                                bpf_info.munmap_prog);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a tracepoint!\n");
                return -1;
        }

        /* requests */
        err = attach_tracepoint("i915", "i915_request_submit",
                                bpf_info.request_submit_prog);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a tracepoint!\n");
                return -1;
        }
        err = attach_tracepoint("i915", "i915_request_retire",
                                bpf_info.request_retire_prog);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a tracepoint!\n");
                return -1;
        }
        err = attach_tracepoint("i915", "i915_request_in",
                                bpf_info.request_in_prog);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a tracepoint!\n");
                return -1;
        }
        err = attach_tracepoint("i915", "i915_request_out",
                                bpf_info.request_out_prog);
        if (err != 0) {
                fprintf(stderr, "Failed to attach a tracepoint!\n");
                return -1;
        }

        /* XXX: Finish vm_close support in BPF and re-enable. This should
     free up any addresses bound to the VM. */
        /* vm_close */
        /*   err = attach_kprobe("vm_close", bpf_info.vm_close_prog, 0); */
        /*   if(err != 0) { */
        /*     fprintf(stderr, "Failed to attach a kprobe!\n"); */
        /*     return -1; */
        /*   } */

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
        printf("GEM ringbuf usage: %lu / %lu\n", avail, size);
}
