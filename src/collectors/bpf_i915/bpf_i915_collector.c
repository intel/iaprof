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

/***************************************
* BPF Handlers
***************************************/

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
        index = get_buffer_profile(info->file, info->handle);
        if(index == -1) {
                index = grow_buffer_profiles();
        }

	gem = &buffer_profile_arr[index];
        gem->handle = info->handle;
        gem->file = info->file;
        gem->mapped = 1;
	memcpy(&(gem->mapping_info), info, sizeof(struct mapping_info));

	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
		return -1;
	}

	return 0;
}

int handle_binary(unsigned char **dst, unsigned char *src, uint64_t *dst_sz,
		  uint64_t src_sz)
{
	uint64_t size;

	size = src_sz;
	if (size > MAX_BINARY_SIZE) {
		size = MAX_BINARY_SIZE;
	}
	*dst = calloc(size, sizeof(unsigned char));
	*dst_sz = size;
	memcpy(*dst, src, size);

	return 0;
}

int handle_unmap(void *data_arg)
{
	struct unmap_info *info;
	int index, retval;
	struct buffer_profile *gem;

	if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	info = (struct unmap_info *)data_arg;
	if (verbose) {
		print_unmap(info);
	}

	index = get_buffer_profile_by_mapping(info->file, info->handle);
	if ((index == -1) && debug) {
		fprintf(stderr,
			"WARNING: unmap called on handle %u with an mmap.\n", info->handle);
		goto cleanup;
	}
	gem = &(buffer_profile_arr[index]);
        gem->mapped = 0;
        if (gem->buff) {
                free(gem->buff);
        }
	retval = handle_binary(&(gem->buff), info->buff, &(gem->buff_sz),
			       info->size);
	if (retval == -1) {
		goto cleanup;
	}

cleanup:
	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
		return -1;
	}
	return retval;
}

int handle_request(void *data_arg)
{
        struct request_info *info;
        
	if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

        info = (struct request_info *)data_arg;
        if (verbose) {
                print_request(info);
        }
        
	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
		return -1;
	}

        return 0;
}

int handle_userptr(void *data_arg)
{
	struct userptr_info *info;

	if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	info = (struct userptr_info *)data_arg;
	if (verbose) {
		print_userptr(info);
	}

	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	return 0;
}

int handle_vm_create(void *data_arg)
{
	struct buffer_profile *gem;
	int index;
	struct vm_create_info *info;

	if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	info = (struct vm_create_info *)data_arg;
	if (verbose) {
		print_vm_create(info);
	}

        /* Register the PID with the debug_i915 collector */
        init_debug_i915(devinfo.fd, info->pid);


	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	return 0;
}

int handle_vm_bind(void *data_arg)
{
	struct buffer_profile *gem;
	int index;
	struct vm_bind_info *info;

	if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	info = (struct vm_bind_info *)data_arg;
	if (verbose) {
		print_vm_bind(info);
	}

	index = get_buffer_binding(info->handle, info->vm_id);
	if (index == -1) {
		index = grow_buffer_profiles();
	}

	/* Copy the vm_bind_info into the buffer's profile. */
	gem = &(buffer_profile_arr[index]);
        gem->handle = info->handle;
        gem->vm_id = info->vm_id;
	memcpy(&(gem->vm_bind_info), info, sizeof(struct vm_bind_info));

	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	return 0;
}

int handle_vm_unbind(void *data_arg)
{
	struct buffer_profile *gem;
	struct vm_unbind_info *info;
	int index;

	if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	info = (struct vm_unbind_info *)data_arg;
	if (verbose) {
		print_vm_unbind(info);
	}

	/* Try to find the buffer that this is unbinding. Note that
           info->handle is going to be 0 here, so we need to use
           the GPU address to look it up. */
	index = get_buffer_profile_by_gpu_addr(info->gpu_addr);
	if (index == -1) {
		if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
			fprintf(stderr,
				"Failed to acquire the buffer_profile_lock!\n");
			return -1;
		}
		if (debug) {
			fprintf(stderr,
				"WARNING: Got a vm_unbind on gpu_addr=0x%llx for which there wasn't a vm_bind!\n",
				info->gpu_addr);
		}
		return 0;
	}

	/* Mark the buffer as "stale." 
     XXX: Find a better solution here. Separate array for "tenured" buffers?
          When do we delete them? After a number of execbuffers without it? */
	gem = &(buffer_profile_arr[index]);
	gem->vm_bind_info.stale = 1;

	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	return 0;
}

int handle_batchbuffer(void *data_arg)
{
        struct batchbuffer_info *info;
        int n;
        struct buffer_profile *gem;
	uint32_t vm_id, pid;
        uint64_t gpu_addr;
        
	if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	info = (struct batchbuffer_info *)data_arg;

        /* Find the buffer that this batchbuffer is associated with */
	vm_id = info->vm_id;
	pid = info->pid;
        gpu_addr = info->gpu_addr;
	for (n = 0; n < buffer_profile_used; n++) {
		gem = &buffer_profile_arr[n];
		if ((gem->vm_bind_info.vm_id == vm_id) &&
		    (gem->vm_bind_info.pid == pid) &&
                    (gem->vm_bind_info.gpu_addr == gpu_addr)) {
                	if (verbose) {
                		print_batchbuffer(info);
                	}
                        /* Replace the current copy of this buffer */
                        if (gem->buff) {
                                free(gem->buff);
                        }
                        gem->buff = malloc(info->buff_sz);
                        memcpy(gem->buff, info->buff, info->buff_sz);
                        gem->buff_sz = info->buff_sz;
                }
                
        }

	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
		return -1;
	}

        return 0;
}

int handle_execbuf_start(void *data_arg)
{
	char found;
	struct buffer_profile *gem;
	uint64_t file;
	uint32_t vm_id, pid;
	int n;
	struct execbuf_start_info *info;
	struct bb_parser *parser;
        struct timespec parser_start, parser_end;

	if (pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
		return -1;
	}

	info = (struct execbuf_start_info *)data_arg;
	if (verbose) {
		print_execbuf_start(info);
	}

	/* This execbuffer call needs to be associated with all GEMs that
           are referenced by this call. Buffers can be referenced in two ways:
           1. Directly in the execbuffer call.
           2. Through the ctx_id (which has an associated vm_id).
     
           Here, we'll iterate over all buffers in the given vm_id. */
	vm_id = info->vm_id;
	pid = info->pid;
	file = info->file;
	for (n = 0; n < buffer_profile_used; n++) {
		gem = &buffer_profile_arr[n];
		/* We'll consider a buffer "in the same VM" if the vm_id, pid, and file are the same. */
		if ((gem->vm_bind_info.vm_id == vm_id) &&
		    (gem->vm_bind_info.pid == pid) &&
		    (gem->vm_bind_info.file == file)) {
			if (verbose) {
				print_execbuf_gem(info, &(gem->vm_bind_info));
			}

			/* Store the execbuf information */
			memcpy(&(gem->exec_info), info,
			       sizeof(struct execbuf_start_info));

			/* Store the stack */
			if (gem->execbuf_stack_str == NULL) {
				store_stack(info->pid, info->stackid,
					    &(gem->execbuf_stack_str));
			}
		}
	}

        if (!iba) {
        	/* The execbuffer call specifies a handle (which is sometimes 0) and a GPU
                address that contains the batchbuffer. Find this buffer and attempt to parse it. */
        	found = 0;
        	for (n = 0; n < buffer_profile_used; n++) {
        		gem = &buffer_profile_arr[n];
        
        		if ((gem->vm_bind_info.file != file) ||
        		    (gem->vm_bind_info.gpu_addr != info->bb_offset)) {
        			/* This buffer doesn't match the one we're looking for */
        			continue;
        		}
        
                        if (info->buff_sz == 0) {
                                /* We didn't get a copy of the batchbuffer from BPF! */
                                continue;
                        }
                        if (gem->buff) {
                                free(gem->buff);
                        }
                        gem->buff = malloc(info->buff_sz);
                        memcpy(gem->buff, info->buff, info->buff_sz);
                        gem->buff_sz = info->buff_sz;
                        if ((!gem->buff) || (!gem->buff_sz)) {
                                continue;
                        }
        
        		/* Parse the batchbuffer */
        		found = 1;
                        clock_gettime(CLOCK_MONOTONIC, &parser_start);
        		parser = bb_parser_init();
        		bb_parser_parse(parser, gem, info->batch_start_offset,
        				info->batch_len);
                        clock_gettime(CLOCK_MONOTONIC, &parser_end);
                        if (verbose) {
                                printf("Parsed %zu dwords in %.5f seconds.\n",
                                       parser->num_dwords,
                                       ((double)parser_end.tv_sec + 1.0e-9*parser_end.tv_nsec) - 
                                       ((double)parser_start.tv_sec + 1.0e-9*parser_start.tv_nsec));
                        }
        		if (parser->iba) {
        			iba = parser->iba;
        		}
        
        		break;
        	}
        	if (!found && debug) {
        		fprintf(stderr,
        			"WARNING: Unable to find a buffer that matches 0x%llx\n",
        			info->bb_offset);
        	}
        }

	if (iba) {
		for (n = 0; n < buffer_profile_used; n++) {
			gem = &buffer_profile_arr[n];
			if ((gem->vm_bind_info.vm_id == vm_id) &&
			    (gem->vm_bind_info.pid == pid) &&
			    (gem->vm_bind_info.file == file)) {
				gem->iba = iba;
			}
		}
	}

	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
		return -1;
	}

	return 0;
}

int handle_execbuf_end(void *data_arg)
{
	struct execbuf_end_info *info;

	/* First, just print out the execbuf_end */
	info = (struct execbuf_end_info *)data_arg;
	if (verbose) {
		print_execbuf_end(info);
	}

	return 0;
}

/* Runs each time a sample from the ringbuffer is collected.
   Samples can be one of four types:
   1. struct mapping_info. This is a struct collected when an `execbuffer` call is made,
      and represents a buffer that is either directly referenced by the `execbuffer`
      call, or a buffer that's in the "VM" assigned to the context that's executing.
   2. struct unmap_info. This is a struct collected when `munmap` is called on a
      VMA that was mapped by i915. Assuming we've seen the associated `mmap` call
      from i915, the buffer is then copied into the ringbuffer (along with some
      metadata).
   3. struct execbuf_start_info. Basic metadata collected at the beginning of an
      execbuffer call.
   4. struct execbuffer_end_info. Basic metadata collected at the end of an
      execbuffer call. */
static int handle_sample(void *ctx, void *data_arg, size_t data_sz)
{
	unsigned char *data;

	if (data_sz == sizeof(struct mapping_info)) {
		return handle_mapping(data_arg);
	} else if (data_sz == sizeof(struct unmap_info)) {
		return handle_unmap(data_arg);
	} else if (data_sz == sizeof(struct userptr_info)) {
		return handle_userptr(data_arg);
	} else if (data_sz == sizeof(struct vm_create_info)) {
		return handle_vm_create(data_arg);
	} else if (data_sz == sizeof(struct vm_bind_info)) {
		return handle_vm_bind(data_arg);
	} else if (data_sz == sizeof(struct vm_unbind_info)) {
		return handle_vm_unbind(data_arg);
	} else if (data_sz == sizeof(struct execbuf_start_info)) {
		return handle_execbuf_start(data_arg);
	} else if (data_sz == sizeof(struct batchbuffer_info)) {
		return handle_batchbuffer(data_arg);
	} else if (data_sz == sizeof(struct execbuf_end_info)) {
		return handle_execbuf_end(data_arg);
	} else if (data_sz == sizeof(struct request_info)) {
		return handle_request(data_arg);
	} else {
		fprintf(stderr,
			"Unknown data size when handling a sample: %lu\n",
			data_sz);
		return -1;
	}

	return 0;
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

        check_bpf_type_sizes();

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

	/*   bpf_info.pwrite_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.pwrite_kprobe; */

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
        printf("epoll_fd = %d\n", bpf_info.epoll_fd);
        printf("rb_fb = %d\n", bpf_info.rb_fd);

	/* XXX: Finish pwrite support in BPF and re-enable. It's another way to
     write to a buffer object via the CPU. */
	/* i915_gem_pwrite_ioctl */
	/*   err = attach_kprobe("i915_gem_pwrite_ioctl", bpf_info.pwrite_ioctl_prog, 0); */
	/*   if(err != 0) { */
	/*     fprintf(stderr, "Failed to attach a kprobe!\n"); */
	/*     return -1; */
	/*   } */

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

/*******************
*  SANITY CHECKS   *
* **************** *
* These macro hacks check the sizes of the `*_info` structs, to make sure
* that they're unique. It throws a static assertion if any match. If you
* add any new struct types to the BPF ringbuf, add them to the
* `BPF_TYPE_SIZES_LIST` macro.
*******************/

/* Macro hacks */
#define STRINGIFY(x) STRINGIFY_(x)
#define STRINGIFY_(x) #x
#define EMPTY()
#define DEFER(id) id EMPTY()
#define OBSTRUCT(...) __VA_ARGS__ DEFER(EMPTY)()
#define EXPAND(...) __VA_ARGS__
#define EVAL(...)  EVAL1(__VA_ARGS__)
#define EVAL1(...) __VA_ARGS__

#define BPF_TYPE_SIZES_LIST(X, ...) \
        X(struct mapping_info, __VA_ARGS__) \
        X(struct unmap_info, __VA_ARGS__) \
        X(struct vm_create_info, __VA_ARGS__) \
        X(struct vm_bind_info, __VA_ARGS__) \
        X(struct vm_unbind_info, __VA_ARGS__) \
        X(struct execbuf_start_info, __VA_ARGS__) \
        X(struct batchbuffer_info, __VA_ARGS__) \
        X(struct execbuf_end_info, __VA_ARGS__) \
        X(struct userptr_info, __VA_ARGS__) \
        X(struct request_info, __VA_ARGS__)
        
#define BPF_TYPE_SIZES_LIST_INDIRECT(...) BPF_TYPE_SIZES_LIST(__VA_ARGS__)

#define X2(type1, type2) \
    static_assert((strcmp(STRINGIFY(type1), STRINGIFY(type2)) == 0) || \
                  (sizeof(type1) != sizeof(type2)));
                  
#define X1(type1, ...) \
  DEFER(BPF_TYPE_SIZES_LIST_INDIRECT)(X2, type1)
        
void check_bpf_type_sizes()
{
        EVAL(BPF_TYPE_SIZES_LIST(X1))
}
