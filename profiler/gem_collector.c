/***************************************
* GEM Collector
***************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <pthread.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#include "pvc_profile.h"
#include "bpf/gem_collector.h"
#include "bpf/gem_collector.skel.h"
#include "stack_printer.h"
#include "printer.h"
#include "gem_collector.h"
#include "utils/utils.h"
#include "bb_parser.h"

/***************************************
* Buffer Profile Array
***************************************/

/* Looks up a buffer in the buffer_profile_arr by file/handle pair
   (using its mapping_info, or mmap call).
   Returns -1 if not found. */
int get_buffer_profile(uint32_t pid, uint64_t file, uint32_t handle) {
  int n;
  struct buffer_profile *gem;
  
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    if((gem->mapping_info.handle == handle) &&
       (gem->mapping_info.file   == file) &&
       (gem->mapping_info.pid    == pid)) {
      return n;
    }
  }
  
  return -1;
}

/* Looks up a buffer in the buffer_profile_arr by the file/handle pair
   found in its vm_bind_info (or vm_bind call).
   Returns -1 if not found. */
int get_buffer_profile_by_binding(uint32_t pid, uint64_t file, uint32_t handle) {
  int n;
  struct buffer_profile *gem;
  
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    if((gem->vm_bind_info.handle == handle) &&
       (gem->vm_bind_info.file   == file)) {
      return n;
    }
  }
  
  return -1;
}

/* Looks up a buffer in the buffer_profile_arr by its GPU address. */
int get_buffer_profile_by_gpu_addr(uint64_t gpu_addr) {
  int n;
  struct buffer_profile *gem;
  
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    if(gem->vm_bind_info.gpu_addr == gpu_addr) {
      return n;
    }
  }
  
  return -1;
}

/* Ensure that we have enough room to place a newly-seen sample, and place it.
   Does NOT grab the lock, so the caller should. */
uint64_t grow_buffer_profiles() {
  size_t old_size;
  struct buffer_profile *gem;
  
  /* Ensure there's enough room in the array */
  if(buffer_profile_size == buffer_profile_used) {
    /* Not enough room in the array */
    old_size = buffer_profile_size;
    buffer_profile_size += 64;
    buffer_profile_arr = realloc(buffer_profile_arr, buffer_profile_size * sizeof(struct buffer_profile));
    memset(buffer_profile_arr + buffer_profile_used, 0, (buffer_profile_size - old_size) * sizeof(struct buffer_profile));
  }
  
  buffer_profile_used++;
  return buffer_profile_used - 1;
}

/***************************************
* BPF Handlers
***************************************/

/* Handles `struct mapping_info`, which comes from
   `mmap` calls. Includes a CPU pointer. */
int handle_mapping(void *data_arg) {
  struct buffer_profile *gem;
  int mapping_index, vm_bind_index, index;
  struct mapping_info *info;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct mapping_info *) data_arg;
  if(debug) {
    print_mapping(info);
  }
  
  /* First, check to see if we've already seen a mapping or a vm_bind called
     on this file/handle pair. */
  mapping_index = get_buffer_profile(info->pid, info->file, info->handle);
  vm_bind_index = get_buffer_profile_by_binding(info->pid, info->file, info->handle);
  if(mapping_index != -1) {
    fprintf(stderr, "WARNING: Detected churn on pid=%u file=0x%llx handle=%u\n", info->pid, info->file, info->handle);
  }
  if((mapping_index == -1) && (vm_bind_index == -1)) {
    /* Common case: this same file/handle pair wasn't already mapped. */
    index = grow_buffer_profiles();
  } else if((mapping_index == -1) && (vm_bind_index != -1)) {
    /* If we've seen this buffer's vm_bind already, use that index */
    index = vm_bind_index;
  } else {
    /* In this case, mapping_index is not -1. Create a new buffer. */
    index = grow_buffer_profiles();
  }
  
  gem = &buffer_profile_arr[index];
  memcpy(&(gem->mapping_info), info, sizeof(struct mapping_info));
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
    return -1;
  }
  
  return 0;
}

int handle_binary(unsigned char **dst, unsigned char *src, uint64_t *dst_sz, uint64_t src_sz) {
  uint64_t size;
  
  size = src_sz;
  if(size > MAX_BINARY_SIZE) {
    size = MAX_BINARY_SIZE;
  }
  *dst = calloc(size, sizeof(unsigned char));
  *dst_sz = size;
  memcpy(*dst, src, size);
  
  return 0;
}

int handle_unmap(void *data_arg) {
  struct unmap_info *info;
  int index, retval;
  struct buffer_profile *gem;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct unmap_info *) data_arg;
  if(debug) {
    print_unmap(info);
  }
  
  index = get_buffer_profile(info->pid, info->file, info->handle);
  if(index == -1) {
    fprintf(stderr, "WARNING: handle_binary called on a mapping that hasn't happened yet.\n");
    goto cleanup;
  }
  gem = &(buffer_profile_arr[index]);
  retval = handle_binary(&(gem->buff), info->buff, &(gem->buff_sz), info->size);
  if(retval == -1) {
    goto cleanup;
  }
  
cleanup:
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  return retval;
}

int handle_userptr(void *data_arg) {
  struct userptr_info *info;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct userptr_info *) data_arg;
  if(debug) {
    print_userptr(info);
  }
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  return 0;
}

int handle_vm_bind(void *data_arg) {
  struct buffer_profile *gem;
  int index;
  struct vm_bind_info *info;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct vm_bind_info *) data_arg;
  if(debug) {
    print_vm_bind(info);
  }
  
  /* Check to see if we've seen mmap get called on this file/handle pair
     yet. If so, use that index, but if not, allocate a new one. */
  index = get_buffer_profile(info->pid, info->file, info->handle);
  if(index == -1) {
    index = grow_buffer_profiles();
  }
  
  /* Copy the vm_bind_info into the buffer's profile. */
  gem = &(buffer_profile_arr[index]);
  memcpy(&(gem->vm_bind_info), info, sizeof(struct vm_bind_info));
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  return 0;
}

int handle_vm_unbind(void *data_arg) {
  struct buffer_profile *gem;
  struct vm_unbind_info *info;
  int index;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct vm_unbind_info *) data_arg;
  if(debug) {
    print_vm_unbind(info);
  }
  
  /* Try to find the buffer that this is unbinding. Note that
     info->handle is going to be 0 here, so we need to use
     the GPU address to look it up. */
  index = get_buffer_profile_by_gpu_addr(info->gpu_addr);
  if(index == -1) {
    if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
      fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
      return -1;
    }
    fprintf(stderr, "WARNING: Got a vm_unbind on gpu_addr=0x%llx for which there wasn't a vm_bind!\n", info->gpu_addr);
    return 0;
  }
  
  #if 0
  /* Zero out the vm_bind_info of the buffer that we've found.
     Note that after this is done, EU stalls can no longer be
     associated with it. */
  gem = &(buffer_profile_arr[index]);
  memset(&(gem->vm_bind_info), 0, sizeof(struct vm_bind_info));
  #endif
  
  /* Mark the buffer as "stale." 
     XXX: Find a better solution here. Separate array for "tenured" buffers?
          When do we delete them? After a number of execbuffers without it? */
  gem = &(buffer_profile_arr[index]);
  gem->vm_bind_info.stale = 1;
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  return 0;
}

int handle_execbuf_start(void *data_arg) {
  struct buffer_profile *gem;
  uint64_t file;
  uint32_t vm_id, pid;
  int n;
  char found, should_free_buffer;
  struct execbuf_start_info *info;
  unsigned char *batchbuffer;
  struct bb_parser *parser;
  
  if(pthread_rwlock_wrlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to acquire the buffer_profile_lock!\n");
    return -1;
  }
  
  info = (struct execbuf_start_info *) data_arg;
  if(debug) {
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
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    /* We'll consider a buffer "in the same VM" if the vm_id, pid, and file are the same. */
    if((gem->vm_bind_info.vm_id == vm_id) &&
       (gem->vm_bind_info.pid == pid) &&
       (gem->vm_bind_info.file == file)) {
      if(debug) {
        print_execbuf_gem(info, &(gem->vm_bind_info));
      }
      memcpy(&(gem->exec_info), info, sizeof(struct execbuf_start_info));
    }
    if(gem->execbuf_stack_str == NULL) {
      store_stack(info->pid, info->stackid, &(gem->execbuf_stack_str));
    }
  }
  
  #if 0
  /* The execbuffer call also specifies a handle (which is sometimes 0) and a GPU
     address that contains the batchbuffer. Find this buffer and attempt to parse it.
     In this loop, we're just looking for a buffer whose file pointer and gpu_addr
     matches what was passed into the execbuffer. */
  found = 0;
  for(n = 0; n < buffer_profile_used; n++) {
    gem = &buffer_profile_arr[n];
    
    if((gem->vm_bind_info.file == file) &&
       (gem->vm_bind_info.gpu_addr == info->bb_offset)) {
      if(debug) {
        print_batchbuffer(info, &(gem->vm_bind_info));
      }
      
      
      /* If the CPU address is a valid one, we want to parse the batchbuffer */
      if(gem->mapping_info.cpu_addr) {
        should_free_buffer = 1;
        batchbuffer = copy_buffer(pid, gem->mapping_info.cpu_addr, gem->mapping_info.size);
        if(!batchbuffer) {
          if(gem->buff) {
            /* If we couldn't copy the buffer, perhaps we had a copy from before? */
            batchbuffer = gem->buff;
            should_free_buffer = 0;
          } else {
            fprintf(stderr, "WARNING: Failed to copy the batchbuffer cpu_addr=0x%llx size=%llx\n",
                    gem->mapping_info.cpu_addr, gem->mapping_info.size);
            goto foundit;
          }
        } else {
          if(!(gem->buff)) {
            /* If we read a valid buffer from the process' address space, why not store it
              for later? We need to do this BEFORE parsing because sometimes batchbuffers
              "jump" to themselves, in which case gem->buff needs to already be populated
              for the parser to perform the jump. */
            gem->buff = batchbuffer;
            should_free_buffer = 0;
          }
        }
        
        if(debug) {
          dump_buffer(batchbuffer, gem->mapping_info.size, gem->vm_bind_info.handle);
        }
        parser = bb_parser_init();
        bb_parser_parse(parser, batchbuffer, info->batch_start_offset, info->batch_len);
        
        if(should_free_buffer) {
          free(batchbuffer);
        }
      }
      
foundit:
      found = 1;
      break;
    }
  }
  if(!found) {
    fprintf(stderr, "WARNING: Failed to find a batchbuffer at file=0x%lx bb_offset=0x%llx\n", file, info->bb_offset);
  }
  #endif
  
  if(pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
    fprintf(stderr, "Failed to unlock the buffer_profile_lock!\n");
    return -1;
  }

  return 0;
}

int handle_execbuf_end(void *data_arg) {
  struct execbuf_end_info *info;
  info = (struct execbuf_end_info *) data_arg;
  if(debug) {
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
static int handle_sample(void *ctx, void *data_arg, size_t data_sz) {
  unsigned char *data;
  
  if(data_sz == sizeof(struct mapping_info)) {
    return handle_mapping(data_arg);
  } else if(data_sz == sizeof(struct unmap_info)) {
    return handle_unmap(data_arg);
  } else if(data_sz == sizeof(struct userptr_info)) {
    return handle_userptr(data_arg);
  } else if(data_sz == sizeof(struct vm_bind_info)) {
    return handle_vm_bind(data_arg);
  } else if(data_sz == sizeof(struct vm_unbind_info)) {
    return handle_vm_unbind(data_arg);
  } else if(data_sz == sizeof(struct execbuf_start_info)) {
    return handle_execbuf_start(data_arg);
  } else if(data_sz == sizeof(struct execbuf_end_info)) {
    return handle_execbuf_end(data_arg);
  } else {
    fprintf(stderr, "Unknown data size when handling a sample: %lu\n", data_sz);
    return -1;
  }
  
  return 0;
}

/***************************************
* BPF Setup
***************************************/

int attach_kprobe(const char *func, struct bpf_program *prog, int ret) {
  struct bpf_kprobe_opts opts;
  
  bpf_info.num_links++;
  bpf_info.links = realloc(bpf_info.links, sizeof(struct bpf_link *) * bpf_info.num_links);
  if(!bpf_info.links) {
    fprintf(stderr, "Failed to allocate memory for the BPF links! Aborting.\n");
    return -1;
  }
  
  memset(&opts, 0, sizeof(opts));
  opts.retprobe = ret;
  opts.sz = sizeof(opts);
  opts.attach_mode = PROBE_ATTACH_MODE_LEGACY;
  bpf_info.links[bpf_info.num_links - 1] = bpf_program__attach_kprobe_opts(prog, func, &opts);
  if(libbpf_get_error(bpf_info.links[bpf_info.num_links - 1])) {
    fprintf(stderr, "Failed to attach the BPF program to a kprobe: %s\n", func);
    /* Set this pointer to NULL, since it's undefined what it will be */
    bpf_info.links[bpf_info.num_links - 1] = NULL;
    return -1;
  }
  
  return 0;
}

int attach_tracepoint(const char *category, const char *func, struct bpf_program *prog) {
  bpf_info.num_links++;
  bpf_info.links = realloc(bpf_info.links, sizeof(struct bpf_link *) * bpf_info.num_links);
  if(!bpf_info.links) {
    fprintf(stderr, "Failed to allocate memory for the BPF links! Aborting.\n");
    return -1;
  }
  bpf_info.links[bpf_info.num_links - 1] = bpf_program__attach_tracepoint(prog, category, func);
  if(libbpf_get_error(bpf_info.links[bpf_info.num_links - 1])) {
    fprintf(stderr, "Failed to attach the BPF program to a tracepoint: %s:%s\n", category, func);
    /* Set this pointer to NULL, since it's undefined what it will be */
    bpf_info.links[bpf_info.num_links - 1] = NULL;
    return -1;
  }
  
  return 0;
}

int deinit_bpf_prog() {
  uint64_t i;
  int retval;
  
  for(i = 0; i < bpf_info.num_links; i++) {
    retval = bpf_link__detach(bpf_info.links[i]);
    if(retval == -1) {
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
  
  bpf_program__unload(bpf_info.vm_bind_ioctl_prog);
  bpf_program__unload(bpf_info.vm_bind_ioctl_ret_prog);
  
  bpf_program__unload(bpf_info.vm_unbind_ioctl_prog);
  
  bpf_program__unload(bpf_info.context_create_ioctl_prog);
  bpf_program__unload(bpf_info.context_create_ioctl_ret_prog);
  
  bpf_program__unload(bpf_info.do_execbuffer_prog);
  bpf_program__unload(bpf_info.do_execbuffer_ret_prog);
  
  bpf_program__unload(bpf_info.munmap_prog);
  
  gem_collector_bpf__destroy(bpf_info.obj);
  
  return 0;
}

int init_bpf_prog() {
  int err;
  struct bpf_object_open_opts opts = {0};

  opts.sz = sizeof(struct bpf_object_open_opts);
  #if 0
  if(pw_opts.btf_custom_path) {
    opts.btf_custom_path = pw_opts.btf_custom_path;
  }
  #endif

  bpf_info.obj = gem_collector_bpf__open_opts(&opts);
  if(!bpf_info.obj) {
    fprintf(stderr, "ERROR: Failed to get BPF object.\n");
    fprintf(stderr, "       Most likely, one of two things are true:\n");
    fprintf(stderr, "       1. You're not root.\n");
    fprintf(stderr, "       2. You don't have a kernel that supports BTF type information.\n");
    return -1;
  }
  err = gem_collector_bpf__load(bpf_info.obj);
  if(err) {
    fprintf(stderr, "Failed to load BPF object!\n");
    return -1;
  }

/*   bpf_info.pwrite_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.pwrite_kprobe; */
  
  bpf_info.mmap_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_ioctl_kprobe;
  bpf_info.mmap_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_ioctl_kretprobe;
  
  bpf_info.mmap_offset_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_offset_ioctl_kprobe;
  bpf_info.mmap_offset_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_offset_ioctl_kretprobe;
  bpf_info.mmap_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_kprobe;
  bpf_info.mmap_ret_prog = (struct bpf_program *) bpf_info.obj->progs.mmap_kretprobe;
  
  bpf_info.userptr_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.userptr_ioctl_kprobe;
  bpf_info.userptr_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.userptr_ioctl_kretprobe;
  
  bpf_info.vm_bind_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.vm_bind_ioctl_kprobe;
  bpf_info.vm_bind_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.vm_bind_ioctl_kretprobe;
  
  bpf_info.vm_unbind_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.vm_unbind_ioctl_kprobe;
  
  bpf_info.context_create_ioctl_prog = (struct bpf_program *) bpf_info.obj->progs.context_create_ioctl_kprobe;
  bpf_info.context_create_ioctl_ret_prog = (struct bpf_program *) bpf_info.obj->progs.context_create_ioctl_kretprobe;
  
  bpf_info.do_execbuffer_prog = (struct bpf_program *) bpf_info.obj->progs.do_execbuffer_kprobe;
  bpf_info.do_execbuffer_ret_prog = (struct bpf_program *) bpf_info.obj->progs.do_execbuffer_kretprobe;
  
  bpf_info.munmap_prog = (struct bpf_program *) bpf_info.obj->progs.munmap_tp;
  
/*   bpf_info.vm_close_prog = (struct bpf_program *) bpf_info.obj->progs.vm_close_kprobe; */
  
  bpf_info.rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.rb), handle_sample, NULL, NULL);
  if(!(bpf_info.rb)) {
    fprintf(stderr, "Failed to create a new ring buffer. You're most likely not root.\n");
    return -1;
  }
  
  /* i915_gem_pwrite_ioctl */
/*   err = attach_kprobe("i915_gem_pwrite_ioctl", bpf_info.pwrite_ioctl_prog, 0); */
/*   if(err != 0) { */
/*     fprintf(stderr, "Failed to attach a kprobe!\n"); */
/*     return -1; */
/*   } */
  
  /* i915_gem_mmap_ioctl */
  err = attach_kprobe("i915_gem_mmap_ioctl", bpf_info.mmap_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_mmap_ioctl", bpf_info.mmap_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_mmap_offset_ioctl and friends */
  err = attach_kprobe("i915_gem_mmap_offset_ioctl", bpf_info.mmap_offset_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_mmap_offset_ioctl", bpf_info.mmap_offset_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_mmap", bpf_info.mmap_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_mmap", bpf_info.mmap_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_userptr_ioctl */
  err = attach_kprobe("i915_gem_userptr_ioctl", bpf_info.userptr_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_userptr_ioctl", bpf_info.userptr_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_vm_bind_ioctl */
  err = attach_kprobe("i915_gem_vm_bind_ioctl", bpf_info.vm_bind_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_vm_bind_ioctl", bpf_info.vm_bind_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_vm_unbind_ioctl */
  err = attach_kprobe("i915_gem_vm_unbind_ioctl", bpf_info.vm_unbind_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_context_create_ioctl */
  err = attach_kprobe("i915_gem_context_create_ioctl", bpf_info.context_create_ioctl_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_context_create_ioctl", bpf_info.context_create_ioctl_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* i915_gem_do_execbuffer */
  err = attach_kprobe("i915_gem_do_execbuffer", bpf_info.do_execbuffer_prog, 0);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  err = attach_kprobe("i915_gem_do_execbuffer", bpf_info.do_execbuffer_ret_prog, 1);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a kprobe!\n");
    return -1;
  }
  
  /* munmap */
  err = attach_tracepoint("syscalls", "sys_enter_munmap", bpf_info.munmap_prog);
  if(err != 0) {
    fprintf(stderr, "Failed to attach a tracepoint!\n");
    return -1;
  }
  
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
void print_ringbuf_stats() {
  uint64_t size, avail;
  
  avail = ring__avail_data_size(ring_buffer__ring(bpf_info.rb, 0));
  size = ring__size(ring_buffer__ring(bpf_info.rb, 0));
  printf("GEM ringbuf usage: %lu / %lu\n", avail, size);
}
