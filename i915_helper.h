#include <errno.h>
#include <stddef.h>
#include <sys/mman.h>
#include <drm/i915_drm_prelim.h>

#include "drm_helper.h"

#define PAGE_SIZE 4096
#define GEM_MAX_ENGINES    (PRELIM_I915_EXEC_ENGINE_MASK + 1)
#define QUERY_SIZE offsetof(struct drm_i915_query_engine_info, engines[GEM_MAX_ENGINES])

/*******************
*   GPU Commands   *
*******************/

/* Offsets in the instruction fields */
#define   INSTR_MI_CLIENT       0x0
#define INSTR_CLIENT_SHIFT      29
#define __INSTR(client) ((client) << INSTR_CLIENT_SHIFT)

/* Memory interface instructions */
#define MI_INSTR(opcode, flags) \
  (__INSTR(INSTR_MI_CLIENT) | (opcode) << 23 | (flags))
#define MI_BATCH_BUFFER_END  MI_INSTR(0x0a, 0)

/*******************
*     CONTEXT      *
*******************/

int i915_ctx_create_all_engines(int fd, uint32_t *ctx_id, struct drm_i915_query_engine_info *engines) {
  int i;
  struct drm_i915_gem_context_create_ext create;
  struct drm_i915_gem_context_create_ext_setparam engines_param;
  I915_DEFINE_CONTEXT_PARAM_ENGINES(phys_engines, GEM_MAX_ENGINES);
  
  if(engines->num_engines > GEM_MAX_ENGINES) {
    fprintf(stderr, "The number of engines is larger than the maximum.\n");
    return -1;
  }
  
  /* Copy the engines over to the array of engines */
  memset(&phys_engines, 0, sizeof(phys_engines));
  for (i = 0; i < engines->num_engines; i++) {
    phys_engines.engines[i] = engines->engines[i].engine;
  }
  
  /* Construct the parameters to pass to ioctl */
  engines_param = (struct drm_i915_gem_context_create_ext_setparam) {
    .base = {
      .name = I915_CONTEXT_CREATE_EXT_SETPARAM,
    },
    .param = {
      .param = I915_CONTEXT_PARAM_ENGINES,
      .size =  offsetof(struct i915_context_param_engines, engines[engines->num_engines]),
      .value = (uintptr_t)(&phys_engines),
    },
  };
  
  /* Create the context */
  memset(&create, 0, sizeof(create));
  create.flags |= I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS;
  create.extensions = (uintptr_t) &engines_param.base;
  if(ioctl_do(fd, DRM_IOCTL_I915_GEM_CONTEXT_CREATE_EXT, &create) != 0) {
    fprintf(stderr, "Failed to create a context.\n");
    ioctl_err(errno);
    return -errno;
  }
  *ctx_id = create.ctx_id;
  return 0;
}

int i915_ctx_create(int fd, uint32_t *ctx_id) {
  int i;
  struct drm_i915_gem_context_create create;
  
  /* Create the context */
  memset(&create, 0, sizeof(create));
  if(ioctl_do(fd, DRM_IOCTL_I915_GEM_CONTEXT_CREATE, &create) != 0) {
    fprintf(stderr, "Failed to create a context.\n");
    ioctl_err(errno);
    return -errno;
  }
  *ctx_id = create.ctx_id;
  return 0;
}

int i915_ctx_destroy(int fd, uint32_t ctx_id) {
  struct drm_i915_gem_context_destroy destroy = {
    ctx_id
  };

  if(ioctl_do(fd, DRM_IOCTL_I915_GEM_CONTEXT_DESTROY, &destroy) != 0) {
    fprintf(stderr, "Failed to destroy a context.\n");
    ioctl_err(errno);
    return -1;
  }
  return 0;
}

/*******************
*       GEM        *
*******************/

/* Creates a GEM on the given device, and returns the size and handle.
   Pass NULL as `ext` if you don't want to add a user extension. */
int i915_gem_create(int fd, uint64_t *size, uint32_t *handle, struct i915_user_extension *ext) {
  int err;
  
  struct prelim_drm_i915_gem_create_ext create = {
    .size = *size,
  };
  
  if(ext) {
    create.extensions = (uintptr_t) ext;
  }
  
  if(ioctl_do(fd, PRELIM_DRM_IOCTL_I915_GEM_CREATE_EXT, &create) != 0) {
    fprintf(stderr, "Failed to create a GEM.\n");
    ioctl_err(errno);
    return -errno;
  }
  *handle = create.handle;
  *size = create.size;
  return 0;
}

void *i915_gem_mmap(int fd, uint32_t handle, uint64_t size, unsigned int prot, uint64_t flags) {
  void *ptr;

  struct drm_i915_gem_mmap_offset arg = {
    .handle = handle,
    .flags = flags,
  };

  if(ioctl_do(fd, DRM_IOCTL_I915_GEM_MMAP_OFFSET, &arg) != 0) {
    fprintf(stderr, "Failed to mmap a GEM!\n");
    return NULL;
  }

  ptr = mmap(0, size, prot, MAP_SHARED, fd, arg.offset);

  if (ptr == MAP_FAILED) {
    return NULL;
  }

  return ptr;
}

int i915_gem_execbuf(int fd, struct drm_i915_gem_execbuffer2 *execbuf) {
  int ret;
  ret = ioctl_do(fd, DRM_IOCTL_I915_GEM_EXECBUFFER2, execbuf);
  if(ret != 0) {
    fprintf(stderr, "Failed to submit an execbuf\n");
    ioctl_err(errno);
    return -1;
  }
  return 0;
}

int i915_gem_close(int fd, uint32_t handle) {
  struct drm_gem_close close = {
    .handle = handle
  };
  if(ioctl_do(fd, DRM_IOCTL_GEM_CLOSE, &close) != 0) {
    fprintf(stderr, "Failed to close a GEM.\n");
    ioctl_err(errno);
    return -1;
  }
  return 0;
}

/*******************
*     ENGINES      *
*******************/

int i915_query_engines(int fd, struct drm_i915_query_engine_info **qei) {
  unsigned int num_engines;
  int ret;
  
  /* Allocate room for the engine info */
  *qei = (void *) calloc(QUERY_SIZE, sizeof(uint8_t));
  
  /* Construct the query struct */
  struct drm_i915_query_item item = {
    .query_id = DRM_I915_QUERY_ENGINE_INFO,
    .data_ptr = (uintptr_t) *qei,
    .length = QUERY_SIZE,
  };
  struct drm_i915_query q = {
    .num_items = 1,
    .items_ptr = (uintptr_t) &item,
  };
  
  /* Call the query itself */
  ret = ioctl_do(fd, DRM_IOCTL_I915_QUERY, &q);
  if(ret) {
    return -1;
  }
  
  return 0;
}

/*******************
*  MEMORY REGIONS  *
*******************/

#define INTEL_MEMORY_REGION_ID(type, instance) ((type) << 16u | (instance))

#define for_each_memory_region(regions__, region__) \
      /* Beginning condition */ \
      for(int iter__ = 0; \
      /* Finished condition */ \
      (iter__ < regions__->num_regions) && (region__ = regions__->regions[iter__].region, 1); \
      /* Incrementing */ \
      iter__ += ((region__.memory_class != I915_MEMORY_CLASS_SYSTEM) && (region__.memory_class != I915_MEMORY_CLASS_DEVICE)) ? 2 : 1)
      
      
int i915_query_memory_regions(int fd, struct drm_i915_query_memory_regions **regions) {
  int ret;
  
  /* Construct the query and ioctl it */
  struct drm_i915_query_item item = {
    .query_id = DRM_I915_QUERY_MEMORY_REGIONS,
  };
  struct drm_i915_query q = {
    .num_items = 1,
    .items_ptr = (uintptr_t) &item,
  };
  ret = ioctl_do(fd, DRM_IOCTL_I915_QUERY, &q);
  if(item.length < 0) {
    fprintf(stderr, "Failed to get the size of the memory regions.\n");
    return -1;
  }
  
  /* Now allocate room for the regions themselves */
  *regions = calloc(1, item.length);
  item.data_ptr = (uintptr_t) *regions;
  
  /* Query again */
  struct drm_i915_query q_items = {
    .num_items = 1,
    .items_ptr = (uintptr_t) &item,
  };
  ret = ioctl_do(fd, DRM_IOCTL_I915_QUERY, &q_items);
  if(ret != 0) {
    fprintf(stderr, "Failed to get the memory regions.\n");
    return -1;
  }
}

int i915_gem_create_in_memory_regions(int fd, uint32_t *handle, uint64_t *size,
                                      const struct drm_i915_gem_memory_class_instance *regions,
                                      int num_regions) {
  int ret;
  
  struct prelim_drm_i915_gem_object_param region_param = {
    .size = num_regions,
    .data = (uintptr_t) regions,
    .param = PRELIM_I915_OBJECT_PARAM | PRELIM_I915_PARAM_MEMORY_REGIONS,
  };
  struct prelim_drm_i915_gem_create_ext_setparam setparam_region = {
    .base = { .name = PRELIM_I915_GEM_CREATE_EXT_SETPARAM },
    .param = region_param,
  };

  ret = i915_gem_create(fd, size, handle, &setparam_region.base);
  if(ret != 0) {
    fprintf(stderr, "Failed to create a GEM in memory regions.\n");
    return -1;
  }
  
  return 0;
}

uint64_t i915_detect_safe_offset_for_region(int fd, struct drm_i915_gem_memory_class_instance *region) {
  int ret;
  uint32_t ctx, *batch;
  uint64_t bb_size = PAGE_SIZE, start_offset = 0;
  struct drm_i915_gem_exec_object2 obj = {};
  struct drm_i915_gem_execbuffer2 eb = {};
  
  /* Create a new context */
  i915_ctx_create(fd, &ctx);
  
  /* Initialize the execbuf */
  eb.buffers_ptr = (uintptr_t) (&obj);
  eb.buffer_count = 1;
  eb.flags = I915_EXEC_DEFAULT;
  eb.rsvd1 = ctx;
  obj.flags = EXEC_OBJECT_PINNED;
  
  /* Create a GEM that creates one command */
  ret = i915_gem_create_in_memory_regions(fd, &(obj.handle), &bb_size, region, 1);
  if(ret != 0) {
    fprintf(stderr, "While trying to detect a safe offset, failed to create a GEM.\n");
    exit(1);
  }
  batch = i915_gem_mmap(fd, obj.handle, bb_size, PROT_WRITE, I915_MMAP_OFFSET_WC);
  if(batch == NULL) {
    fprintf(stderr, "While trying to detect a safe offset, failed to mmap a GEM.\n");
    exit(1);
  }
  *batch = MI_BATCH_BUFFER_END;
  munmap(batch, bb_size);

  while (1) {
    obj.offset = start_offset;

    if(i915_gem_execbuf(fd, &eb) == 0) {
      break;
    }

    if (start_offset)
      start_offset <<= 1;
    else
      start_offset = PAGE_SIZE;

    if (start_offset >= 1ull << 32)
      obj.flags |= EXEC_OBJECT_SUPPORTS_48B_ADDRESS;
  }
  
  /* Cleanup */
  i915_gem_close(fd, obj.handle);
  i915_ctx_destroy(fd, ctx);

  /* Return the safe offset */
  return start_offset;
}
      
uint64_t i915_safe_offset_for_memory_regions(int fd, struct drm_i915_query_memory_regions *regions) {
  struct drm_i915_gem_memory_class_instance region;
  uint64_t offset = 0, tmp_offset;
  
  for_each_memory_region(regions, region) {
    tmp_offset = i915_detect_safe_offset_for_region(fd, &region);
    if(tmp_offset > offset) {
      offset = tmp_offset;
    }
  }
  
  return offset;
}

/*******************
*   BATCHBUFFERS   *
*******************/

int i915_batchbuf_create(int fd, uint32_t ctx, uint32_t size, uint64_t start, uint64_t end) {
  uint64_t safe_offset;
  
  safe_offset = i915_safe_offset_for_memory_regions(fd, regions

  start = max_t(uint64_t, start, gem_detect_safe_start_offset(i915));
}
