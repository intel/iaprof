#pragma once

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <search.h>
#include <unistd.h>
#include <drm/i915_drm_prelim.h>

#include "drm_helper.h"

#define PAGE_SIZE 4096
#define GEM_MAX_ENGINES (PRELIM_I915_EXEC_ENGINE_MASK + 1)
#define QUERY_SIZE \
	offsetof(struct drm_i915_query_engine_info, engines[GEM_MAX_ENGINES])
#ifndef ALIGN
#define ALIGN(x, y) (((x) + (y)-1) & -(y))
#endif

/*******************
*    Utilities     *
*******************/
#define GEN8_GTT_ADDRESS_WIDTH 48

static int64_t sign_extend64(uint64_t value, int index)
{
	int shift = 63 - index;
	return (int64_t)(value << shift) >> shift;
}

static inline uint64_t CANONICAL(uint64_t offset)
{
	return sign_extend64(offset, GEN8_GTT_ADDRESS_WIDTH - 1);
}
#define DECANONICAL(offset) (offset & ((1ull << GEN8_GTT_ADDRESS_WIDTH) - 1))

/*******************
*   GPU Commands   *
*******************/

/* Offsets in the instruction fields */
#define INSTR_MI_CLIENT 0x0
#define INSTR_CLIENT_SHIFT 29
#define __INSTR(client) ((client) << INSTR_CLIENT_SHIFT)

/* Memory interface instructions */
#define MI_INSTR(opcode, flags) \
	(__INSTR(INSTR_MI_CLIENT) | (opcode) << 23 | (flags))
#define MI_BATCH_BUFFER_END MI_INSTR(0x0a, 0)

/*******************
*     CONTEXT      *
*******************/

#define for_each_engine(engines__, engine__)                   \
	/* Beginning condition */                              \
	for (int iter__ = 0; /* Finished condition */          \
	     (iter__ < engines__->num_engines) &&              \
	     (engine__ = &(engines__->engines[iter__].engine), \
	     1); /* Incrementing */                            \
	     iter__ += 1)

int i915_ctx_create_all_engines(int fd, uint32_t *ctx_id,
				struct drm_i915_query_engine_info *engines)
{
	int i;
	struct drm_i915_gem_context_create_ext create;
	struct drm_i915_gem_context_create_ext_setparam engines_param;
	I915_DEFINE_CONTEXT_PARAM_ENGINES(phys_engines, GEM_MAX_ENGINES);

	if (engines->num_engines > GEM_MAX_ENGINES) {
		fprintf(stderr,
			"The number of engines is larger than the maximum.\n");
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
	create.extensions = (uintptr_t)&engines_param.base;
	if (ioctl_do(fd, DRM_IOCTL_I915_GEM_CONTEXT_CREATE_EXT, &create) != 0) {
		fprintf(stderr, "Failed to create a context.\n");
		ioctl_err(errno);
		return -errno;
	}
	*ctx_id = create.ctx_id;
	return 0;
}

int i915_ctx_create(int fd, uint32_t *ctx_id)
{
	int i;
	struct drm_i915_gem_context_create create;

	/* Create the context */
	memset(&create, 0, sizeof(create));
	if (ioctl_do(fd, DRM_IOCTL_I915_GEM_CONTEXT_CREATE, &create) != 0) {
		fprintf(stderr, "Failed to create a context.\n");
		ioctl_err(errno);
		return -errno;
	}
	*ctx_id = create.ctx_id;
	return 0;
}

int i915_ctx_destroy(int fd, uint32_t ctx_id)
{
	struct drm_i915_gem_context_destroy destroy = { ctx_id };

	if (ioctl_do(fd, DRM_IOCTL_I915_GEM_CONTEXT_DESTROY, &destroy) != 0) {
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
int i915_gem_create(int fd, uint64_t *size, uint32_t *handle,
		    struct i915_user_extension *ext)
{
	int err;

	struct prelim_drm_i915_gem_create_ext create = {
		.size = *size,
	};

	if (ext) {
		create.extensions = (uintptr_t)ext;
	}

	if (ioctl_do(fd, PRELIM_DRM_IOCTL_I915_GEM_CREATE_EXT, &create) != 0) {
		fprintf(stderr, "Failed to create a GEM.\n");
		ioctl_err(errno);
		return -errno;
	}
	*handle = create.handle;
	*size = create.size;
	return 0;
}

void *i915_gem_mmap(int fd, uint32_t handle, uint64_t size, unsigned int prot,
		    uint64_t flags)
{
	void *ptr;

	struct drm_i915_gem_mmap_offset arg = {
		.handle = handle,
		.flags = flags,
	};

	if (ioctl_do(fd, DRM_IOCTL_I915_GEM_MMAP_OFFSET, &arg) != 0) {
		fprintf(stderr, "Failed to mmap a GEM!\n");
		return NULL;
	}

	ptr = mmap(0, size, prot, MAP_SHARED, fd, arg.offset);

	if (ptr == MAP_FAILED) {
		return NULL;
	}

	return ptr;
}

int i915_gem_execbuf(int fd, struct drm_i915_gem_execbuffer2 *execbuf)
{
	int ret;
	ret = ioctl_do(fd, DRM_IOCTL_I915_GEM_EXECBUFFER2, execbuf);
	if (ret != 0) {
		fprintf(stderr, "Failed to submit an execbuf\n");
		ioctl_err(errno);
		return -1;
	}
	return 0;
}

int i915_gem_execbuf_wr(int fd, struct drm_i915_gem_execbuffer2 *execbuf)
{
	int ret;
	ret = ioctl_do(fd, DRM_IOCTL_I915_GEM_EXECBUFFER2_WR, execbuf);
	if (ret != 0) {
		fprintf(stderr, "Failed to submit an execbuf (wr)\n");
		fflush(stderr);
		ioctl_err(errno);
		return -1;
	}
	return 0;
}

uint64_t i915_gem_aperture_size(int fd)
{
	int err;
	struct drm_i915_gem_context_param p = {
		.param = I915_CONTEXT_PARAM_GTT_SIZE
	};

	/*   if (__gem_context_get_param(fd, &p)) */
	/*     p.value = gem_global_aperture_size(fd); */

	if (ioctl_do(fd, DRM_IOCTL_I915_GEM_CONTEXT_GETPARAM, &p)) {
		ioctl_err(errno);
		fprintf(stderr, "Failed to request the aperture size!\n");
		return -1;
	}

	return p.value;
}

uint32_t i915_gem_get_caching(int fd, uint32_t handle)
{
	struct drm_i915_gem_caching arg;
	int ret;

	memset(&arg, 0, sizeof(arg));
	arg.handle = handle;
	ret = ioctl_do(fd, DRM_IOCTL_I915_GEM_GET_CACHING, &arg);
	if (ret != 0) {
		fprintf(stderr, "Failed to get the caching bits.\n");
		ioctl_err(errno);
	}

	return arg.caching;
}

void *i915_gem_mmap_offset(int fd, uint32_t handle, uint64_t offset,
			   uint64_t size, unsigned int prot, uint64_t flags)
{
	struct drm_i915_gem_mmap_offset arg;
	void *ptr;

	memset(&arg, 0, sizeof(arg));
	arg.handle = handle;
	arg.flags = flags;

	if (ioctl_do(fd, DRM_IOCTL_I915_GEM_MMAP_OFFSET, &arg)) {
		return NULL;
	}

	ptr = mmap(0, size, prot, MAP_SHARED, fd, arg.offset + offset);

	if (ptr == MAP_FAILED)
		ptr = NULL;
	else
		errno = 0;

	return ptr;
}

void *i915_gem_mmap_offset_cpu(int fd, uint32_t handle, uint64_t offset,
			       uint64_t size, unsigned prot)
{
	void *ptr;

	ptr = i915_gem_mmap_offset(fd, handle, offset, size, prot,
				   I915_MMAP_OFFSET_WB);
	if (!ptr) {
		fprintf(stderr, "Failed to get the offset of the GEM.\n");
		/*     ptr = __gem_mmap_offset__fixed(fd, handle, offset, size, prot); */
	}

	return ptr;
}

void *i915_gem_mmap_cpu_coherent(int fd, uint32_t handle, uint64_t offset,
				 uint64_t size, unsigned prot)
{
	void *ptr = i915_gem_mmap_offset_cpu(fd, handle, offset, size, prot);
	if (!ptr) {
		fprintf(stderr, "Failed to get the coherent offset.\n");
		/*     ptr = __gem_mmap__cpu(fd, handle, offset, size, prot); */
	}
	return ptr;
}

int i915_gem_set_domain(int fd, uint32_t handle, uint32_t read, uint32_t write)
{
	struct drm_i915_gem_set_domain set_domain;
	int err;

	memset(&set_domain, 0, sizeof(set_domain));
	set_domain.handle = handle;
	set_domain.read_domains = read;
	set_domain.write_domain = write;

	if (ioctl_do(fd, DRM_IOCTL_I915_GEM_SET_DOMAIN, &set_domain)) {
		fprintf(stderr, "Failed to set the GEM domain.\n");
		return -1;
	}
	return 0;
}

int i915_gem_wait(int fd, uint32_t handle, int64_t *timeout_ns)
{
	struct drm_i915_gem_wait wait;
	int ret;

	memset(&wait, 0, sizeof(wait));
	wait.bo_handle = handle;
	wait.timeout_ns = timeout_ns ? *timeout_ns : -1;
	wait.flags = 0;

	ret = 0;
	if (ioctl_do(fd, DRM_IOCTL_I915_GEM_WAIT, &wait)) {
		fprintf(stderr, "Failed to wait on the GEM.\n");
		ioctl_err(errno);
		return -1;
	}

	if (timeout_ns) {
		*timeout_ns = wait.timeout_ns;
	}

	return 0;
}

void i915_gem_sync(int fd, uint32_t handle)
{
	if (i915_gem_wait(fd, handle, NULL))
		i915_gem_set_domain(fd, handle, I915_GEM_DOMAIN_GTT,
				    I915_GEM_DOMAIN_GTT);
	errno = 0;
}

int i915_gem_write(int fd, uint32_t handle, uint64_t offset, const void *buf,
		   uint64_t length)
{
	void *map = NULL;

	if (!length)
		return -1;

	if (i915_gem_get_caching(fd, handle) != 0) {
		/* offset arg for mmap functions must be 0 */
		map = i915_gem_mmap_cpu_coherent(fd, handle, 0, offset + length,
						 PROT_READ | PROT_WRITE);
		if (map)
			i915_gem_set_domain(fd, handle, I915_GEM_DOMAIN_CPU,
					    I915_GEM_DOMAIN_CPU);
	}

	memcpy(map + offset, buf, length);
	munmap(map, offset + length);
	return 0;
}

int i915_gem_close(int fd, uint32_t handle)
{
	struct drm_gem_close close = { .handle = handle };
	if (ioctl_do(fd, DRM_IOCTL_GEM_CLOSE, &close) != 0) {
		fprintf(stderr, "Failed to close a GEM.\n");
		ioctl_err(errno);
		return -1;
	}
	return 0;
}

/*******************
*     ENGINES      *
*******************/

int i915_query_engines(int fd, struct drm_i915_query_engine_info **qei)
{
	unsigned int num_engines;
	int ret;

	/* Allocate room for the engine info */
	*qei = (void *)calloc(QUERY_SIZE, sizeof(uint8_t));

	/* Construct the query struct */
	struct drm_i915_query_item item = {
		.query_id = DRM_I915_QUERY_ENGINE_INFO,
		.data_ptr = (uintptr_t)*qei,
		.length = QUERY_SIZE,
	};
	struct drm_i915_query q = {
		.num_items = 1,
		.items_ptr = (uintptr_t)&item,
	};

	/* Call the query itself */
	ret = ioctl_do(fd, DRM_IOCTL_I915_QUERY, &q);
	if (ret) {
		return -1;
	}

	return 0;
}

/*******************
*  MEMORY REGIONS  *
*******************/

#define INTEL_MEMORY_REGION_ID(type, instance) ((type) << 16u | (instance))

#define for_each_memory_region(regions__, region__)                            \
	/* Beginning condition */                                              \
	for (int iter__ = 0; /* Finished condition */                          \
	     (iter__ < regions__->num_regions) &&                              \
	     (region__ = regions__->regions[iter__].region,                    \
	     1); /* Incrementing */                                            \
	     iter__ += ((region__.memory_class != I915_MEMORY_CLASS_SYSTEM) && \
			(region__.memory_class != I915_MEMORY_CLASS_DEVICE)) ? \
			       2 :                                             \
			       1)

int i915_query_memory_regions(int fd,
			      struct drm_i915_query_memory_regions **regions)
{
	int ret;

	/* Construct the query and ioctl it */
	struct drm_i915_query_item item = {
		.query_id = DRM_I915_QUERY_MEMORY_REGIONS,
	};
	struct drm_i915_query q = {
		.num_items = 1,
		.items_ptr = (uintptr_t)&item,
	};
	ret = ioctl_do(fd, DRM_IOCTL_I915_QUERY, &q);
	if (item.length < 0) {
		fprintf(stderr,
			"Failed to get the size of the memory regions.\n");
		return -1;
	}

	/* Now allocate room for the regions themselves */
	*regions = calloc(1, item.length);
	item.data_ptr = (uintptr_t)*regions;

	/* Query again */
	struct drm_i915_query q_items = {
		.num_items = 1,
		.items_ptr = (uintptr_t)&item,
	};
	ret = ioctl_do(fd, DRM_IOCTL_I915_QUERY, &q_items);
	if (ret != 0) {
		fprintf(stderr, "Failed to get the memory regions.\n");
		return -1;
	}

	return 0;
}

int i915_gem_create_in_memory_regions(
	int fd, uint32_t *handle, uint64_t *size,
	const struct drm_i915_gem_memory_class_instance *regions,
	int num_regions)
{
	int ret;

	struct prelim_drm_i915_gem_object_param region_param = {
		.size = num_regions,
		.data = (uintptr_t)regions,
		.param = PRELIM_I915_OBJECT_PARAM |
			 PRELIM_I915_PARAM_MEMORY_REGIONS,
	};
	struct prelim_drm_i915_gem_create_ext_setparam setparam_region = {
		.base = { .name = PRELIM_I915_GEM_CREATE_EXT_SETPARAM },
		.param = region_param,
	};

	ret = i915_gem_create(fd, size, handle, &setparam_region.base);
	if (ret != 0) {
		fprintf(stderr, "Failed to create a GEM in memory regions.\n");
		return -1;
	}

	return 0;
}

uint64_t i915_detect_safe_offset_for_region(
	int fd, struct drm_i915_gem_memory_class_instance *region)
{
	int ret;
	uint32_t ctx, *batch;
	uint64_t bb_size = PAGE_SIZE, start_offset = 0;
	struct drm_i915_gem_exec_object2 obj = {};
	struct drm_i915_gem_execbuffer2 eb = {};

	/* Create a new context */
	i915_ctx_create(fd, &ctx);

	/* Initialize the execbuf */
	eb.buffers_ptr = (uintptr_t)(&obj);
	eb.buffer_count = 1;
	eb.flags = I915_EXEC_DEFAULT;
	eb.rsvd1 = ctx;
	obj.flags = EXEC_OBJECT_PINNED;

	/* Create a GEM that creates one command */
	ret = i915_gem_create_in_memory_regions(fd, &(obj.handle), &bb_size,
						region, 1);
	if (ret != 0) {
		fprintf(stderr,
			"While trying to detect a safe offset, failed to create a GEM.\n");
		exit(1);
	}
	batch = i915_gem_mmap(fd, obj.handle, bb_size, PROT_WRITE,
			      I915_MMAP_OFFSET_WC);
	if (batch == NULL) {
		fprintf(stderr,
			"While trying to detect a safe offset, failed to mmap a GEM.\n");
		exit(1);
	}
	*batch = MI_BATCH_BUFFER_END;
	munmap(batch, bb_size);

	while (1) {
		obj.offset = start_offset;

		if (i915_gem_execbuf(fd, &eb) == 0) {
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

uint64_t i915_safe_offset_for_memory_regions(
	int fd, struct drm_i915_query_memory_regions *regions)
{
	struct drm_i915_gem_memory_class_instance region;
	uint64_t offset = 0, tmp_offset;

	for_each_memory_region(regions, region)
	{
		tmp_offset = i915_detect_safe_offset_for_region(fd, &region);
		if (tmp_offset > offset) {
			offset = tmp_offset;
		}
	}

	return offset;
}

/*******************
*     BUFFERS      *
*******************/

#define BUFF_INVALID_ADDRESS (-1ull)

enum buff_mocs {
	INTEL_BUF_MOCS_DEFAULT,
	INTEL_BUF_MOCS_UC,
	INTEL_BUF_MOCS_WB,
};

struct buff {
	uint64_t size, bo_size;
	uint32_t handle, bpp;
	enum buff_mocs mocs;

	struct {
		uint32_t offset;
		uint32_t stride;
		uint64_t size;
	} surface[2];

	struct {
		uint64_t offset;
		uint32_t ctx;
	} addr;
};

struct buff *i915_buff_create(uint32_t handle, int width, int height, int bpp,
			      int alignment)
{
	uint64_t size;
	struct buff *buf;

	buf = calloc(1, sizeof(struct buff));
	buf->mocs = INTEL_BUF_MOCS_DEFAULT;
	buf->surface[0].stride = ALIGN(width * (bpp / 8), alignment ?: 1);
	buf->surface[0].size = buf->surface[0].stride * height;
	buf->addr.offset = BUFF_INVALID_ADDRESS;
	buf->bpp = bpp;

	buf->size = buf->surface[0].stride * height;
	buf->handle = handle;
	buf->bo_size = buf->size;

	return buf;
}

static inline unsigned int i915_buff_width(const struct buff *buf)
{
	return buf->surface[0].stride / (buf->bpp / 8);
}

static inline unsigned int i915_buff_height(const struct buff *buf)
{
	return buf->surface[0].size / buf->surface[0].stride;
}

/*******************
*   BATCHBUFFERS   *
*******************/

#define MINIMUM_OBJECTS 64
#define BATCH_STATE_SPLIT 2048

struct batchbuffer {
	int fd;
	uint64_t size;
	uint64_t gtt_size;
	uint32_t ctx;
	uint32_t handle;
	uint32_t *ptr;
	uint32_t *batch;
	uint64_t batch_offset;
	uint64_t alignment;
	int fence;

	/* These are buffs that we added to this batchbuffer.
     We need to keep track of them so that we can update
     their offsets before execution. */
	struct buff *buffs;

	/* Relocations */
	struct drm_i915_gem_relocation_entry *relocs;
	uint32_t num_relocs;
	uint32_t allocated_relocs;

	/* A binary tree "cache" of objects,
     so's we can find 'em and edit 'em */
	void *cache;

	/* Array of object pointers */
	struct drm_i915_gem_exec_object2 **objects;
	uint32_t num_objects, num_alloc_objects;
};

static int __compare_objects(const void *p1, const void *p2)
{
	const struct drm_i915_gem_exec_object2 *o1 = p1, *o2 = p2;

	return (int)((int64_t)o1->handle - (int64_t)o2->handle);
}

struct drm_i915_gem_exec_object2 *
i915_batchbuf_add_to_cache(struct batchbuffer *bb, uint32_t handle)
{
	struct drm_i915_gem_exec_object2 **found, *object;

	object = malloc(sizeof(struct drm_i915_gem_exec_object2));

	object->handle = handle;
	object->alignment = 0;
	found = tsearch((void *)object, &(bb->cache), __compare_objects);

	if (*found == object) {
		memset(object, 0, sizeof(struct drm_i915_gem_exec_object2));
		object->handle = handle;
		object->offset = BUFF_INVALID_ADDRESS;
	} else {
		free(object);
		object = *found;
	}

	return object;
}

struct drm_i915_gem_exec_object2 *
i915_batchbuf_add_object(struct batchbuffer *bb, uint32_t handle, uint64_t size,
			 uint64_t offset, uint64_t alignment, bool write)
{
	struct drm_i915_gem_exec_object2 *object;
	uint32_t prev_num_alloc_objects;

	object = i915_batchbuf_add_to_cache(bb, handle);
	object->handle = handle;
	if (write) {
		object->flags |= EXEC_OBJECT_WRITE;
	}

	if (object->offset == BUFF_INVALID_ADDRESS) {
		if (offset == BUFF_INVALID_ADDRESS) {
			offset = 0;
		} else {
			offset = offset & (bb->gtt_size - 1);
		}
	}

	object->offset = offset;

	if (bb->num_objects <= bb->num_alloc_objects) {
		/* We need to allocate more room */
		prev_num_alloc_objects = bb->num_alloc_objects;
		if (bb->objects == NULL) {
			bb->num_alloc_objects = MINIMUM_OBJECTS;
		} else {
			bb->num_alloc_objects *= 2;
		}
		bb->objects = realloc(
			bb->objects,
			bb->num_alloc_objects *
				sizeof(struct drm_i915_gem_exec_object2 *));
		memset(&(bb->objects[prev_num_alloc_objects]), 0,
		       bb->num_alloc_objects - prev_num_alloc_objects);
	}

	bb->objects[bb->num_objects++] = object;
	return object;
}

struct drm_i915_gem_exec_object2 *i915_batchbuf_add_buff(struct batchbuffer *bb,
							 struct buff *buf,
							 uint64_t alignment,
							 bool write)
{
	struct drm_i915_gem_exec_object2 *object;

	if (!alignment) {
		alignment = 0x1000;
		while (alignment < buf->surface[0].size) {
			alignment <<= 1;
		}
	}

	object = i915_batchbuf_add_object(bb, buf->handle, buf->bo_size,
					  buf->addr.offset, alignment, write);
	buf->addr.offset = object->offset;

	return object;
}

struct drm_i915_gem_exec_object2 *
i915_batchbuf_find_object(struct batchbuffer *bb, uint32_t handle)
{
	struct drm_i915_gem_exec_object2 object = { .handle = handle };
	struct drm_i915_gem_exec_object2 **found;

	found = tfind((void *)&object, &bb->cache, __compare_objects);
	if (!found)
		return NULL;

	return *found;
}

struct batchbuffer *i915_batchbuf_create(device_info *devinfo, uint32_t ctx,
					 uint64_t size)
{
	int ret;
	uint64_t start;
	struct batchbuffer *bb;
	struct drm_i915_gem_exec_object2 *object;

	start = i915_safe_offset_for_memory_regions(devinfo->fd,
						    devinfo->memory_regions);
	printf("The safe starting offset is: %" PRIu64 "\n", start);

	/* Initialize the batchbuffer */
	bb = calloc(1, sizeof(struct batchbuffer));
	ret = i915_gem_create(devinfo->fd, &size, &(bb->handle), NULL);
	if (ret != 0) {
		fprintf(stderr,
			"Failed to create a GEM while creating a batchbuffer.\n");
		return NULL;
	}
	bb->size = size;
	bb->ctx = ctx;
	bb->batch = calloc(1, size);
	bb->ptr = bb->batch;
	bb->alignment = 0;
	bb->objects = NULL;
	bb->num_objects = 0;
	bb->num_alloc_objects = 0;
	bb->fence = -1;
	bb->fd = devinfo->fd;

	bb->gtt_size = i915_gem_aperture_size(devinfo->fd);

	object = i915_batchbuf_add_object(bb, bb->handle, bb->size,
					  BUFF_INVALID_ADDRESS, bb->alignment,
					  false);
	bb->batch_offset = object->offset;

	return bb;
}

static uint64_t i915_batchbuf_add_reloc(struct batchbuffer *bb,
					uint32_t to_handle, uint32_t handle,
					uint32_t read_domains,
					uint32_t write_domain, uint64_t delta,
					uint64_t offset,
					uint64_t presumed_offset)
{
	struct drm_i915_gem_relocation_entry *relocs;
	struct drm_i915_gem_exec_object2 *object, *to_object;
	uint32_t i;

	object = i915_batchbuf_find_object(bb, handle);

	if (to_handle == bb->handle) {
		relocs = bb->relocs;
		if (bb->num_relocs == bb->allocated_relocs) {
			/* We need to allocate more room */
			bb->allocated_relocs += 4096 / sizeof(*relocs);
			relocs = realloc(relocs, sizeof(*relocs) *
							 bb->allocated_relocs);
			bb->relocs = relocs;
		}
		i = bb->num_relocs++;
	} else {
		to_object = i915_batchbuf_find_object(bb, to_handle);

		i = to_object->relocation_count++;
		relocs = (struct drm_i915_gem_relocation_entry *)
				 to_object->relocs_ptr;
		relocs = realloc(relocs,
				 sizeof(*relocs) * to_object->relocation_count);
		to_object->relocs_ptr = (uintptr_t)relocs;
	}

	memset(&relocs[i], 0, sizeof(*relocs));
	relocs[i].target_handle = handle;
	relocs[i].read_domains = read_domains;
	relocs[i].write_domain = write_domain;
	relocs[i].delta = delta;
	relocs[i].offset = offset;
	relocs[i].presumed_offset = -1;

out:
	return object->offset;
}

static inline void i915_batchbuf_out(struct batchbuffer *bb, uint32_t dword)
{
	*bb->ptr = dword;
	bb->ptr++;
}

static uint64_t i915_batchbuf_emit_reloc(struct batchbuffer *bb,
					 uint32_t to_handle, uint32_t to_offset,
					 uint32_t handle, uint32_t read_domains,
					 uint32_t write_domain, uint64_t delta,
					 uint64_t presumed_offset)
{
	uint64_t address;

	address = i915_batchbuf_add_reloc(bb, to_handle, handle, read_domains,
					  write_domain, delta, to_offset,
					  presumed_offset);

	i915_batchbuf_out(bb, delta + address);
	i915_batchbuf_out(bb, (delta + address) >> 32);

	return address;
}

static inline uint32_t i915_batchbuf_offset(struct batchbuffer *bb)
{
	return (uint32_t)((uint8_t *)bb->ptr - (uint8_t *)bb->batch);
}

void i915_batchbuf_ptr_set(struct batchbuffer *bb, uint32_t offset)
{
	bb->ptr = (void *)((uint8_t *)bb->batch + offset);
}

void i915_batchbuf_ptr_align(struct batchbuffer *bb, uint32_t alignment)
{
	i915_batchbuf_ptr_set(bb, ALIGN(i915_batchbuf_offset(bb), alignment));
}

void *i915_batchbuf_ptr(struct batchbuffer *bb)
{
	return (void *)bb->ptr;
}

void i915_batchbuf_ptr_add(struct batchbuffer *bb, uint32_t add)
{
	i915_batchbuf_ptr_set(bb, i915_batchbuf_offset(bb) + add);
}

void i915_batchbuf_destroy(struct batchbuffer *bb)
{
	/*   __i915_batchbuf_remove_intel_bufs(bb); */
	/*   __i915_batchbuf_destroy_relocations(bb); */
	/*   __i915_batchbuf_destroy_objects(bb); */
	/*   __i915_batchbuf_destroy_cache(bb); */

	i915_gem_close(bb->fd, bb->handle);

	/*   if (bb->fence >= 0) */
	/*     close(bb->fence); */

	free(bb->batch);
	free(bb);
}

struct sync_merge_data {
	char name[32];
	__s32 fd2;
	__s32 fence;
	__u32 flags;
	__u32 pad;
};

#define SYNC_IOC_MAGIC '>'
#define SYNC_IOC_MERGE _IOWR(SYNC_IOC_MAGIC, 3, struct sync_merge_data)

int i915_sync_fence_merge(int fd1, int fd2)
{
	struct sync_merge_data data = { .fd2 = fd2 };

	if (ioctl_do(fd1, SYNC_IOC_MERGE, &data)) {
		ioctl_err(errno);
		fprintf(stderr, "Failed to create a new fence!\n");
		return -1;
	}

	return data.fence;
}

static struct drm_i915_gem_exec_object2 *
i915_batchbuf_create_objects_array(struct batchbuffer *bb)
{
	struct drm_i915_gem_exec_object2 *objects;
	uint32_t i;

	objects = malloc(sizeof(*objects) * bb->num_objects);

	for (i = 0; i < bb->num_objects; i++) {
		objects[i] = *(bb->objects[i]);
		objects[i].offset = CANONICAL(objects[i].offset);
	}

	return objects;
}

static void
i915_batchbuf_update_offsets(struct batchbuffer *bb,
			     struct drm_i915_gem_exec_object2 *objects)
{
	struct drm_i915_gem_exec_object2 *object;
	struct buff *entry;
	uint32_t i;

	for (i = 0; i < bb->num_objects; i++) {
		object = i915_batchbuf_find_object(bb, objects[i].handle);

		object->offset = DECANONICAL(objects[i].offset);

		if (i == 0)
			bb->batch_offset = object->offset;
	}

	/*   igt_list_for_each_entry(entry, &bb->intel_bufs, link) { */
	/*     object = i915_batchbuf_find_object(bb, entry->handle); */
	/*     entry->addr.offset = object->offset; */
	/*     entry->addr.ctx = bb->ctx; */
	/*   } */
}

int i915_batchbuf_exec(struct batchbuffer *bb, uint32_t end_offset,
		       uint64_t flags, bool sync)
{
	struct drm_i915_gem_execbuffer2 execbuf;
	struct drm_i915_gem_exec_object2 *objects;
	int ret, fence, new_fence;

	bb->objects[0]->relocs_ptr = (uintptr_t)bb->relocs;
	bb->objects[0]->relocation_count = bb->num_relocs;
	bb->objects[0]->handle = bb->handle;
	bb->objects[0]->offset = bb->batch_offset;

	printf("Writing to bb->batch: %p\n", bb->batch);
	i915_gem_write(bb->fd, bb->handle, 0, bb->batch, bb->size);

	memset(&execbuf, 0, sizeof(execbuf));
	objects = i915_batchbuf_create_objects_array(bb);
	execbuf.buffers_ptr = (uintptr_t)objects;
	execbuf.buffer_count = bb->num_objects;
	execbuf.batch_len = end_offset;
	execbuf.rsvd1 = bb->ctx;
	execbuf.flags = flags | I915_EXEC_BATCH_FIRST | I915_EXEC_FENCE_OUT;
	execbuf.flags &= ~I915_EXEC_NO_RELOC;
	execbuf.rsvd2 = 0;

	/*   if (bb->dump_base64) */
	/*     intel_bb_dump_base64(bb, LINELEN); */

	/* For debugging on CI, remove in final series */
	/*   intel_bb_dump_execbuf(bb, &execbuf); */

	ret = i915_gem_execbuf_wr(bb->fd, &execbuf);
	if (ret) {
		free(objects);
		fprintf(stderr,
			"Failed to submit the execbuf from the batchbuffer.\n");
		return -1;
		/*     intel_bb_dump_execbuf(bb, &execbuf); */
		/*     free(objects); */
		/*     return ret; */
	}

	/* Update addresses in the cache */
	i915_batchbuf_update_offsets(bb, objects);

	/* Save/merge fences */
	fence = execbuf.rsvd2 >> 32;

	if (bb->fence < 0) {
		bb->fence = fence;
	} else {
		new_fence = i915_sync_fence_merge(bb->fence, fence);
		close(bb->fence);
		close(fence);
		bb->fence = new_fence;
	}

	/* DEBUG */
	/*   intel_bb_dump_execbuf(bb, &execbuf); */
	/*   if (intel_bb_debug_tree) { */
	/*     igt_info("\nTree:\n"); */
	/*     twalk(bb->root, print_node); */
	/*   } */

	free(objects);

	return 0;
}
