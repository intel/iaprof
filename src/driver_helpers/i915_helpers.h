#pragma once

#include "drm_helpers/drm_helpers.h"

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

static int64_t sign_extend64(uint64_t value, int index);
static inline uint64_t CANONICAL(uint64_t offset);
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
                                struct drm_i915_query_engine_info *engines);

int i915_ctx_create(int fd, uint32_t *ctx_id);

int i915_ctx_destroy(int fd, uint32_t ctx_id);

/*******************
*       GEM        *
*******************/

int i915_gem_create(int fd, uint64_t *size, uint32_t *handle,
                    struct i915_user_extension *ext);
void *i915_gem_mmap(int fd, uint32_t handle, uint64_t size, unsigned int prot,
                    uint64_t flags);
int i915_gem_execbuf(int fd, struct drm_i915_gem_execbuffer2 *execbuf);
int i915_gem_execbuf_wr(int fd, struct drm_i915_gem_execbuffer2 *execbuf);
uint64_t i915_gem_aperture_size(int fd);
uint32_t i915_gem_get_caching(int fd, uint32_t handle);
void *i915_gem_mmap_offset(int fd, uint32_t handle, uint64_t offset,
                           uint64_t size, unsigned int prot, uint64_t flags);
void *i915_gem_mmap_offset_cpu(int fd, uint32_t handle, uint64_t offset,
                               uint64_t size, unsigned prot);
void *i915_gem_mmap_cpu_coherent(int fd, uint32_t handle, uint64_t offset,
                                 uint64_t size, unsigned prot);
int i915_gem_set_domain(int fd, uint32_t handle, uint32_t read, uint32_t write);
int i915_gem_wait(int fd, uint32_t handle, int64_t *timeout_ns);
void i915_gem_sync(int fd, uint32_t handle);
int i915_gem_write(int fd, uint32_t handle, uint64_t offset, const void *buf,
                   uint64_t length);
int i915_gem_close(int fd, uint32_t handle);

/*******************
*     ENGINES      *
*******************/

int i915_query_engines(int fd, struct drm_i915_query_engine_info **qei);

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
                              struct drm_i915_query_memory_regions **regions);
int i915_gem_create_in_memory_regions(
        int fd, uint32_t *handle, uint64_t *size,
        const struct drm_i915_gem_memory_class_instance *regions,
        int num_regions);
uint64_t i915_detect_safe_offset_for_region(
        int fd, struct drm_i915_gem_memory_class_instance *region);
uint64_t i915_safe_offset_for_memory_regions(
        int fd, struct drm_i915_query_memory_regions *regions);

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
                              int alignment);
static inline unsigned int i915_buff_width(const struct buff *buf);
static inline unsigned int i915_buff_height(const struct buff *buf);

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

static int __compare_objects(const void *p1, const void *p2);
struct drm_i915_gem_exec_object2 *
i915_batchbuf_add_to_cache(struct batchbuffer *bb, uint32_t handle);
struct drm_i915_gem_exec_object2 *
i915_batchbuf_add_object(struct batchbuffer *bb, uint32_t handle, uint64_t size,
                         uint64_t offset, uint64_t alignment, bool write);
struct drm_i915_gem_exec_object2 *i915_batchbuf_add_buff(struct batchbuffer *bb,
                                                         struct buff *buf,
                                                         uint64_t alignment,
                                                         bool write);
struct drm_i915_gem_exec_object2 *
i915_batchbuf_find_object(struct batchbuffer *bb, uint32_t handle);
struct batchbuffer *i915_batchbuf_create(device_info *devinfo, uint32_t ctx,
                                         uint64_t size);
static uint64_t i915_batchbuf_add_reloc(struct batchbuffer *bb,
                                        uint32_t to_handle, uint32_t handle,
                                        uint32_t read_domains,
                                        uint32_t write_domain, uint64_t delta,
                                        uint64_t offset,
                                        uint64_t presumed_offset);
static inline void i915_batchbuf_out(struct batchbuffer *bb, uint32_t dword);
static uint64_t i915_batchbuf_emit_reloc(struct batchbuffer *bb,
                                         uint32_t to_handle, uint32_t to_offset,
                                         uint32_t handle, uint32_t read_domains,
                                         uint32_t write_domain, uint64_t delta,
                                         uint64_t presumed_offset);
static inline uint32_t i915_batchbuf_offset(struct batchbuffer *bb);
void i915_batchbuf_ptr_set(struct batchbuffer *bb, uint32_t offset);
void i915_batchbuf_ptr_align(struct batchbuffer *bb, uint32_t alignment);
void *i915_batchbuf_ptr(struct batchbuffer *bb);
void i915_batchbuf_ptr_add(struct batchbuffer *bb, uint32_t add);
void i915_batchbuf_destroy(struct batchbuffer *bb);

struct sync_merge_data {
        char name[32];
        __s32 fd2;
        __s32 fence;
        __u32 flags;
        __u32 pad;
};

#define SYNC_IOC_MAGIC '>'
#define SYNC_IOC_MERGE _IOWR(SYNC_IOC_MAGIC, 3, struct sync_merge_data)

int i915_sync_fence_merge(int fd1, int fd2);
static struct drm_i915_gem_exec_object2 *
i915_batchbuf_create_objects_array(struct batchbuffer *bb);
static void
i915_batchbuf_update_offsets(struct batchbuffer *bb,
                             struct drm_i915_gem_exec_object2 *objects);
int i915_batchbuf_exec(struct batchbuffer *bb, uint32_t end_offset,
                       uint64_t flags, bool sync);
