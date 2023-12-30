#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>

#include "drm_helper.h"
#include "i915_helper.h"
#include "pvc_helper.h"

#include "gpgpu_fill.h"

#define THREADS 1
#define NUM_ITERS 10
#define ARR_SIZE 1024*1024

#define ALIGN(x, y) (((x) + (y) - 1) & -(y))
#define WIDTH 64
#define HEIGHT 64
#define STRIDE (WIDTH)
#define SIZE (HEIGHT*STRIDE)
#define COLOR 0xa5
#define INVERSE 0x5a

/* void fillfunc(int fd, uint32_t ctx, unsigned int engine, */
/*              struct intel_buf *buf, */
/*              unsigned x, unsigned y, */
/*              unsigned width, unsigned height, */
/*              uint8_t color) { */
/*    */
/* } */

/*   fill(data->drm_fd, */
/*        ctx_id, e->flags, */
/*        buf, 0, 0, WIDTH / 2, HEIGHT / 2, */
/*        INVERSE); */


void pvc_fill(device_info *devinfo, struct buff *buf, unsigned int engine_flags,
              unsigned int width, unsigned int height, unsigned int x, unsigned int y,
              uint8_t color) {
  struct batchbuffer *bb;
  struct drm_i915_gem_exec_object2 *object;
  struct pvc_interface_descriptor_data idd;
  int ret;
  
  bb = i915_batchbuf_create(devinfo, devinfo->ctx_id, PAGE_SIZE);
  object = i915_batchbuf_add_buff(bb, buf, 0, true);
  
  i915_batchbuf_ptr_set(bb, BATCH_STATE_SPLIT);
  pvc_fill_interface_descriptor(bb, buf, gpgpu_kernel, sizeof(gpgpu_kernel), &idd);
  i915_batchbuf_ptr_set(bb, 0);

  /* GPGPU pipeline */
  i915_batchbuf_out(bb, GEN7_PIPELINE_SELECT | GEN9_PIPELINE_SELECTION_MASK |
      PIPELINE_SELECT_GPGPU);
  pvc_emit_state_base_address(bb);
  pvc_emit_state_compute_mode(bb);
  pvc_emit_state_binding_table_pool_alloc(bb);
  pvc_emit_cfe_state(bb, THREADS);
  pvc_emit_compute_walk(bb, x, y, width, height, &idd, color);

  i915_batchbuf_out(bb, MI_BATCH_BUFFER_END);
  i915_batchbuf_ptr_align(bb, 32);

  ret = i915_batchbuf_exec(bb, i915_batchbuf_offset(bb),
                           engine_flags | I915_EXEC_NO_RELOC, false);
  if(ret != 0) {
    fprintf(stderr, "Failed to execute the batchbuffer!\n");
    exit(1);
  }

  i915_batchbuf_destroy(bb);
}

void gpgpu_fill_iter(device_info *devinfo, const struct drm_i915_gem_memory_class_instance *region, unsigned int engine_flags) {
  int width, height, i, j, ret;
  uint8_t bpp, *ptr, val;
  uint32_t gem_handle, stride;
  uint32_t binding_table_offset, kernel_offset;
  uint64_t size = SIZE;
  struct buff *buf;
  
  /* Create a GEM in this particular memory region */
  ret = i915_gem_create_in_memory_regions(devinfo->fd, &gem_handle, &size, region, 1);
  if(ret != 0) {
    exit(1);
  }
  
  /* Wrap it in a buff */
  buf = i915_buff_create(gem_handle, WIDTH / 4, HEIGHT, 32, 0);
  
  /* mmap the buffer to initialize it */
  ptr = i915_gem_mmap(devinfo->fd, gem_handle, buf->surface[0].size, PROT_WRITE, I915_MMAP_OFFSET_WC);
  
  /* Initialize the buffer */
  for (i = 0; i < buf->surface[0].size; i++) {
    ptr[i] = COLOR;
  }

  /* Unmap the buffer */
  munmap(ptr, buf->surface[0].size);
  
  /* Now read the buffer */
  ptr = i915_gem_mmap(devinfo->fd, gem_handle, buf->surface[0].size, PROT_READ, I915_MMAP_OFFSET_WC);
  
  /* Sanity check */
  for (i = 0; i < WIDTH; i++) {
    for (j = 0; j < HEIGHT; j++) {
      val = ptr[j * WIDTH + i];
      if (val != COLOR)
        fprintf(stderr, "Expected 0x%02x, found 0x%02x at (%d,%d)\n",
            COLOR, val, i, j);
    }
  }
  
  pvc_fill(devinfo, buf, engine_flags, WIDTH / 2, HEIGHT / 2, 0, 0, INVERSE);
  pvc_fill(devinfo, buf, engine_flags, WIDTH / 2, HEIGHT / 2, WIDTH / 2, HEIGHT / 2, INVERSE | COLOR);
  
  for (i = 0; i < WIDTH; i++) {
    for (j = 0; j < HEIGHT; j++) {
      if (i < WIDTH / 2 && j < HEIGHT / 2) {
        val = ptr[j * WIDTH + i];
        if (val != INVERSE)
          fprintf(stderr, "Expected 0x%02x, found 0x%02x at (%d,%d)\n",
              INVERSE, val, i, j);
      } else if (i >= WIDTH / 2 && j >= HEIGHT / 2) {
        val = ptr[j * WIDTH + i];
        if (val != (INVERSE | COLOR))
          fprintf(stderr, "Expected 0x%02x, found 0x%02x at (%d,%d)\n",
              INVERSE | COLOR, val, i, j);
      } else {
        val = ptr[j * WIDTH + i];
        if (val != COLOR)
          fprintf(stderr, "Expected 0x%02x, found 0x%02x at (%d,%d)\n",
              COLOR, val, i, j);
      }
    }
  }

  munmap(ptr, buf->surface[0].size);
}

void gpgpu_fill(device_info *devinfo) {
  int i;
  struct drm_i915_gem_relocation_entry *reloc;
  struct drm_i915_gem_memory_class_instance region;
  
  uint64_t size = 4096;
  uint32_t handle, *buf, *src, *dst;
  int ret;
  
  /* Create a context */
  if(i915_ctx_create_all_engines(devinfo->fd, &(devinfo->ctx_id), devinfo->engine_info) != 0) {
    exit(1);
  }
  
  printf("Printing out %d regions:\n", devinfo->memory_regions->num_regions);
  for_each_memory_region(devinfo->memory_regions, region) {
    printf("  ID = %d\n", INTEL_MEMORY_REGION_ID(region.memory_class, region.memory_instance));
    for(i = 0; i < devinfo->engine_info->num_engines; i++) {
      gpgpu_fill_iter(devinfo, &region, i);
    }
  }
}

int main() {
  struct device_info *devinfo;
  
  /* Grab the i915 driver file descriptor */
  devinfo = open_first_driver();
  if(!devinfo) {
    fprintf(stderr, "Failed to open any drivers. Aborting.\n");
    exit(1);
  }

  /* Get information about the device */
  if(get_drm_device_info(devinfo) != 0) {
    fprintf(stderr, "Failed to get device info. Aborting.\n");
    exit(1);
  }
  
  /* Get the physical engines */
  if(i915_query_engines(devinfo->fd, &(devinfo->engine_info)) != 0) {
    fprintf(stderr, "Failed to query the engines. Aborting.\n");
    exit(1);
  }
  
  /* Get the memory regions */
  if(i915_query_memory_regions(devinfo->fd, &(devinfo->memory_regions)) != 0) {
    fprintf(stderr, "Failed to query the memory regions. Aborting.\n");
    exit(1);
  }

  printf("Device ID: 0x%X\n", devinfo->id);
  
  gpgpu_fill(devinfo);
}
