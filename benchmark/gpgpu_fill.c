#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>

#include "drm_helper.h"
#include "i915_helper.h"

#include "gpgpu_fill.h"

#define NUM_ITERS 10
#define ARR_SIZE 1024*1024

#define ALIGN(x, y) (((x) + (y) - 1) & -(y))
#define WIDTH 64
#define HEIGHT 64
#define STRIDE (WIDTH)
#define SIZE (HEIGHT*STRIDE)
#define COLOR 0xa5

/* void fillfunc(int fd, uint32_t ctx, unsigned int engine, */
/*              struct intel_buf *buf, */
/*              unsigned x, unsigned y, */
/*              unsigned width, unsigned height, */
/*              uint8_t color) { */
/*    */
/* } */

void gpgpu_fill_iter(int fd, const struct drm_i915_gem_memory_class_instance *region) {
  int width, height, i, j, ret;
  uint8_t bpp, *ptr, val;
  uint32_t gem_handle, stride;
  uint64_t size = SIZE;
  
  /* Create a GEM in this particular memory region */
  ret = i915_gem_create_in_memory_regions(fd, &gem_handle, &size, region, 1);
  if(ret != 0) {
    exit(1);
  }
  
  width = WIDTH / 4;
  height = HEIGHT;
  bpp = 32;
  stride = ALIGN(width * (bpp / 8), 1);
  struct {
    uint32_t stride;
    uint64_t size;
  } surface = {
    .stride = stride,
    .size = stride * height,
  };
  
  /* mmap the buffer to initialize it */
  ptr = i915_gem_mmap(fd, gem_handle, surface.size, PROT_WRITE, I915_MMAP_OFFSET_WC);
  
  /* Initialize the buffer */
  for (i = 0; i < surface.size; i++) {
    ptr[i] = COLOR;
  }

  /* Unmap the buffer */
  munmap(ptr, surface.size);
  
  /* Now read the buffer */
  ptr = i915_gem_mmap(fd, gem_handle, surface.size, PROT_READ, I915_MMAP_OFFSET_WC);
  
  /* Sanity check */
  for (i = 0; i < WIDTH; i++) {
    for (j = 0; j < HEIGHT; j++) {
      val = ptr[j * WIDTH + i];
      if (val != COLOR)
        fprintf(stderr, "Expected 0x%02x, found 0x%02x at (%d,%d)\n",
            COLOR, val, i, j);
    }
  }
  
  /* Now do the actual benchmark */
  
}

void gpgpu_fill(device_info *devinfo) {
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
    gpgpu_fill_iter(devinfo->fd, &region);
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
