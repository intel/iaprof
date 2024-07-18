#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <drm/i915_drm_prelim.h>
#include <drm/i915_drm.h>

/*******************
*    DISCOVERY     *
*******************/

#define DRIVER_BASE "/dev/dri/card"

typedef struct device_info {
	uint32_t id, ctx_id;
	char name[16];
	int fd;
	uint64_t min_freq, max_freq;
	unsigned graphics_ver, graphics_rel;
	struct drm_i915_query_engine_info *engine_info;
	struct drm_i915_query_memory_regions *memory_regions;
} device_info;

#define IP_VER(ver, rel) ((ver) << 8 | (rel))
static const int num_pvc_ids = 9;
static const uint32_t pvc_ids[] = { 0x0b69, 0x0bd0, 0x0bd5, 0x0bd6, 0x0bd7,
				    0x0bd8, 0x0bd9, 0x0bda, 0x0bdb };

void ioctl_err(int err);
int ioctl_do(int fd, unsigned long request, void *arg);
int open_first_driver(device_info *devinfo);
int open_sysfs_dir(int fd);
bool read_fd_uint64(int fd, uint64_t *out_value);
bool read_sysfs(int sysfs_dir_fd, const char *file_path, uint64_t *out_value);
int get_drm_device_info(device_info *devinfo);
uint32_t get_drm_device_id(device_info *devinfo);
void free_driver(device_info *devinfo);
