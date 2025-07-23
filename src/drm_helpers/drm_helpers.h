/*
Copyright 2025 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <stdbool.h>
#include <stdint.h>
#if GPU_DRIVER == GPU_DRIVER_xe
#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>
#elif GPU_DRIVER == GPU_DRIVER_i915
#include <drm/i915_drm.h>
#include <drm/i915_drm_prelim.h>
#endif

/*******************
*    DISCOVERY     *
*******************/

#define DRIVER_BASE "/dev/dri/card"

typedef struct device_info {
        uint32_t id, ctx_id;
        char name[16];
        int fd, cardnum;
        uint64_t record_size, va_bits;
        unsigned graphics_ver, graphics_rel;
#if GPU_DRIVER == GPU_DRIVER_xe
        struct drm_xe_query_gt_list *gt_info;
        struct drm_xe_query_eu_stall *stall_info;
        uint64_t oa_timestamp_freq;
#elif GPU_DRIVER == GPU_DRIVER_i915
        struct drm_i915_query_engine_info *engine_info;
        struct drm_i915_query_memory_regions *memory_regions;
#endif
} device_info;

#define IP_VER(ver, rel) ((ver) << 8 | (rel))
static const int num_pci_ids = 16;
static const uint32_t pci_ids[] = {
        /* PVC */
        0x0b69,
        0x0bd0,
        0x0bd5,
        0x0bd6,
        0x0bd7,
        0x0bd8,
        0x0bd9,
        0x0bda,
        0x0bdb,
        0x0be0,
        0x0be1,
        0x0be5,

        /* LNL */
        0x6420,
        0x64a0,
        0x64b0,
        
        /* BMG */
        0xe20b
};

void ioctl_err(int err);
int ioctl_do(int fd, unsigned long request, void *arg);
int open_first_driver(device_info *devinfo);
int open_sysfs_dir(int fd);
bool read_fd_uint64(int fd, uint64_t *out_value);
bool read_sysfs(int sysfs_dir_fd, const char *file_path, uint64_t *out_value);
int get_drm_device_info(device_info *devinfo);
uint32_t get_drm_device_id(device_info *devinfo);
void free_driver(device_info *devinfo);

#define DRM_CANONICALIZE(addr) ((((uint64_t)(addr)) << (64 - devinfo.va_bits)) >> (64 - devinfo.va_bits))
