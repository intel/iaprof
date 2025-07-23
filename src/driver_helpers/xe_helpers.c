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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <limits.h>
#include <search.h>
#include <unistd.h>
#include <math.h>

#include <stdbool.h>
#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>

#include "printers/debug/debug_printer.h"
#include "xe_helpers.h"
#include "oa_registers.h"

void xe_print_props(struct drm_xe_ext_set_property *properties)
{
        struct drm_xe_ext_set_property *proptr;
        
        proptr = properties;
        while (proptr) {
                proptr = (struct drm_xe_ext_set_property *)proptr->base.next_extension;
        }
}

void xe_add_prop(struct drm_xe_ext_set_property **properties, int *index, uint32_t property, uint64_t value)
{
        int i;
        
        *properties = realloc(*properties, (*index + 1) * sizeof(struct drm_xe_ext_set_property));
        (*properties)[*index].base.name = DRM_XE_EU_STALL_EXTENSION_SET_PROPERTY;
        (*properties)[*index].base.pad = 0;
        (*properties)[*index].property = property;
        (*properties)[*index].value = value;
        (*properties)[*index].pad = 0;
        
        /* Fix all next_extension pointers after realloc */
        for (i = 0; i < *index; i++) {
                (*properties)[i].base.next_extension = (__u64)&((*properties)[i + 1]);
        }
        /* Ensure the last element has next_extension set to 0 */
        (*properties)[*index].base.next_extension = 0;
        
        (*index)++;
}

/* Gets a list of GTs on the graphics device. */
int xe_query_gts(int fd, struct drm_xe_query_gt_list **qg)
{
        int ret;

        /* Get the size that we should allocate */
        struct drm_xe_device_query query = {
                .query = DRM_XE_DEVICE_QUERY_GT_LIST,
                .size = 0,
        };
        ret = ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
        if (ret) {
                fprintf(stderr, "Failed to query the xe driver's available GTs! Aborting.\n");
                return -1;
        }
        
        *qg = malloc(query.size);
        query.data = (uintptr_t)*qg;
        ret = ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
        if (ret) {
                fprintf(stderr, "Failed to query the xe driver's available GTs! Aborting.\n");
                return -1;
        }

        return 0;
}

/* Gets information about EU stall sampling on this device */
int xe_query_eu_stalls(int fd, struct drm_xe_query_eu_stall **stall_info)
{
        int ret;

        /* Get the size that we should allocate */
        struct drm_xe_device_query query = {
                .query = DRM_XE_DEVICE_QUERY_EU_STALL,
                .size = 0,
        };
        ret = ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
        if (ret) {
                fprintf(stderr, "Failed to query the xe driver's EU stall capabilities! Aborting.\n");
                return -1;
        }
        
        *stall_info = malloc(query.size);
        query.data = (uintptr_t)*stall_info;
        ret = ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
        if (ret) {
                fprintf(stderr, "Failed to query the xe driver's EU stall capabilities! Aborting.\n");
                return -1;
        }
        
        return 0;
}

/* Gets information about OA units on this device */
int xe_query_oa_units(int fd, struct drm_xe_query_oa_units **oa_units_info)
{
        int ret;

        /* Get the size that we should allocate */
        struct drm_xe_device_query query = {
                .query = DRM_XE_DEVICE_QUERY_OA_UNITS,
                .size = 0,
        };
        ret = ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
        if (ret) {
                fprintf(stderr, "Failed to query the xe driver's OA capabilities! Aborting.\n");
                return -1;
        }
        
        *oa_units_info = malloc(query.size);
        query.data = (uintptr_t)*oa_units_info;
        ret = ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
        if (ret) {
                fprintf(stderr, "Failed to query the xe driver's OA capabilities! Aborting.\n");
                return -1;
        }
        
        return 0;
}


/* Initializes eustalls on Xe, returns the resulting fd to read from. */
int xe_init_eustall(struct device_info *devinfo)
{
        struct drm_xe_gt *gt;
        int fd, found, retval, index;
        struct drm_xe_query_gt_list *qg;
        struct drm_xe_query_eu_stall *stall_info;
        struct drm_xe_ext_set_property *properties;
        
        qg = NULL;
        retval = xe_query_gts(devinfo->fd, &qg);
        if (retval) {
                return retval;
        }
        
        /* Get the record size */
        stall_info = NULL;
        retval = xe_query_eu_stalls(devinfo->fd, &stall_info);
        if (retval || !stall_info) {
                return retval;
        }
        devinfo->record_size = stall_info->record_size;
        
        if (!stall_info->num_sampling_rates) {
                fprintf(stderr, "No sampling rates available! Aborting.\n");
                free(stall_info);
                free(qg);
                return -1;
        }
        
        index = 0;
        properties = NULL;
        xe_add_prop(&properties, &index, DRM_XE_EU_STALL_PROP_SAMPLE_RATE, stall_info->sampling_rates[stall_info->num_sampling_rates - 1]);
        xe_add_prop(&properties, &index, DRM_XE_EU_STALL_PROP_WAIT_NUM_REPORTS, 1);
        
        found = 0;
        for_each_gt(qg, gt)
        {
                if (gt->type == DRM_XE_QUERY_GT_TYPE_MAIN) {
                        xe_add_prop(&properties, &index, DRM_XE_EU_STALL_PROP_GT_ID, gt->gt_id);
                        found++;
                }
        }
        free(stall_info);
        free(qg);
        xe_print_props(properties);
        if (!found) {
                fprintf(stderr, "Failed to find any GTs of type DRM_XE_QUERY_GT_TYPE_MAIN! Aborting.\n");
                free(properties);
                return -1;
        }
        
        struct drm_xe_observation_param param = {
                .observation_type = DRM_XE_OBSERVATION_TYPE_EU_STALL,
                .observation_op = DRM_XE_OBSERVATION_OP_STREAM_OPEN,
                .param = (__u64)properties,
                .extensions = 0,
        };
        
        /* Open the fd */
        fd = ioctl_do(devinfo->fd, DRM_IOCTL_XE_OBSERVATION, &param);
        if (fd < 0) {
                fprintf(stderr, "Failed to open the perf file descriptor.\n");
                free(properties);
                return -1;
        }
        
        /* Enable the fd */
        retval = ioctl_do(fd, DRM_XE_OBSERVATION_IOCTL_ENABLE, NULL);
        if (retval < 0) {
                fprintf(stderr, "Failed to enable the perf file descriptor.\n");
                free(properties);
                return -1;
        }

        free(properties);
        return fd;
}

int xe_add_oa_config(struct device_info *devinfo)
{
        int config_id, num_chars;
        const char *uuid = "0c47fabe-3bbf-4b82-9efb-ff7b30f73d90";
        const char *metric_path_format = "/sys/class/drm/card%d/metrics/%s/id";
        char *metric_path, config_id_str[11];
        FILE *file;
        
        if (!devinfo) {
                fprintf(stderr, "Invalid device info! Aborting.\n");
                return -1;
        }
        
        num_chars = snprintf(NULL, 0, metric_path_format, devinfo->cardnum, uuid);
        metric_path = malloc(num_chars + 1);
        if (!metric_path) {
                fprintf(stderr, "Failed to allocate memory for metric path.\n");
                return -1;
        }
        num_chars = snprintf(metric_path, num_chars + 1, metric_path_format, devinfo->cardnum, uuid);
        if (num_chars < 0) {
                fprintf(stderr, "Failed to construct the string for OA metrics.");
                return -1;
        }
        
        file = fopen(metric_path, "r");
        if (file) {
                num_chars = fread(config_id_str, sizeof(char), 10, file);
                fclose(file);
                free(metric_path);
                config_id_str[num_chars] = '\0';
                config_id = (int)strtol(config_id_str, NULL, 10);
                return config_id;
        }
        free(metric_path);
        
        struct drm_xe_oa_config config = {
                .uuid = {},
                .regs_ptr = (uint64_t)&compute_basic_oa_registers,
                .n_regs = sizeof(compute_basic_oa_registers) / 2 / sizeof(uint32_t),
        };
        struct drm_xe_observation_param param = {
                .observation_type = DRM_XE_OBSERVATION_TYPE_OA,
                .observation_op = DRM_XE_OBSERVATION_OP_ADD_CONFIG,
                .param = (uint64_t)&config,
                .extensions = 0,
        };
        
        memcpy(&config.uuid, uuid, 36);
        
        config_id = ioctl_do(devinfo->fd, DRM_IOCTL_XE_OBSERVATION, &param);
        if (config_id < 0) {
                fprintf(stderr, "Failed to add the OA config! Got: %d\n", errno);
                return -1;
        }
        
        return config_id;
}

int xe_get_oa_unit(int fd, struct drm_xe_oa_unit *unit)
{
        int retval, i;
        struct drm_xe_query_oa_units *oa_units_info;
        struct drm_xe_oa_unit *oau;
        uint8_t *poau;
        
        /* Figure out the OA unit ID */
        oa_units_info = NULL;
        retval = xe_query_oa_units(fd, &oa_units_info);
        if (retval) {
                return retval;
        }
        if (!oa_units_info) {
                fprintf(stderr, "Failed to get OA units info! Aborting.\n");
                return -1;
        }
        
        retval = -1;
        poau = (uint8_t *)&oa_units_info->oa_units[0];
        for (i = 0; i < oa_units_info->num_oa_units; i++) {
                oau = (struct drm_xe_oa_unit *)poau;
                poau += sizeof(*oau) + oau->num_engines * sizeof(oau->eci[0]);
                
                debug_printf("OA unit %d, type %d\n", oau->oa_unit_id, oau->oa_unit_type);
                
                if (oau->oa_unit_type == DRM_XE_OA_UNIT_TYPE_OAG) {
                        memcpy(unit, oau, sizeof(struct drm_xe_oa_unit));
                        retval = 0;
                        break;
                }
        }
        free(oa_units_info);
        return retval;
}

/* Initializes eustalls on Xe, returns the resulting fd to read from. */
int xe_init_oa(struct device_info *devinfo)
{
        int retval, config_id, fd, index;
        struct drm_xe_ext_set_property *properties;
        struct drm_xe_oa_unit unit;
        uint32_t unit_id, timestamp_freq;
        
        retval = xe_get_oa_unit(devinfo->fd, &unit);
        if (retval) {
                return retval;
        }
        unit_id = unit.oa_unit_id;
        timestamp_freq = (uint32_t)unit.oa_timestamp_freq;
        devinfo->oa_timestamp_freq = timestamp_freq;
        
        /* Add and receive the metric config ID */
        config_id = xe_add_oa_config(devinfo);
        if (config_id < 1) {
                return config_id;
        }
        
        /* Calculate the period exponent */
        uint64_t period_exponent = (uint64_t)log2(timestamp_freq) - 1;
        
        /* Construct the list of properties */
        properties = NULL;
        index = 0;
        xe_add_prop(&properties, &index, DRM_XE_OA_PROPERTY_OA_UNIT_ID, unit_id);
        debug_printf("DRM_XE_OA_PROPERTY_OA_UNIT_ID=%u\n", unit_id);
        xe_add_prop(&properties, &index, DRM_XE_OA_PROPERTY_SAMPLE_OA, 1);
        xe_add_prop(&properties, &index, DRM_XE_OA_PROPERTY_OA_METRIC_SET, config_id);
        debug_printf("DRM_XE_OA_PROPERTY_OA_METRIC_SET=%d\n", config_id);
        xe_add_prop(&properties, &index, DRM_XE_OA_PROPERTY_OA_FORMAT, DRM_XE_OA_FMT_TYPE_PEC | ( 1 << 8 ) | ( 1 << 16 ) | ( 0 << 24 ) );
        debug_printf("DRM_XE_OA_PROPERTY_OA_FORMAT=%u\n", DRM_XE_OA_FMT_TYPE_PEC | ( 1 << 8 ) | ( 1 << 16 ) | ( 0 << 24 ));
        xe_add_prop(&properties, &index, DRM_XE_OA_PROPERTY_OA_DISABLED, 1);
        xe_add_prop(&properties, &index, DRM_XE_OA_PROPERTY_OA_PERIOD_EXPONENT, period_exponent);
        debug_printf("DRM_XE_OA_PROPERTY_OA_PERIOD_EXPONENT=%lu\n", (unsigned long)period_exponent);
        
        struct drm_xe_observation_param param = {
                .observation_type = DRM_XE_OBSERVATION_TYPE_OA,
                .observation_op = DRM_XE_OBSERVATION_OP_STREAM_OPEN,
                .param = (__u64)properties,
                .extensions = 0,
        };
        
        /* Open the fd */
        fd = ioctl_do(devinfo->fd, DRM_IOCTL_XE_OBSERVATION, &param);
        if (fd < 0) {
                fprintf(stderr, "Failed to open the OA file descriptor. Got: %d\n", errno);
                return -1;
        }
        
        /* Enable the fd */
        retval = ioctl_do(fd, DRM_XE_OBSERVATION_IOCTL_ENABLE, NULL);
        if (retval < 0) {
                fprintf(stderr, "Failed to enable the OA file descriptor. Got: %d\n", errno);
                return -1;
        }

        return fd;
}
