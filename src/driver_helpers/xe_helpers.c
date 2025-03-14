#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <search.h>
#include <unistd.h>

#include <stdbool.h>
#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>

#include "xe_helpers.h"

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
        *properties = realloc(*properties, (*index + 1) * sizeof(struct drm_xe_ext_set_property));
        (*properties)[*index].base.name = DRM_XE_EU_STALL_EXTENSION_SET_PROPERTY;
        (*properties)[*index].base.pad = 0;
        (*properties)[*index].property = property;
        (*properties)[*index].value = value;
        (*properties)[*index].pad = 0;
        if (*index > 0) {
                (*properties)[*index - 1].base.next_extension = (__u64)&((*properties)[*index]);
        }
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
        if (stall_info) {
                devinfo->record_size = stall_info->record_size;
                free(stall_info);
        }
        if (retval) {
                return retval;
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
        free(qg);
        if (!found) {
                fprintf(stderr, "Failed to find any GTs of type DRM_XE_QUERY_GT_TYPE_MAIN! Aborting.\n");
                return -1;
        }
        xe_print_props(properties);
        
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
                return -1;
        }
        
        /* Enable the fd */
        retval = ioctl_do(fd, DRM_XE_OBSERVATION_IOCTL_ENABLE, NULL);
        if (retval < 0) {
                fprintf(stderr, "Failed to enable the perf file descriptor.\n");
                return -1;
        }

        return fd;
}
