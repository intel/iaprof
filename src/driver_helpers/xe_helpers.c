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
