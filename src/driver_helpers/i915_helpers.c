#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <search.h>
#include <unistd.h>

#include <drm/i915_drm_prelim.h>

#include "i915_helpers.h"

/*******************
*     ENGINES      *
*******************/

int i915_query_engines(int fd, struct drm_i915_query_engine_info **qei)
{
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

int i915_init_eustall(struct device_info *devinfo)
{
        fprintf(stderr, "UNIMPLEMENTED i915_init_eustall\n");
        return 0;
}
