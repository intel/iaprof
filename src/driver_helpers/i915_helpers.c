#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <search.h>
#include <unistd.h>

#include <drm/i915_drm.h>
#include <drm/i915_drm_prelim.h>

#include "iaprof.h"

#include "i915_helpers.h"

/*******************
*  Stall Options   *
*******************/

#define DEFAULT_SAMPLE_RATE 4 /* HW events per sample, max 7 in i915 */
/* XXX ^^^ increase i915 max as this is too low and generates excessive samples */
#define DEFAULT_DSS_BUF_SIZE (128 * 1024)
#define DEFAULT_USER_BUF_SIZE (64 * DEFAULT_DSS_BUF_SIZE)
#define DEFAULT_POLL_PERIOD_NS 1000000 /* userspace wakeup interval */
#define DEFAULT_EVENT_COUNT \
        1 /* aggregation: number of events to trigger poll read */


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
        struct i915_engine_class_instance *engine_class;
        int i, fd, found, retval;
        uint64_t *properties;
        size_t properties_size;

        i = 0;
        properties_size = sizeof(uint64_t) * 5 * 2;
        properties = malloc(properties_size);

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_BUF_SZ;
        properties[i++] = DEFAULT_DSS_BUF_SIZE;

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_SAMPLE_RATE;
        properties[i++] = DEFAULT_SAMPLE_RATE;

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_POLL_PERIOD;
        properties[i++] = DEFAULT_POLL_PERIOD_NS;

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_EVENT_REPORT_COUNT;
        properties[i++] = DEFAULT_EVENT_COUNT;

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_CLASS;
        properties[i++] = 4;

        found = 0;
        for_each_engine(devinfo->engine_info, engine_class)
        {
                if (engine_class->engine_class ==
                    PRELIM_I915_ENGINE_CLASS_COMPUTE) {
                        properties_size += (sizeof(uint64_t) * 2);
                        properties = realloc(properties, properties_size);
                        properties[i++] =
                                PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_INSTANCE;
                        properties[i++] = engine_class->engine_instance;
                        found++;
                }
        }
        if (found == 0) {
                ERR("Didn't find any PRELIM_I915_ENGINE_CLASS_COMPUTE engines.\n");
                return -1;
        }

        struct drm_i915_perf_open_param param = {
                .flags = I915_PERF_FLAG_FD_CLOEXEC |
                         PRELIM_I915_PERF_FLAG_FD_EU_STALL |
                         I915_PERF_FLAG_DISABLED,
                .num_properties = properties_size / (sizeof(uint64_t) * 2),
                .properties_ptr = (unsigned long long)properties,
        };

        /* Open the fd */
        fd = ioctl_do(devinfo->fd, DRM_IOCTL_I915_PERF_OPEN, &param);
        if (fd < 0) {
                ERR("Failed to open the perf file descriptor.\n");
                return -1;
        }

        /* Enable the fd */
        retval = ioctl_do(fd, I915_PERF_IOCTL_ENABLE, NULL);
        if (retval < 0) {
                ERR("Failed to enable the perf file descriptor.\n");
                return -1;
        }

        return fd;
}
