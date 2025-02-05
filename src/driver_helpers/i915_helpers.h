#pragma once

#include "drm_helpers/drm_helpers.h"

#define PAGE_SIZE (4096)
#define GEM_MAX_ENGINES (PRELIM_I915_EXEC_ENGINE_MASK + 1)
#define QUERY_SIZE \
        offsetof(struct drm_i915_query_engine_info, engines[GEM_MAX_ENGINES])
#ifndef ALIGN
#define ALIGN(x, y) (((x) + (y)-1) & -(y))
#endif

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

/*******************
*     ENGINES      *
*******************/

int i915_query_engines(int fd, struct drm_i915_query_engine_info **qei);
int i915_init_eustall(struct device_info *devinfo);
