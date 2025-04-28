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
