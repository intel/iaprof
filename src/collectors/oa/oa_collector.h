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

#include <inttypes.h>
#include <pthread.h>

#include "drm_helpers/drm_helpers.h"
#include "driver_helpers/xe_helpers.h"
#include "collectors/bpf/bpf_collector.h"

#include "utils/array.h"

/******************************************************************************
* Report Format
* ******
* The struct that the report buffer is filled with.
******************************************************************************/
struct pec_report_format {
        uint64_t rpt_id, time,
                 ctx_id, ticks,
                 pec0, pec1, pec2, pec3,
                 pec4, pec5, pec6, pec7,
                 pec8, pec9, pec10, pec11,
                 pec12, pec13, pec14, pec15,
                 pec16, pec17, pec18, pec19,
                 pec20, pec21, pec22, pec23,
                 pec24, pec25, pec26, pec27,
                 pec28, pec29, pec30, pec31,
                 busy,  pec33, pec34, pec35,
                 pec36, pec37, pec38, pec39,
                 pec40, pec41, pec42, pec43,
                 pec44, pec45, pec46, pec47,
                 pec48, pec49, pec50, pec51,
                 pec52, pec53, pec54, pec55,
                 pec56, pec57, pec58, pec59,
                 pec60, pec61, pec62, pec63;
        char padding[32];
} __attribute__((packed));

#define CCS_ID(val) ((val >> 36) & 0x1F)
#define REPORT_REASON(val) ((val >> 19) & 0x7F)
#define TILE_ID(val) ((val >> 32) & 0x3)
#define SOURCE_ID(val) ((val >> 25) & 0x3F)

#define SOURCE_MEDIA(val) (SOURCE_ID(val) & 0x20)
#define SOURCE_CS(val) (!SOURCE_MEDIA(val) && ((SOURCE_ID(val) & 0x18) == 0x8))
#define SOURCE_SHADERS(val) (!SOURCE_MEDIA(val) && ((SOURCE_ID(val) & 0x18) == 0x10))
#define SOURCE_RCS(val) (!SOURCE_MEDIA(val) && SOURCE_CS(val) && ((SOURCE_ID(val) & 0x3) == 0))
#define SOURCE_CCS(val) (!SOURCE_MEDIA(val) && SOURCE_CS(val) && ((SOURCE_ID(val) & 0x3) == 1))
#define SOURCE_BCS(val) (!SOURCE_MEDIA(val) && SOURCE_CS(val) && ((SOURCE_ID(val) & 0x3) == 2))

/******************************************************************************
* oa_info
* *******
* Struct that stores information about the OA buffer.
******************************************************************************/

#define MAX_TILE 8
struct oa_info_t {
        int fd;
        uint8_t buf[MAX_OA_BUFFER_SIZE];
        
        uint64_t samples_read;
        uint64_t bytes_read;
        uint32_t timestamp_freq;
        
        struct pec_report_format prev_report[MAX_TILE];
        
        struct {
                uint64_t avg_mhz;
                uint64_t busy_perc;
        } metrics;
};
extern struct oa_info_t oa_info;

/******************************************************************************
* Status
* ******
* Return types for the oa collector.
******************************************************************************/
enum oa_status {
        OA_STATUS_OK,
        OA_STATUS_ERROR,
        OA_STATUS_NOTFOUND,
};


struct device_info;

int init_oa(struct device_info *devinfo);
int handle_oa_read(void *buf, int len, struct device_info *devinfo);
