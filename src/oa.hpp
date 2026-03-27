/*
Copyright 2026 Intel Corporation

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

#include "common.hpp"

struct __attribute__((packed)) pec_report_format {
    u64 rpt_id, time,
        ctx_id, ticks,
        pec0,  pec1,  pec2,  pec3,
        pec4,  pec5,  pec6,  pec7,
        pec8,  pec9,  pec10, pec11,
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
};

#define REPORT_REASON(val) (((val) >> 19) & 0x7F)
#define TILE_ID(val)       (((val) >> 32) & 0x3)
#define SOURCE_ID(val)     (((val) >> 25) & 0x3F)

struct OA_Metrics {
    u64 avg_mhz   = 0;
    u64 busy_perc = 0;
};

class OA_Collector {
    bool        initialized         = false;
    std::mutex  init_mtx;
    std::thread thr;
    int         thread_stop_pipe[2] = { -1, -1 };
    int         fd                  = -1;

    std::mutex        metrics_mtx;
    OA_Metrics        metrics;
    pec_report_format prev_report = {};
    bool              has_prev    = false;
    u64               buf_size    = 0;

    ~OA_Collector();

    bool init();
    void handle_report(const pec_report_format &report);
    static void oa_thread(OA_Collector &collector);

public:
    static OA_Collector &get();
    OA_Metrics get_metrics();
};
