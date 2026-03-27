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

enum {
    EU_STALL_TYPE_ACTIVE,
    EU_STALL_TYPE_CONTROL,
    EU_STALL_TYPE_PIPESTALL,
    EU_STALL_TYPE_SEND,
    EU_STALL_TYPE_DIST_ACC,
    EU_STALL_TYPE_SBID,
    EU_STALL_TYPE_SYNC,
    EU_STALL_TYPE_INST_FETCH,
    EU_STALL_TYPE_OTHER,
    EU_STALL_TYPE_TDR,
    NR_EU_STALL_TYPES,
};

struct __attribute__((__packed__)) EU_Stall_Sample {
    u32 ip          : 29;
    u16 tdr         :  8;
    u16 other       :  8;
    u16 control     :  8;
    u16 pipestall   :  8;
    u16 send        :  8;
    u16 dist_acc    :  8;
    u16 sbid        :  8;
    u16 sync        :  8;
    u16 inst_fetch  :  8;
    u16 active      :  8;
    u16 ex_id       :  8;
    u16 end_flag    :  1;
    u16 unused_bits : 15;
};

struct EU_Stall_Profile {
    union {
        struct {
                u64 active;
                u64 control;
                u64 pipestall;
                u64 send;
                u64 dist_acc;
                u64 sbid;
                u64 sync;
                u64 inst_fetch;
                u64 other;
                u64 tdr;
        };
        u64 counts[NR_EU_STALL_TYPES];
    };
};

class EU_Stall_Collector {
    bool        initialized         = false;
    std::mutex  init_mtx;
    std::thread thr;
    int         thread_stop_pipe[2] = { -1, -1 };
    int         fd                  = -1;
    u64         iba                 = 0;
    u64         counter             = 0;
    u64         sample_period       = 1000;
    u64         matched             = 0;
    u64         unmatched           = 0;

    ~EU_Stall_Collector();

    bool init();
    bool handle_sample(const EU_Stall_Sample &sample);

    static void eustall_thread(EU_Stall_Collector &eustall_collector);

public:
    static EU_Stall_Collector &get();

    void set_instruction_base_address(u64 addr);
};
