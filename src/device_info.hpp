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

#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>

struct Device_Info {
    u32                           id;
    u32                           ctx_id;
    char                          name[16];
    int                           fd = -1;
    int                           cardnum;
    u64                           record_size;
    u64                           va_bits;
    u32                           graphics_ver;
    u32                           graphics_rel;
    int                           eustall_fd = -1;
    int                           oa_fd = -1;
    u64                           oa_buf_size = 0;
    struct drm_xe_query_eu_stall *stall_info;
    u64                           oa_timestamp_freq;

    void init();
    int  get_eustall_fd();
    int  get_oa_fd();
    u64  canonicalize(u64 addr);
    u64  canonicalized_kernel_addr(u64 addr);

    ~Device_Info();

private:
    int xe_eustall_fd();
    int xe_oa_fd();
};
