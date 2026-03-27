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
#include "device_info.hpp"
#include "symbolizer.hpp"
#include "profile.hpp"

#define IAPROF_VERSION             "2026.2"
#define DEFAULT_INTERVAL           (10)
#define DEFAULT_EU_STALL_SUBSAMPLE (100)

extern bool        debug;
extern std::mutex  debug_print_mtx;
extern s64         profile_interval_ms;
extern s64         eu_stall_subsample;
extern Device_Info device_info;
extern Symbolizer  symbolizer;
extern Profile     profile;
