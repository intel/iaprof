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

#include "globals.hpp"

bool        debug                 = true;
std::mutex  debug_print_mtx       = {};
s64         profile_interval_ms   = DEFAULT_INTERVAL;
s64         eu_stall_subsample    = DEFAULT_EU_STALL_SUBSAMPLE;
Device_Info device_info           = {};
Symbolizer  symbolizer            = {};
Profile     profile               = {};
