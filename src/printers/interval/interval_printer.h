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

#include <stdio.h>
#include <stdint.h>
#include <linux/types.h>
#include "collectors/bpf/bpf/main.h"
#include "utils/array.h"

enum profile_event {
        PROFILE_EVENT_STRING = 0,
        PROFILE_EVENT_EUSTALL = 1,
        PROFILE_EVENT_PROC_NAME = 2,
        PROFILE_EVENT_PID = 3,
        PROFILE_EVENT_USTACK = 4,
        PROFILE_EVENT_KSTACK = 5,
        PROFILE_EVENT_SHADER_TYPE = 6,
        PROFILE_EVENT_GPU_FILE = 7,
        PROFILE_EVENT_GPU_SYMBOL = 8,
        PROFILE_EVENT_INSN_TEXT = 9,
        PROFILE_EVENT_INTERVAL_START = 10,
        PROFILE_EVENT_INTERVAL_END = 11,
        PROFILE_EVENT_MAX = 12
};

/* Maximum string sizes, so we don't have to guess */
#define MAX_PROC_NAME_LEN (16)
#define MAX_PID_LEN (10)
#define MAX_GPU_FILE_LEN (4096 + 16)
#define MAX_GPU_SYMBOL_LEN (4096 + 16)
#define MAX_INSN_TEXT_LEN (32)
#define MAX_STALL_TYPE_LEN (16)
#define MAX_OFFSET_LEN (20)

extern uint64_t failed_decode_id;

struct eustall_result {
        uint64_t proc_name_id, gpu_file_id, gpu_symbol_id,
                 insn_text_id, stall_type_id,
                 ustack_id, kstack_id;

        unsigned pid;
        uint64_t samp_offset, samp_count;
        int shader_type;
};

struct interval_result {
        uint64_t num;
        double time;
};

void print_initial_strings();
char *get_string(uint64_t id);
void parse_interval_profile();
uint64_t print_string(const char *str);
void print_frame();
void print_interval(uint64_t interval, array_t *waitlist);
int get_profile_event_func(char *str, size_t *size, int (**func_ptr)(char *, void *), enum profile_event *event);
