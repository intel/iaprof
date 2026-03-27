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

enum {
    PROBE_EVENT_IBA,
    PROBE_EVENT_KERNEL_LAUNCH,
    PROBE_EVENT_KERNEL_INFO,
    PROBE_EVENT_KERNEL_BIN,
    PROBE_EVENT_FRAME_INFO,
    PROBE_EVENT_KERNEL_PATH,
};

#define PROBES_MAX_BINARY_SIZE   (1024 * 1024)
#define PROBES_MAX_SYMBOL_SIZE   (4096)
#define PROBES_MAX_FILENAME_SIZE (4096)
#define TASK_COMM_LEN            (16)
#define MAX_STACK_DEPTH          (512)

struct stack {
    __s64 len;
    __u64 addrs[MAX_STACK_DEPTH];
    __u32 pid;
};

struct probe_event_kernel_launch {
    __u8         type;

    __u64        addr;
    __u64        size;

    struct stack stack;

    __u64        time;
    __u32        pid;
    __u32        tid;
    __u32        cpu;
    char         name[TASK_COMM_LEN];
};

struct probe_event_iba {
    __u8  type;

    __u64 addr;

    __u32 pid;
    __u32 tid;
};

struct probe_event_elf {
    __u8          type;

    __u64         size;
    unsigned char data[PROBES_MAX_BINARY_SIZE];
};

struct probe_event_kernel {
    __u8  type;

    __u64 addr;

    __u64 size;
    char  symbol[PROBES_MAX_SYMBOL_SIZE];
    char  filename[PROBES_MAX_FILENAME_SIZE];
    int   linenum;
};

struct probe_event_kernel_path {
    __u8  type;

    __u32 pid;
    __u32 tid;
    char  filename[PROBES_MAX_FILENAME_SIZE];
};

struct probe_event_kernel_bin {
    __u8          type;

    __u64         addr;

    __u64         size;
    unsigned char data[PROBES_MAX_BINARY_SIZE];
};

struct probe_event_frame {
    __u8 type;
};
