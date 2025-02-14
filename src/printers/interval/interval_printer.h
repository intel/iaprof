#pragma once

#include <stdio.h>
#include <stdint.h>
#include <linux/types.h>
#include "collectors/bpf_i915/bpf/main.h"

enum profile_event {
        PROFILE_EVENT_STRING = 0,
        PROFILE_EVENT_EUSTALL = 1,
        PROFILE_EVENT_INTERVAL_START = 2,
        PROFILE_EVENT_INTERVAL_END = 3,
        PROFILE_EVENT_MAX
};

/* Maximum string sizes, so we don't have to guess */
#define MAX_PROC_NAME_LEN (16)
#define MAX_PID_LEN (10)
#define MAX_GPU_FILE_LEN (4096 + 16)
#define MAX_GPU_SYMBOL_LEN (4096 + 16)
#define MAX_INSN_TEXT_LEN (32)
#define MAX_STALL_TYPE_LEN (16)
#define MAX_OFFSET_LEN (20)

struct eustall_result {
        char proc_name[MAX_PROC_NAME_LEN + 1];
        char gpu_file[MAX_GPU_FILE_LEN + 1];
        char gpu_symbol[MAX_GPU_SYMBOL_LEN + 1];
        char insn_text[MAX_INSN_TEXT_LEN + 1];
        char stall_type_str[MAX_STALL_TYPE_LEN + 1];
        char *ustack_str, *kstack_str;
        unsigned pid;
        uint64_t samp_offset, samp_count;
        int is_debug, is_sys;
};

void parse_interval_profile();
void print_string(const char *str);
void print_interval(uint64_t interval);
int get_profile_event_func(char *str, size_t *size, int (**func_ptr)(char *, void *), enum profile_event *event);
