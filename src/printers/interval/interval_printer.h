#pragma once

#include <stdio.h>
#include <stdint.h>
#include <linux/types.h>
#include "collectors/bpf/bpf/main.h"

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

extern uint64_t failed_decode_id;

struct eustall_result {
        uint64_t proc_name_id, gpu_file_id, gpu_symbol_id,
                 insn_text_id, stall_type_id,
                 ustack_id, kstack_id;
        
        unsigned pid;
        uint64_t samp_offset, samp_count;
        int is_debug, is_sys;
};

void print_initial_strings();
char *get_string(uint64_t id);
void parse_interval_profile();
uint64_t print_string(const char *str);
void print_interval(uint64_t interval);
int get_profile_event_func(char *str, size_t *size, int (**func_ptr)(char *, void *), enum profile_event *event);
