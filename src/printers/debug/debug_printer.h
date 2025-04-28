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
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

extern char debug;
extern pthread_mutex_t debug_print_lock;

#define EVENT_LEN 14
#define TIME_LEN 14
#define CPU_LEN 4
#define PID_LEN 8
#define TID_LEN 8

struct vm_create_info;
struct vm_bind_info;
struct vm_unbind_info;
struct execbuf_info;
struct eustall_sample;

void print_header();
void print_vm_create(struct vm_create_info *info);
void print_vm_bind(struct vm_bind_info *info, uint32_t vm_bind_counter);
void print_vm_unbind(struct vm_unbind_info *info);
void print_execbuf(struct execbuf_info *info);

void print_total_eustall(uint64_t num, unsigned long long time);
void print_debug_profile();

#define debug_printf(...)                                \
do {                                                     \
        if (debug) {                                     \
                pthread_mutex_lock(&debug_print_lock);   \
                fprintf(stderr, __VA_ARGS__);            \
                fflush(stderr);                          \
                pthread_mutex_unlock(&debug_print_lock); \
        }                                                \
} while (0)

#define ERR(_fmt, ...)                                   \
do {                                                     \
        int _save_errno = errno;                         \
        fprintf(stderr, "%sERROR%s: " _fmt,              \
                isatty(2) ? "\e[0;31m" : "",             \
                isatty(2) ? "\e[00m" : "",               \
                ##__VA_ARGS__);                          \
        if (_save_errno) { exit(_save_errno); }          \
        exit(1);                                         \
} while (0)

#define ERR_NOEXIT(_fmt, ...)                            \
do {                                                     \
    fprintf(stderr, "%sERROR%s: " _fmt,                  \
            isatty(2) ? "\e[0;31m" : "",                 \
            isatty(2) ? "\e[00m" : "",                   \
            ##__VA_ARGS__);                              \
} while (0)

#define WARN(_fmt, ...)                                  \
do {                                                     \
    fprintf(stderr, "%sWARNING%s: " _fmt,                \
            isatty(2) ? "\e[0;33m" : "",                 \
            isatty(2) ? "\e[00m" : "",                   \
            ##__VA_ARGS__);                              \
} while (0)

#define INFO(_fmt, ...)                                  \
do {                                                     \
    fprintf(stderr, "%INFO%s: " _fmt,                    \
            isatty(2) ? "\e[0;36m" : "",                 \
            isatty(2) ? "\e[00m" : "",                   \
            ##__VA_ARGS__);                              \
} while (0)
