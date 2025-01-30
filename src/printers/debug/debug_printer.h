#pragma once

#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

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
void print_eustall(struct eustall_sample *sample, uint64_t gpu_addr,
                  uint64_t offset, uint32_t handle,
                  unsigned long long time);
void print_eustall_churn(struct eustall_sample *sample, uint64_t gpu_addr,
                        uint64_t offset, unsigned long long time);
void print_eustall_drop(struct eustall_sample *sample, uint64_t gpu_addr,
                       unsigned long long time);
void print_eustall_defer(struct eustall_sample *sample, uint64_t gpu_addr,
                        unsigned long long time);
void print_eustall_multichurn(struct eustall_sample *sample, uint64_t gpu_addr,
                             unsigned long long time);
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
