#pragma once

#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include "drm_helpers/drm_helpers.h"

extern char debug;
extern char bb_debug;
extern char verbose;
extern char debug_collector;
extern int g_samples_matched;
extern int g_samples_unmatched;

extern device_info devinfo;

extern pthread_mutex_t debug_print_lock;

void add_to_epoll_fd(int fd);

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
