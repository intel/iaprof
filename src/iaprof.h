#pragma once

#include <pthread.h>

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
