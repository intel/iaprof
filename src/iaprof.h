#pragma once

#include "drm_helpers/drm_helpers.h"

extern char debug;
extern char bb_debug;
extern char verbose;
extern char gpu_syms;
extern int g_samples_matched;
extern int g_samples_unmatched;

extern device_info devinfo;

void add_to_epoll_fd(int fd);
