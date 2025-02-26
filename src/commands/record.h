#pragma once

#include "drm_helpers/drm_helpers.h"

extern char bb_debug;
extern char debug_collector;
extern int g_samples_matched;
extern int g_samples_unmatched;

extern device_info devinfo;

void record(int argc, char **argv);
