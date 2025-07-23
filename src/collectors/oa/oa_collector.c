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

#include <stdlib.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <unistd.h>

#include "iaprof.h"
#include "drm_helpers/drm_helpers.h"
#include "collectors/oa/oa_collector.h"
#include "printers/debug/debug_printer.h"

/* Driver-specific stuff */
#if GPU_DRIVER == GPU_DRIVER_xe
#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>
#include <uapi/drm/xe_drm_eudebug.h>
#include "driver_helpers/xe_helpers.h"
#elif GPU_DRIVER == GPU_DRIVER_i915
#include <drm/i915_drm_prelim.h>
#include "driver_helpers/i915_helpers.h"
#endif

uint64_t safe_diff(uint64_t val, uint64_t prev_val, unsigned num_bits)
{
        if (prev_val > val) {
                if (num_bits == 64) {
                        return UINT64_MAX - prev_val + val;
                }
                return (val | (1ULL << num_bits)) - prev_val;
        }
        return val - prev_val;
}

int handle_oa_read(void *buf, int len, struct device_info *devinfo)
{
        struct pec_report_format *report = (struct pec_report_format *)buf;
        int i, num_reports;
        uint64_t diff_time, diff_ticks;
        uint32_t tile_id;
        
        if (len <= 0) {
                debug_printf("OA read: invalid buffer length %d\n", len);
                return OA_STATUS_ERROR;
        }
        
        num_reports = len / sizeof(struct pec_report_format);
        for (i = 0; i < num_reports; i++) {
                /* Get the command streamer type (render, blit, compute) and CCS ID */
                tile_id = TILE_ID(report[i].rpt_id);
                if (tile_id != 0) {
                        fprintf(stderr, "TILE_ID is: %u\n", tile_id);
                        return -1;
                }
                
                if (!oa_info.prev_report[tile_id].rpt_id &&
                    !oa_info.prev_report[tile_id].time && 
                    !oa_info.prev_report[tile_id].ticks) {
                        goto next;
                }
                
                
                diff_time  = ((safe_diff(report[i].time, oa_info.prev_report[tile_id].time, 56) * 100) / (oa_info.timestamp_freq / 100000)) * 100;
                diff_ticks = safe_diff(report[i].ticks, oa_info.prev_report[tile_id].ticks, 32);
                
                oa_info.metrics.avg_mhz   = (diff_ticks * 1000) / diff_time;
                oa_info.metrics.busy_perc = (uint64_t)((((double)safe_diff(report[i].busy, oa_info.prev_report[tile_id].busy, 64)) / diff_ticks) * 100);
                
                debug_printf("Avg MHz:    %lu\n",   oa_info.metrics.avg_mhz);
                debug_printf("Busy:       %lu%%\n", oa_info.metrics.busy_perc);
next:
                memcpy(&(oa_info.prev_report[tile_id]), &(report[i]), sizeof(struct pec_report_format));
        }
        
        /* Update statistics */
        oa_info.samples_read++;
        oa_info.bytes_read += len;
        
        return OA_STATUS_OK;
}



int init_oa(struct device_info *devinfo)
{
        int fd;
        
        /* Initialize the oa_info structure */
        memset(&oa_info, 0, sizeof(oa_info));
        
#if GPU_DRIVER == GPU_DRIVER_xe
        fd = xe_init_oa(devinfo);
#elif GPU_DRIVER == GPU_DRIVER_i915
        /* TODO: Add i915 support if needed */
        fprintf(stderr, "OA collector not yet supported for i915 driver\n");
        return -1;
#endif
        
        if (fd <= 0) {
                fprintf(stderr, "Failed to initialize OA collector. Aborting.\n");
                return -1;
        }
        
        /* Store the file descriptor */
        oa_info.fd = fd;
        oa_info.timestamp_freq = devinfo->oa_timestamp_freq;
        
        debug_printf("OA collector initialized with fd=%d\n", fd);
        
        return 0;
}
