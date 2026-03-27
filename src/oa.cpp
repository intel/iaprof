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

#include "oa.hpp"
#include "globals.hpp"

void OA_Collector::oa_thread(OA_Collector &collector) {
    bool                       stop = false;
    std::vector<struct pollfd> pfds;
    std::vector<u8>            buff(collector.buf_size);

    int oa_fd = device_info.get_oa_fd();

    pfds.push_back({ .fd = oa_fd,                         .events = POLLIN });
    pfds.push_back({ .fd = collector.thread_stop_pipe[0], .events = POLLIN });

    while (!stop) {
        int n_ready;
        while ((n_ready = poll(pfds.data(), pfds.size(), -1)) == EINTR && n_ready == 0);
        if (n_ready < 0) {
            ERR("poll failed with errno {}\n", errno);
        }

        for (auto &pfd : pfds) {
            if (!(pfd.revents & POLLIN)) { continue; }

            if (pfd.fd == collector.thread_stop_pipe[0]) {
                stop = true;
                break;
            } else if (pfd.fd == oa_fd) {
                ssize_t len = read(oa_fd, buff.data(), buff.size());
                if (len < 0) {
                    WARN("Failed to read OA reports. (errno = {})\n", errno);
                    continue;
                }

                for (ssize_t i = 0; i + (ssize_t)sizeof(pec_report_format) <= len; i += sizeof(pec_report_format)) {
                    auto *report = (pec_report_format *)(buff.data() + i);
                    if (TILE_ID(report->rpt_id) != 0) {
                        WARN("Unexpected TILE_ID {} in OA report\n", TILE_ID(report->rpt_id));
                        continue;
                    }
                    collector.handle_report(*report);
                }
            }
        }
    }
}

OA_Collector::~OA_Collector() {
    write(this->thread_stop_pipe[1], "stop", 4);
    this->thr.join();
}

static u64 safe_diff(u64 val, u64 prev_val, unsigned num_bits) {
    if (prev_val > val) {
        if (num_bits == 64) {
            return UINT64_MAX - prev_val + val;
        }
        return (val | (1ULL << num_bits)) - prev_val;
    }
    return val - prev_val;
}

void OA_Collector::handle_report(const pec_report_format &report) {
    std::scoped_lock lock(this->metrics_mtx);

    if (!this->has_prev) {
        this->prev_report = report;
        this->has_prev    = true;
        return;
    }

    u64 diff_time  = ((safe_diff(report.time,  this->prev_report.time,  56) * 100) / (device_info.oa_timestamp_freq / 100000)) * 100;
    u64 diff_ticks = safe_diff(report.ticks, this->prev_report.ticks, 32);

    if (diff_ticks > 0) {
        this->metrics.avg_mhz   = (diff_ticks * 1000) / diff_time;
        this->metrics.busy_perc = (u64)(((double)safe_diff(report.busy, this->prev_report.busy, 64) / diff_ticks) * 100);
    }

    this->prev_report = report;
}

bool OA_Collector::init() {
    pipe(this->thread_stop_pipe);

    this->fd = device_info.get_oa_fd();
    if (this->fd < 0) { return false; }

    this->buf_size = device_info.oa_buf_size > 0 ? device_info.oa_buf_size : 1 * 1024 * 1024;

    this->thr = std::thread(oa_thread, std::ref(*this));
    this->initialized = true;
    return true;
}

OA_Collector &OA_Collector::get() {
    static OA_Collector collector;

    if (!collector.initialized) {
        std::scoped_lock lock(collector.init_mtx);
        if (!collector.initialized) {
            if (!collector.init()) {
                ERR("Failed to initialize OA collector.\n");
            }
        }
    }

    return collector;
}

OA_Metrics OA_Collector::get_metrics() {
    std::scoped_lock lock(this->metrics_mtx);
    return this->metrics;
}
