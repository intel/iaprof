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

#include "eustall.hpp"
#include "globals.hpp"

#define EUSTALL_READ_BUFFER_SIZE (2 * 1024 * 1024)

void EU_Stall_Collector::eustall_thread(EU_Stall_Collector &eustall_collector) {
    bool                       stop = false;
    std::vector<struct pollfd> pfds;

    int eustall_fd = device_info.get_eustall_fd();

    pfds.push_back({ .fd = eustall_fd,                            .events = POLLIN });
    pfds.push_back({ .fd = eustall_collector.thread_stop_pipe[0], .events = POLLIN });

    while (!stop) {
        int n_ready;
        while ((n_ready = poll(pfds.data(), pfds.size(), -1)) == EINTR && n_ready == 0);
        if (n_ready < 0) {
            ERR("poll failed with errno {}\n", errno);
        }

        for (auto &pfd : pfds) {
            if (!(pfd.revents & POLLIN)) { continue; }

            if (pfd.fd == eustall_collector.thread_stop_pipe[0]) {
                stop = true;
                break;
            } else if (pfd.fd == eustall_fd) {
                static u8 buff[EUSTALL_READ_BUFFER_SIZE];

                ssize_t len = read(eustall_fd, buff, sizeof(buff));
                if (len < 0) {
                    WARN("Failed to read EU stall samples. (errno = {})\n", errno);
                    continue;
                }

                u64 record_size = device_info.record_size;
                for (ssize_t i = 0; i + (ssize_t)record_size <= len; i += record_size) {
                    eustall_collector.counter += 1;
                    if (eustall_collector.counter % eustall_collector.sample_period != 0) { continue; }

                    auto *sample = (EU_Stall_Sample *)(buff + i);
                    eustall_collector.handle_sample(*sample);
                }

            }
        }
    }
}

EU_Stall_Collector::~EU_Stall_Collector() {
    INFO("matched: {} unmatched: {}\n", this->matched, this->unmatched);
    write(this->thread_stop_pipe[1], "stop", 4);
    this->thr.join();
}

bool EU_Stall_Collector::handle_sample(const EU_Stall_Sample &sample) {
    u64 addr = ((u64)sample.ip << 3) + this->iba;

    if (auto locked_kernel = profile.find_kernel_at(addr)) {
        u64 offset = addr - (*locked_kernel)->gpu_addr;

        auto &oprof = (*locked_kernel)->offset_profile[offset];

        oprof.active     += sample.active;
        oprof.control    += sample.control;
        oprof.pipestall  += sample.pipestall;
        oprof.send       += sample.send;
        oprof.dist_acc   += sample.dist_acc;
        oprof.sbid       += sample.sbid;
        oprof.sync       += sample.sync;
        oprof.inst_fetch += sample.inst_fetch;
        oprof.other      += sample.other;
        oprof.tdr        += sample.tdr;

        this->matched += 1;
    } else {
        this->unmatched += 1;
        return false;
    }

    return true;
}

bool EU_Stall_Collector::init() {
    pipe(this->thread_stop_pipe);

    this->fd = device_info.get_eustall_fd();
    if (this->fd < 0) { return false; }

    this->sample_period = eu_stall_subsample;

    this->thr = std::thread(eustall_thread, std::ref(*this));

    this->initialized = true;

    return true;
}

EU_Stall_Collector &EU_Stall_Collector::get() {
    static EU_Stall_Collector collector;

    if (!collector.initialized) {
        std::scoped_lock lock(collector.init_mtx);

        if (!collector.initialized) {
            if (!collector.init()) {
                ERR("Failed to initialize EU stall collector.\n");
            }
        }
    }

    return collector;
}

void EU_Stall_Collector::set_instruction_base_address(u64 addr) {
    this->iba = addr;
}
