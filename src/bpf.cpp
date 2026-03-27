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


#include "bpf.hpp"
#include "globals.hpp"
#include "eustall.hpp"
#include "profile.hpp"

int BPF_Collector::discover_handle_libze_intel_gpu(discover_libze_intel_gpu *data) {
    std::filesystem::path maps_path = std::format("/proc/{}/maps", data->pid);

    std::ifstream maps(maps_path);

    if (!maps.is_open()) {
        WARN("failed to open {}\n", maps_path.string());
        return 0;
    }

    std::regex lib_re(R"(\d+\s{2,}(/.*libze_intel_gpu\.so.*$))");

    std::string line;
    std::string lib_path;
    while (std::getline(maps, line)) {
        std::smatch match;
        if (std::regex_search(line, match, lib_re)) {
            lib_path = match[1].str();
            break;
        }
    }

    if (lib_path.empty()) { return 0; }

    auto &collector  = BPF_Collector::get();
    auto patcher_obj = collector.patcher.get_obj();
    auto it          = collector.probes.find(lib_path);

    if (it != collector.probes.end()) { return 0; }

    auto &obj = (collector.probes[lib_path] = std::make_unique<BPF_OBJECT(libze_intel_gpu)>());

    if (!obj->open_and_load()) { ERR("Failed to load BPF libze_intel_gpu probes.\n"); }

    std::regex patch_re(R"(usdt/[ ]{4096}(:.*))");

    for (u32 p = 0; p < patcher_obj->bss->prog_count; p += 1) {
        char *sec_name_ptr = nullptr;
        bpf_map__lookup_elem(patcher_obj->maps.prog_sec_names, &p, sizeof(p), &sec_name_ptr, sizeof(sec_name_ptr), 0);

        std::string sec_name(sec_name_ptr);

        std::smatch match;
        if (std::regex_search(sec_name, match, patch_re)) {
            std::string patched = std::format("usdt/{}{}", lib_path, match[1].str());
            memset(sec_name_ptr, 0, strlen(sec_name_ptr));
            strncpy(sec_name_ptr, patched.c_str(), patched.size());
        }
    }

    if (!obj->attach(probes_sample_fn)) { ERR("Failed to attach BPF libze_intel_gpu probes.\n"); }

    INFO("attached probes for {}\n", lib_path);

    return 0;
}

int BPF_Collector::discover_sample_fn(void *ctx, void *data, size_t size) {
    u8 type;

    type = *((u8*)data);

    switch (type) {
        case DISCOVER_LIBZE_INTEL_GPU: return discover_handle_libze_intel_gpu(auto_cast(data));
    }

    ERR("Unknown data type when handling a sample: {}\n", type);
    return -1;
}

int BPF_Collector::handle_probe_event_iba(probe_event_iba *iba_event) {
    EU_Stall_Collector::get().set_instruction_base_address(iba_event->addr);
    return 0;
}

int BPF_Collector::handle_probe_event_kernel_launch(probe_event_kernel_launch *kernel_launch_event) {
    u64 addr = device_info.canonicalize(kernel_launch_event->addr);

    profile.set_kernel_launch_info(addr, kernel_launch_event->size, kernel_launch_event->name, kernel_launch_event->pid, kernel_launch_event->stack);

    INFO("new kernel {:x}\n", addr);

//     auto kernel = profile.get_or_create_kernel(addr);

//     if (kernel->type == GPU_Kernel::Type::Unknown) {
//         kernel->type = GPU_Kernel::Type::Kernel;
//     }

//     kernel->size         = kernel_launch_event->size;
//     kernel->pid          = kernel_launch_event->pid;
//     kernel->stack_id     = profile.get_stack_id(kernel_launch_event->stack);
//     kernel->ustack_id    = print_string(store_ustack(kernel_launch_event->pid, &kernel_launch_event->ustack));
//     kernel->kstack_id    = 0;
//     kernel->proc_name_id = print_string(kernel_launch_event->name);

//     release_kernel(kernel);
//     wakeup_eustall_deferred_attrib_thread();

    return 0;
}

int BPF_Collector::handle_probe_event_kernel_path(probe_event_kernel_path *kernel_path_event) {
    auto syms = symbolizer.get_elf_symbols(kernel_path_event->filename);

    for (auto &sym : syms) {
        profile.set_kernel_debug_info(device_info.canonicalize(sym.addr), sym.symbol, sym.filename, sym.line, sym.binary);
    }

    return 0;
}

int BPF_Collector::probes_sample_fn(void *ctx, void *data, size_t size) {
    u8 type;

    type = *((u8*)data);

    switch (type) {
        case PROBE_EVENT_IBA:           return handle_probe_event_iba(auto_cast(data));
        case PROBE_EVENT_KERNEL_LAUNCH: return handle_probe_event_kernel_launch(auto_cast(data));
        case PROBE_EVENT_KERNEL_PATH:   return handle_probe_event_kernel_path(auto_cast(data));
    }

    ERR("Unknown data type when handling a sample: {}\n", type);
    return -1;
}

void BPF_Collector::bpf_thread(BPF_Collector &bpf_collector) {
    bool                                         stop = false;
    std::vector<struct pollfd>                   pfds;
    std::unordered_map<int, struct ring_buffer*> rbs;

    while (!stop) {
        pfds.clear();
        rbs.clear();

        {
            std::scoped_lock lock(bpf_collector.probes_mtx);

            pfds.push_back({ .fd = bpf_collector.thread_stop_pipe[0], .events = POLLIN });
            pfds.push_back({ .fd = bpf_collector.trace_pipe_fd, .events = POLLIN });
            pfds.push_back({ .fd = bpf_collector.discover.ringbuf_fd, .events = POLLIN });
            rbs[bpf_collector.discover.ringbuf_fd] = bpf_collector.discover.ringbuf;

            for (auto &pair : bpf_collector.probes) {
                BPF_Object_Base *object = pair.second.get();
                pfds.push_back({ .fd = object->ringbuf_fd, .events = POLLIN });
                rbs[object->ringbuf_fd] = object->ringbuf;
            }
        }

        int n_ready;
        while ((n_ready = poll(pfds.data(), pfds.size(), -1)) == EINTR && n_ready == 0);
        if (n_ready < 0) {
            ERR("poll failed with errno {}\n", errno);
        }

        for (auto &pfd : pfds) {
            if (!(pfd.revents & POLLIN)) { continue; }

            if (pfd.fd == bpf_collector.thread_stop_pipe[0]) {
                stop = true;
                break;
            } else if (pfd.fd == bpf_collector.trace_pipe_fd) {
                std::scoped_lock lock(debug_print_mtx);
                int n_read;
                char buff[512];
                while ((n_read = read(pfd.fd, buff, sizeof(buff))) > 0) {
                    write(2, buff, n_read);
                }
            } else {
                ring_buffer__consume(rbs[pfd.fd]);
            }
        }
    }
}

BPF_Collector::~BPF_Collector() {
    write(this->thread_stop_pipe[1], "stop", 4);
    this->thr.join();
}

bool BPF_Collector::init() {
    pipe(this->thread_stop_pipe);

    this->trace_pipe_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_NONBLOCK | O_RDONLY);

    if (!this->discover.open_and_load())                           { return false; }
    if (!this->discover.attach(BPF_Collector::discover_sample_fn)) { return false; }

    if (!this->patcher.open_and_load()) { return false; }
    if (!this->patcher.attach())        { return false; }

    this->thr = std::thread(bpf_thread, std::ref(*this));

    this->initialized = true;

    return true;
}

BPF_Collector &BPF_Collector::get() {
    static BPF_Collector collector;

    if (!collector.initialized) {
        std::scoped_lock lock(collector.init_mtx);

        if (!collector.initialized) {
            if (!collector.init()) {
                ERR("Failed to initialize BPF.\n");
            }
        }
    }

    return collector;
}
