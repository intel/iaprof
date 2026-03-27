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

#pragma once

#include "common.hpp"
#include "eustall.hpp"
#include "probes_types.h"

struct kv_t;

struct GPU_Kernel {
    static constexpr u64 ADDRESS_MASK = 0xFFFFFFFFFF00;

    enum class Type {
        Unknown,
        Kernel,
        System_Routine,
        Debug_Area,
    };

    std::mutex mtx;

    u64 gpu_addr;
    u64 size;

    Type type;

    u32 pid;

    std::reference_wrapper<const std::string> command_name;
    u64                                       command_name_id;

    std::reference_wrapper<const std::string> cpu_stack;
    u64                                       cpu_stack_id;

    std::reference_wrapper<const std::string> symbol;
    u64                                       symbol_id;

    std::reference_wrapper<const std::string> filename;
    u64                                       filename_id;

    int linenum;

    std::vector<char> binary;

    std::unordered_map<u64, EU_Stall_Profile> offset_profile;

    struct kv_t *kv = nullptr;

    GPU_Kernel();
    ~GPU_Kernel();
};

struct Locked_GPU_Kernel {
    std::unique_lock<std::mutex>  lock;
    GPU_Kernel                   &kernel;

    Locked_GPU_Kernel(GPU_Kernel &kernel);

    Locked_GPU_Kernel()                                   = delete;
    Locked_GPU_Kernel(const Locked_GPU_Kernel&)           = delete;
    Locked_GPU_Kernel operator=(const Locked_GPU_Kernel&) = delete;
    Locked_GPU_Kernel(Locked_GPU_Kernel&&)                = default;

    GPU_Kernel *operator->();
};

struct Stack_Hash {
    size_t operator()(const stack &stack) const;
};

struct Stack_Equal {
    bool operator()(const stack &l, const stack &r) const;
};

class Profile {
    u64                                                                interval = 0;
    u64                                                                string_id = 1;
    std::unordered_map<std::string, u64>                               string_ids;
    std::unordered_map<u64, std::reference_wrapper<const std::string>> ids_to_string;
    std::unordered_map<stack, u64, Stack_Hash, Stack_Equal>            cpu_stack_string_ids;
    std::map<u64, std::unique_ptr<GPU_Kernel>>                         kernels;
    std::shared_mutex                                                  kernels_mtx;
    std::mutex                                                         output_mtx;

    template <typename... Args>
    auto output(std::format_string<Args...> fmt, Args&&... args) {
        std::scoped_lock lock(this->output_mtx);
        std::print(fmt, args...);
    }


    void output_string_id(u64 id, const std::string &string);

    std::pair<u64, std::reference_wrapper<const std::string>> get_string_id(const std::string &string);
    std::pair<u64, std::reference_wrapper<const std::string>> get_string_id(const char *cstring);
    std::pair<u64, std::reference_wrapper<const std::string>> get_string_id(const struct stack &cpu_stack);

    GPU_Kernel *get_or_create_kernel(u64 addr);

public:

    Locked_GPU_Kernel set_kernel_launch_info(u64 addr, u64 size, char command_name[TASK_COMM_LEN], u32 pid, struct stack &cpu_stack);
    Locked_GPU_Kernel set_kernel_debug_info(u64 addr, std::string symbol, std::string filename, int line, std::vector<char> binary);
    std::optional<Locked_GPU_Kernel> find_kernel_at(u64 addr);
    void output_interval();
};
