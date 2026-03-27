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

#include "profile.hpp"
#include "globals.hpp"
#include "oa.hpp"

#include <iga/kv.h>

const static std::string empty_string;

GPU_Kernel::GPU_Kernel()
    : gpu_addr(0),
      size(0),
      type(Type::Unknown),
      pid(0),
      command_name(empty_string), command_name_id(0),
      cpu_stack(empty_string),    cpu_stack_id(0),
      symbol(empty_string),       symbol_id(0),
      filename(empty_string),     filename_id(0),
      linenum(0)
      {}

GPU_Kernel::~GPU_Kernel() {
    if (this->kv != nullptr) {
        kv_delete(this->kv);
    }
}

Locked_GPU_Kernel::Locked_GPU_Kernel(GPU_Kernel &kernel)
    : lock(kernel.mtx), kernel(kernel) {}

GPU_Kernel *Locked_GPU_Kernel::operator->() { return &this->kernel; }


constexpr u64 FNV_OFFSET_BASIS = 0xcbf29ce484222325ULL;
constexpr u64 FNV_PRIME        = 0x100000001b3ULL;

size_t Stack_Hash::operator()(const stack &stack) const {
    size_t hash = FNV_OFFSET_BASIS;

    hash ^= stack.pid;
    hash *= FNV_PRIME;

    for (int i = 0; i < stack.len; i++) {
        hash ^= stack.addrs[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

bool Stack_Equal::operator()(const stack &l, const stack &r) const {
    if (l.len != r.len) { return false; }
    if (l.pid != r.pid) { return false; }

    for (int i = 0; i < l.len; i++) {
        if (l.addrs[i] != r.addrs[i]) { return false; }
    }

    return true;
}

void Profile::output_string_id(u64 id, const std::string &string) {
    this->output("string\t{}\t{}\n", id, string);
}


std::pair<u64, std::reference_wrapper<const std::string>> Profile::get_string_id(const std::string &string) {
    auto it = this->string_ids.find(string);
    if (it != this->string_ids.end()) {
        return std::pair{ it->second, std::ref(it->first) };
    }

    u64 id = this->string_id;

    const auto [inserted, _] = this->string_ids.try_emplace(string, id);
    this->ids_to_string.try_emplace(id, std::ref(inserted->first));

    this->string_id += 1;

    this->output_string_id(id, inserted->first);

    return std::pair{ id, std::ref(inserted->first) };
}

std::pair<u64, std::reference_wrapper<const std::string>> Profile::get_string_id(const char *cstring) {
    std::string string = cstring;
    return this->get_string_id(string);
}

std::pair<u64, std::reference_wrapper<const std::string>> Profile::get_string_id(const stack &cpu_stack) {
    auto it = this->cpu_stack_string_ids.find(cpu_stack);
    if (it != this->cpu_stack_string_ids.end()) {
        return std::pair{ it->second, this->ids_to_string.at(it->second) };
    }

    std::string stack_str = "";
    std::string lazy_semicolon = "";
    for (int i = cpu_stack.len; i > 0; i -= 1) {
        stack_str += lazy_semicolon;
        if (auto sym = symbolizer.get_sym(cpu_stack.pid, cpu_stack.addrs[i - 1])) {
            stack_str += *sym;
        } else {
            stack_str += std::format("{:#x}", cpu_stack.addrs[i - 1]);
        }
        lazy_semicolon = ";";
    }

    auto pair = this->get_string_id(stack_str);

    this->cpu_stack_string_ids[cpu_stack] = pair.first;

    return pair;
}

GPU_Kernel *Profile::get_or_create_kernel(u64 addr) {
    std::unique_lock lock(this->kernels_mtx);

    auto it = this->kernels.find(addr);

    if (it != this->kernels.end()) {
        return it->second.get();
    }

    const auto [inserted, _] = this->kernels.try_emplace(addr, std::make_unique<GPU_Kernel>());
    inserted->second->gpu_addr = addr;
    return inserted->second.get();
}

Locked_GPU_Kernel Profile::set_kernel_launch_info(u64 addr, u64 size, char command_name[TASK_COMM_LEN], u32 pid, struct stack &cpu_stack) {
    GPU_Kernel *kernel = this->get_or_create_kernel(addr);

    if (size != 0 && size != kernel->binary.size()) {
        WARN("reported kernel size at launch differs from provided binary size ({} vs {})\n", size, kernel->binary.size());
    }

    kernel->size = size;
    kernel->type = GPU_Kernel::Type::Kernel;
    kernel->pid  = pid;

    {
        auto [id, str_ref]      = this->get_string_id(command_name);
        kernel->command_name_id = id;
        kernel->command_name    = str_ref;
    }

    {
        auto [id, str_ref]   = this->get_string_id(cpu_stack);
        kernel->cpu_stack_id = id;
        kernel->cpu_stack    = str_ref;
    }

    return Locked_GPU_Kernel(*kernel);
}

Locked_GPU_Kernel Profile::set_kernel_debug_info(u64 addr, std::string symbol, std::string filename, int line, std::vector<char> binary) {
    GPU_Kernel *kernel = this->get_or_create_kernel(addr);

    {
        auto [id, str_ref] = this->get_string_id(symbol);
        kernel->symbol_id  = id;
        kernel->symbol     = str_ref;
    }
    {
        auto [id, str_ref]   = this->get_string_id(filename);
        kernel->filename_id  = id;
        kernel->filename     = str_ref;
    }

    kernel->linenum = line;

    if (kernel->size == 0) {
        kernel->size = binary.size();
    } else if (binary.size() != kernel->size) {
        WARN("kernel binary size different from reported kernel size from launch info ({} vs {})\n", binary.size(), kernel->size);
    }

    kernel->binary = std::move(binary);

    return Locked_GPU_Kernel(*kernel);
}

std::optional<Locked_GPU_Kernel> Profile::find_kernel_at(u64 addr) {
    std::shared_lock lock(this->kernels_mtx);

    auto it = this->kernels.upper_bound(addr);
    if (it == this->kernels.begin()) {
        return {};
    }

    --it;
    GPU_Kernel *kernel = it->second.get();

    if (addr >= kernel->gpu_addr + kernel->size) {
        return {};
    }

    return Locked_GPU_Kernel(*kernel);
}

static std::string iga_disassemble(GPU_Kernel &kernel, u64 offset) {
    if (kernel.binary.empty() || offset >= kernel.binary.size()) {
        return "[failed decode]";
    }

    if (!kernel.kv) {
        iga_status_t status;
        kernel.kv = kv_create(IGA_XE2, kernel.binary.data(), kernel.binary.size(), &status, NULL, 0, 0);
        if (!kernel.kv) {
            WARN("Failed to initialize IGA: {}\n", iga_status_to_string(status));
            return "[failed decode]";
        }
    }

    u32 opcode = kv_get_opcode(kernel.kv, offset);

    iga_opspec_t op;
    iga_status_t status = iga_opspec_from_op(IGA_XE2, opcode, &op);
    if (status != IGA_SUCCESS) {
        WARN("Failed to get opspec: {}\n", iga_status_to_string(status));
        return "[failed decode]";
    }

    size_t len = 0;
    iga_opspec_mnemonic(op, NULL, &len);

    char *mnemonic = (char*)alloca(len);
    memset(mnemonic, 0, len);

    status = iga_opspec_mnemonic(op, mnemonic, &len);
    if (status != IGA_SUCCESS) {
        WARN("Failed to get mnemonic: {}\n", iga_status_to_string(status));
        return "[failed decode]";
    }

    return std::string(mnemonic);
}

void Profile::output_interval() {
    struct timespec tspec;

    clock_gettime(CLOCK_MONOTONIC, &tspec);
    double time = ((double)tspec.tv_sec) + ((double)tspec.tv_nsec / 1000000000);

    this->output("interval\t{}\t{:.6f}\n", this->interval, time);

    {
        std::shared_lock map_lock(this->kernels_mtx);

        for (auto &[addr, kernel_ptr] : this->kernels) {
            std::scoped_lock kernel_lock(kernel_ptr->mtx);

            if (kernel_ptr->offset_profile.empty()) { continue; }

            GPU_Kernel &kernel = *kernel_ptr;

            this->output("kernel\t{:#x}\t{}\t{}\t{}\t{}\t{}\n",
                kernel.gpu_addr,
                kernel.command_name_id,
                kernel.pid,
                kernel.cpu_stack_id,
                kernel.filename_id,
                kernel.symbol_id);

            for (auto &[offset, prof] : kernel.offset_profile) {
                auto [insn_text_id, _] = this->get_string_id(iga_disassemble(kernel, offset));

                this->output("eustall\t{:#x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                    offset,
                    insn_text_id,
                    prof.active,
                    prof.control,
                    prof.pipestall,
                    prof.send,
                    prof.dist_acc,
                    prof.sbid,
                    prof.sync,
                    prof.inst_fetch,
                    prof.other,
                    prof.tdr);
            }

            kernel_ptr->offset_profile.clear();
        }

        OA_Metrics metrics = OA_Collector::get().get_metrics();
        this->output("metric\tfrequency-MHz\t{}\n",   metrics.avg_mhz);
        this->output("metric\tbusy-percent\t{}\n", metrics.busy_perc);
    }

    this->interval += 1;
}
