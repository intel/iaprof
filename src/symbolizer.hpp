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

#include "blazesym.h"

struct Elf_Symbol {
    u64               addr;
    std::string       symbol;
    int               line = 0;
    std::string       filename;
    std::vector<char> binary;
};

struct Elf;

class Symbolizer {
    blaze_symbolizer *bsym =  nullptr;

    std::unordered_set<u32> vma_cached_pids;

    bool cache_process_vmas(u32 pid);

    std::vector<Elf_Symbol> parse_elf(Elf *elf);
    std::vector<Elf_Symbol> parse_elf(const char *path);
    std::vector<Elf_Symbol> parse_elf(char *image, size_t size);

public:
    Symbolizer();

    std::vector<std::optional<std::string>> get_syms(u32 pid, const u64 *addrs, size_t n);
    std::vector<Elf_Symbol>                 get_elf_symbols(const char *path);
    std::vector<Elf_Symbol>                 get_elf_symbols(char *elf_data, size_t elf_size);
};
