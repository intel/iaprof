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

#include "symbolizer.hpp"
#include "globals.hpp"
#include "libelf.h"
#include <elfutils/libdw.h>
#include <llvm/Demangle/Demangle.h>

Symbolizer::Symbolizer() {
    this->bsym = blaze_symbolizer_new();
}

std::optional<std::string> Symbolizer::get_sym(u32 pid, u64 addr) {
    blaze_symbolize_src_process src = {
        .type_size = sizeof(src),
        .pid       = pid,
    };

    const blaze_syms *syms = blaze_symbolize_process_abs_addrs(this->bsym, &src, &addr, 1);
    if (syms == nullptr || syms->cnt < 1 || syms->syms[0].name == nullptr) { return {}; }

    std::string ret = syms->syms[0].name;

    blaze_syms_free(syms);

    return ret;
}

static void extract_elf_symbol_binary(Elf_Symbol &sym, Elf_Scn *section) {
    Elf64_Shdr *shdr   = elf64_getshdr(section);
    u64         saddr  = shdr->sh_addr;
    u64         offset = sym.addr - saddr;
    Elf_Data   *data   = elf_getdata(section, NULL);

    sym.binary.resize(data->d_size - offset);
    memcpy(sym.binary.data(), ((char*)data->d_buf) + offset, data->d_size - offset);
}

static void extract_elf_symbol(Elf *elf, Elf64_Sym *symbol, size_t string_table_index, std::vector<Elf_Symbol> &results) {
    Elf_Symbol sym;

    sym.addr = symbol->st_value;

    const char *name = elf_strptr(elf, string_table_index, symbol->st_name);
    sym.symbol = llvm::demangle(name);

    Elf_Scn *section = elf_getscn(elf, symbol->st_shndx);
    extract_elf_symbol_binary(sym, section);

    results.emplace_back(std::move(sym));
}

static void extract_elf_symtab(Elf *elf, Elf_Scn *section, size_t string_table_index, std::vector<Elf_Symbol> &results) {
    Elf_Data *section_data = elf_getdata(section, NULL);
    while (section_data != NULL) {
        if (!(section_data->d_type == ELF_T_SYM)) { continue; }

        size_t     num_symbols = section_data->d_size / sizeof(Elf64_Sym);
        Elf64_Sym *symbols     = (Elf64_Sym *)section_data->d_buf;
        for (size_t i = 0; i < num_symbols; i++) {
            if (ELF64_ST_TYPE(symbols[i].st_info) == STT_FUNC) {
                extract_elf_symbol(elf, &(symbols[i]), string_table_index, results);
            }
        }

        section_data = elf_getdata(section, section_data);
    }
}

static void extract_elf_progbits(Elf *elf, Elf_Scn *section, Elf64_Shdr *section_header, size_t string_table_index, std::vector<Elf_Symbol> &results) {
    Elf_Symbol sym;

    sym.addr = section_header->sh_addr;

    extract_elf_symbol_binary(sym, section);

    results.emplace_back(std::move(sym));
}

static int dwarf_func_cb(Dwarf_Die *diep, void *arg) {
    std::unordered_map<u64, std::reference_wrapper<Elf_Symbol>> &sym_map
        = *(std::remove_reference<decltype(sym_map)>::type *)arg;

    u64 addr = 0;
    dwarf_lowpc(diep, &addr);

    auto lookup = sym_map.find(addr);
    if (lookup == sym_map.end()) { return DWARF_CB_OK; }

    Elf_Symbol &sym = lookup->second;

    const char *dwarf_filename = dwarf_decl_file(diep);
    sym.filename = dwarf_filename == NULL ? "<unknown>" : dwarf_filename;

    dwarf_decl_line(diep, &sym.line);

    return DWARF_CB_OK;
}

static void extract_dwarf_debug_info(Elf *elf, std::vector<Elf_Symbol> &syms) {
    std::unordered_map<u64, std::reference_wrapper<Elf_Symbol>> sym_map;

    for (auto &sym : syms) {
        sym_map.insert_or_assign(sym.addr, std::ref(sym));
    }

    Dwarf *dwarf = dwarf_begin_elf(elf, DWARF_C_READ, NULL);

    if (dwarf == NULL) { return; }

    Dwarf_CU *cu      = NULL;
    Dwarf_CU *next_cu = NULL;

    do {
        cu = next_cu;

        Dwarf_Half version   = 123;
        u8         unit_type = 123;
        Dwarf_Die  cudie;
        Dwarf_Die  subdie;

        int retval = dwarf_get_units(dwarf, cu, &next_cu, &version, &unit_type, &cudie, &subdie);

        if (retval != 0) {
            break;
        }

        dwarf_getfuncs(&cudie, dwarf_func_cb, &sym_map, 0);

    } while (next_cu != NULL);

    dwarf_end(dwarf);
}

std::vector<Elf_Symbol> Symbolizer::parse_elf(const char *path) {
    std::vector<Elf_Symbol> results;

    int fd = open(path, O_RDONLY);

    if (fd < 0) {
        WARN("failed to open ELF file {}\n", path);
        return {};
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL) {
        WARN("{} is not a valid ELF file\n", path);
        return {};
    }

    Elf64_Ehdr *elf_header = elf64_getehdr(elf);
    if (elf_header == NULL) {
        WARN("Failed to get the ELF header for {}.\n", path);
        goto cleanup;
    }

    size_t string_table_index;
    if (elf_getshdrstrndx(elf, &string_table_index) != 0) {
        WARN("Failed to get the index of the ELF string table for {}.\n", path);
        goto cleanup;
    }

    {
        bool     seen_symtab = false;
        Elf_Scn *section     = elf_nextscn(elf, NULL);
        while (section != NULL) {
            Elf64_Shdr *section_header = elf64_getshdr(section);
            if (section_header == NULL) {
                WARN("There was an error reading the ELF section headers for {}.\n", path);
                results.clear();
                goto cleanup;
            }

            if (section_header->sh_type == SHT_SYMTAB) {
                extract_elf_symtab(elf, section, string_table_index, results);
                seen_symtab = true;
            }

            section = elf_nextscn(elf, section);
        }

        if (!seen_symtab) {
            section = elf_nextscn(elf, NULL);
            while (section != NULL) {
                Elf64_Shdr *section_header = elf64_getshdr(section);

                if (section_header->sh_type == SHT_PROGBITS) {
                    extract_elf_progbits(elf, section, section_header, string_table_index, results);
                }

                section = elf_nextscn(elf, section);
            }
        }
    }

    extract_dwarf_debug_info(elf, results);

cleanup:
    elf_end(elf);

    return results;
}

std::vector<Elf_Symbol> Symbolizer::get_elf_symbols(const char *path) {
    return this->parse_elf(path);
}
