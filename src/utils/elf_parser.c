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

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <libgen.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>

#include <libelf.h>
#include <elfutils/libdw.h>


#include "printers/interval/interval_printer.h"
#include "printers/debug/debug_printer.h"
#include "commands/record.h"
#include "stores/gpu_kernel.h"
#include "utils/utils.h"
#include "utils/hash_table.h"
#include "utils/demangle.h"

typedef char *sym_str_t;
typedef struct {
        char *filename;
        int   linenum;
} Debug_Info;
use_hash_table_e(sym_str_t, Debug_Info, str_equ);

static void extract_elf_shader_binary(uint64_t addr, Elf_Scn *section) {
        Elf64_Shdr *shdr;
        uint64_t    saddr;
        uint64_t    offset;
        Elf_Data   *data;

        shdr   = elf64_getshdr(section);
        saddr  = DRM_CANONICALIZE(shdr->sh_addr);

        if (addr < saddr) {
                WARN("extract_elf_shader_binary addr=0x%lx < saddr=0x%lx\n", addr, saddr);
                return;
        }

        offset = addr - saddr;
        data   = elf_getdata(section, NULL);

        set_kernel_binary(addr & SHADER_ADDRESS_MASK, data->d_buf + offset, data->d_size - offset);
}

/* Adds a symbol to the per-PID symbol table.
   XXX: Check for duplicates and throw a warning */
static void extract_elf_symbol(Elf64_Sym *symbol, Elf *elf, int string_table_index, hash_table(sym_str_t, Debug_Info) debug_info_table)
{
        uint64_t    address, name_id, filename_id;
        char       *name;
        char       *filename;
        int         linenum;
        char       *demangled;
        Debug_Info *info;
        Elf_Scn    *section;

        address   = DRM_CANONICALIZE(symbol->st_value);
        name      = elf_strptr(elf, string_table_index, symbol->st_name);
        demangled = NULL;
        filename  = NULL;
        linenum   = 0;

        if (name == NULL) {
                name = "???";
        } else {
                info = hash_table_get_val(debug_info_table, name);
                if (info != NULL) {
                        filename = info->filename;
                        linenum  = info->linenum;
                }
                demangled = demangle(name);
                if (demangled != NULL) {
                        name = demangled;
                }
        }
        if (filename == NULL) {
                filename = "<unknown>";
        }

        debug_printf("    Symbol 0x%lx:%s @ %s:%d\n", address, name, filename, linenum);

        name_id = print_string(name);
        filename_id = print_string(filename);
        set_kernel_info(address & SHADER_ADDRESS_MASK, symbol->st_size, name_id, filename_id, linenum);

        if (demangled) {
                free(demangled);
        }

        section = elf_getscn(elf, symbol->st_shndx);

        extract_elf_shader_binary(address, section);
}

static void extract_elf_symtab(Elf *elf, Elf_Scn *section, size_t string_table_index, hash_table(sym_str_t, Debug_Info) debug_info_table)
{
        Elf_Data *section_data;
        size_t num_symbols, i;
        Elf64_Sym *symbols;

        section_data = elf_getdata(section, NULL);
        while (section_data != NULL) {
                if (!(section_data->d_type == ELF_T_SYM)) {
                        /* Why would data in a .symtab not be a symbol...? */
                        continue;
                }

                num_symbols = section_data->d_size / sizeof(Elf64_Sym);
                symbols = (Elf64_Sym *)section_data->d_buf;
                for (i = 0; i < num_symbols; i++) {
                        if (ELF64_ST_TYPE(symbols[i].st_info) == STT_FUNC) {
                                /* Add an entry into our internal symbol tables, and record
                                   the name and address */

                                extract_elf_symbol(&(symbols[i]), elf, string_table_index, debug_info_table);
                        }
                }

                /* Go to the next buffer of symbols, if applicable */
                section_data = elf_getdata(section, section_data);
        }
}

static int dwarf_func_cb(Dwarf_Die *diep, void *arg) {
        const char                        *name;
        const char                        *dwarf_filename;
        char                              *filename;
        int                                probably_jit;
        char                              *base;
        Debug_Info                         info;
        hash_table(sym_str_t, Debug_Info)  debug_info_table;
        Debug_Info                        *existing_info;


        name = dwarf_diename(diep);
        if (name == NULL) {
                goto out;
        }

        dwarf_filename = dwarf_decl_file(diep);

        if (dwarf_filename == NULL) {
            filename = strdup("<unknown>");
        } else {
            filename = strdup(dwarf_filename);

            probably_jit = 1;

            for (base = basename(filename); *base; base += 1) {
                if (!isdigit(*base)){
                    probably_jit = 0;
                }
            }

            if (probably_jit) {
                free(filename);
                filename = strdup("JIT");
            }
        }

        info.filename = filename;

        info.linenum = 0;
        dwarf_decl_line(diep, &info.linenum);

        debug_info_table = (hash_table(sym_str_t, Debug_Info))arg;

        if ((existing_info = hash_table_get_val(debug_info_table, (char*)name)) != NULL) {
                if (existing_info->filename != NULL) {
                        free(existing_info->filename);
                }
                existing_info->filename = info.filename;
                existing_info->linenum  = info.linenum;
        } else {
                hash_table_insert(debug_info_table, strdup(name), info);
        }

out:;
        return DWARF_CB_OK;
}

static hash_table(sym_str_t, Debug_Info) build_debug_info_table(Elf *elf)
{
        hash_table(sym_str_t, Debug_Info)  debug_info_table;
        Dwarf                             *dwarf;
        Dwarf_CU                          *cu;
        Dwarf_CU                          *next_cu;
        Dwarf_Half                         version;
        uint8_t                            unit_type;
        int                                retval;
        Dwarf_Die                          cudie;
        Dwarf_Die                          subdie;


        debug_info_table = hash_table_make(sym_str_t, Debug_Info, str_hash);

        dwarf = dwarf_begin_elf(elf, DWARF_C_READ, NULL);

        if (dwarf == NULL) {
/*                 WARN("error opening dwarf from elf: %s\n", dwarf_errmsg(dwarf_errno())); */
                goto out;
        }


        cu      = NULL;
        next_cu = NULL;

        do {
                cu = next_cu;

                version   = 123;
                unit_type = 123;

                retval = dwarf_get_units(dwarf, cu, &next_cu, &version, &unit_type, &cudie, &subdie);

                if (retval != 0) {
                        break;
                }

                dwarf_getfuncs(&cudie, dwarf_func_cb, debug_info_table, 0);

        } while (next_cu != NULL);

        dwarf_end(dwarf);

out:;
        return debug_info_table;
}

static void free_debug_info_table(hash_table(sym_str_t, Debug_Info) debug_info_table) {
        char *key;
        Debug_Info *val;

        hash_table_traverse(debug_info_table, key, val) {
                free(key);
                free(val->filename);
        }

        hash_table_free(debug_info_table);
}

static void extract_elf_progbits(Elf *elf, Elf_Scn *section, Elf64_Shdr *section_header, size_t string_table_index, hash_table(sym_str_t, Debug_Info) debug_info_table) {
        uint64_t    address, filename_id, name_id;
        char       *name;
        int         len;
        char       *seek;
        char       *filename;
        int         linenum;
        char       *demangled;
        Debug_Info *info;

        address = DRM_CANONICALIZE(section_header->sh_addr);

        name      = elf_strptr(elf, string_table_index, section_header->sh_name);
        len       = strlen(name);
        demangled = NULL;

        if (len == 0) { return; }

        /* Chop off *. prefix. */
        for (seek = name + len; seek > name && *(seek - 1) != '.'; seek -= 1);
        name = seek;

        if (*name == 0) { return; }

        filename = NULL;
        linenum  = 0;

        info = hash_table_get_val(debug_info_table, name);
        if (info != NULL) {
                filename = info->filename;
                linenum  = info->linenum;
        }
        demangled = demangle(name);
        if (demangled != NULL) {
                name = demangled;
        }
        if (filename == NULL) {
                filename = "<unknown>";
        }

        name_id = print_string(name);
        filename_id = print_string(filename);
        debug_printf("    Symbol 0x%lx:%s @ %s:%d\n", address, name, filename, linenum);

        set_kernel_info(address & SHADER_ADDRESS_MASK, section_header->sh_size, name_id, filename_id, linenum);

        if (demangled != NULL) {
                free(demangled);
        }

        extract_elf_shader_binary(address, section);
}

void extract_elf_kernel_info(const unsigned char *elf_data, uint64_t elf_data_size)
{
        Elf *elf;
        hash_table(sym_str_t, Debug_Info) debug_info_table;
        Elf64_Ehdr *elf_header;
        int seen_symtab;
        Elf_Scn *section;
        Elf64_Shdr *section_header;
        int retval;
        size_t string_table_index;

        debug_printf("Processing ELF\n");

        /* Initialize the ELF from the buffer */
        elf = elf_memory((char *)elf_data, elf_data_size);
        if (!elf) {
                WARN("Error reading an ELF file.\n");
                return;
        }

        /* Build a debug info table. */
        debug_info_table = build_debug_info_table(elf);

        /* Get the ELF header */
        elf_header = elf64_getehdr(elf);
        if (elf_header == NULL) {
                WARN("Failed to get the ELF header.\n");
                goto cleanup;
        }

        /* Get the index of the string table section. */
        retval = elf_getshdrstrndx(elf, &string_table_index);
        if (retval != 0) {
                WARN("Failed to get the index of the ELF string table.\n");
                goto cleanup;
        }


        /* Iterate over ELF sections to find .symbtab sections */
        seen_symtab = 0;
        section = elf_nextscn(elf, NULL);
        while (section != NULL) {
                /* Get the section header */
                section_header = elf64_getshdr(section);
                if (section_header == NULL) {
                        WARN("There was an error reading the ELF section headers.\n");
                        goto cleanup;
                }

                /* Get the string name */
                debug_printf("Section: %s type: %d\n",
                        elf_strptr(elf, string_table_index,
                                section_header->sh_name),
                                section_header->sh_type);

                /* If this is a .symtab section, it'll be marked as SHT_SYMTAB */
                if (section_header->sh_type == SHT_SYMTAB) {
                        debug_printf("  Symbol table:\n");
                        extract_elf_symtab(elf, section, string_table_index, debug_info_table);
                        seen_symtab = 1;
                }

                /* Next section */
                section = elf_nextscn(elf, section);
        }

        if (!seen_symtab) {
                section = elf_nextscn(elf, NULL);
                while (section != NULL) {
                        /* Get the section header */
                        section_header = elf64_getshdr(section);
                        if (section_header == NULL) {
                                WARN("There was an error reading the ELF section headers.\n");
                                goto cleanup;
                        }

                        if (section_header->sh_type == SHT_PROGBITS) {
                                /* Get the string name */
                                debug_printf("Progbits: %s\n", elf_strptr(elf, string_table_index, section_header->sh_name));
                                extract_elf_progbits(elf, section, section_header, string_table_index, debug_info_table);
                        }

                        /* Next section */
                        section = elf_nextscn(elf, section);
                }

        }

cleanup:
        free_debug_info_table(debug_info_table);

        retval = elf_end(elf);
        if (retval != 0) {
                WARN("Failed to cleanup ELF object.\n");
        }
}
