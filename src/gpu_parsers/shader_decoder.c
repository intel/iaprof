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

#include "printers/debug/debug_printer.h"
#include "shader_decoder.h"

#if GPU_PLATFORM == GPU_PLATFORM_xe2
#define IGA_PLAT IGA_XE2
#elif GPU_PLATFORM == GPU_PLATFORM_pvc
#define IGA_PLAT IGA_XE_HPC
#endif

struct kv_t *iga_init(unsigned char *buff, size_t buff_len)
{
        iga_status_t status;
        struct kv_t *kv;

        kv = kv_create(IGA_PLAT, (void *)buff, buff_len, &status, NULL, 0, 0);
        if (status != IGA_SUCCESS) {
                debug_printf("IGA decoding error: '%s'.\n",
                             iga_status_to_string(status));
                /* We're going to return kv anyway, since it could still disassemble
                   some insns successfully (and usually does!). */
        }
        return kv;
}

void iga_fini(struct kv_t *kv) {
    kv_delete(kv);
}

/* Returns 0 for success (and insn_text set appropriately), -1 for failure (insn_text unchanged) */
char iga_disassemble_insn(struct kv_t *kv, uint64_t offset, char **insn_text,
                          size_t *insn_text_len)
{
        uint32_t opcode;
        iga_status_t status;
        iga_opspec_t op;
        size_t new_insn_text_len;

        opcode = kv_get_opcode(kv, offset);
        status = iga_opspec_from_op(IGA_PLAT, opcode, &op);
        if (status != IGA_SUCCESS) {
                debug_printf("Failed to disassemble insn. Error was: '%s'\n",
                             iga_status_to_string(status));
                return -1;
        }

        /* Get the length that insn_text needs to be. */
        status = iga_opspec_mnemonic(op, NULL, &new_insn_text_len);
        if (status != IGA_SUCCESS) {
                debug_printf("Failed to disassemble insn. Error was: '%s'\n",
                             iga_status_to_string(status));
                return -1;
        }
        if (new_insn_text_len > *insn_text_len) {
                *insn_text =
                        realloc(*insn_text, sizeof(char) * new_insn_text_len);
                *insn_text_len = new_insn_text_len;
        }

        /* Set *insn_text to the mnemonic */
        status = iga_opspec_mnemonic(op, *insn_text, &new_insn_text_len);
        if (status != IGA_SUCCESS) {
                debug_printf("Failed to disassemble insn. Error was: '%s'\n",
                             iga_status_to_string(status));
                return -1;
        }

        return 0;
}
