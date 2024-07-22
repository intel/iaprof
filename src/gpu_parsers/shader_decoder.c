#include <stdio.h>
#include <stdlib.h>

#include "iaprof.h"
#include "shader_decoder.h"

struct kv_t *iga_init(unsigned char *buff, size_t buff_len)
{
        iga_status_t status;
        struct kv_t *kv;
        
        kv = kv_create(IGA_XE_HPC, (void *) buff, buff_len, 
                       &status, NULL, 0, 0);
        if (status != IGA_SUCCESS) {
                if (debug) {
                        fprintf(stderr, "WARNING: IGA decoding error: '%s'.\n", iga_status_to_string(status));
                }
                /* We're going to return kv anyway, since it could still disassemble
                   some insns successfully (and usually does!). */
        }
        return kv;
}

/* Returns 0 for success (and insn_text set appropriately), -1 for failure (insn_text unchanged) */
char iga_disassemble_insn(struct kv_t *kv, uint64_t offset, char **insn_text, size_t *insn_text_len)
{
        uint32_t opcode;
        iga_status_t status;
        iga_opspec_t op;
        size_t new_insn_text_len;
        
        opcode = kv_get_opcode(kv, offset);
        status = iga_opspec_from_op(IGA_XE_HPC, opcode, &op);
        if (status != IGA_SUCCESS) {
                if (debug) {
                        fprintf(stderr, "WARNING: Failed to disassemble insn.\n");
                        fprintf(stderr, "Error was: '%s'\n", iga_status_to_string(status));
                }
                return -1;
        }
        
        /* Get the length that insn_text needs to be. */
        status = iga_opspec_mnemonic(op, NULL, &new_insn_text_len);
        if (status != IGA_SUCCESS) {
                if (debug) {
                        fprintf(stderr, "WARNING: Failed to disassemble insn.\n");
                        fprintf(stderr, "Error was: '%s'\n", iga_status_to_string(status));
                }
                return -1;
        }
        if(new_insn_text_len > *insn_text_len) {
                *insn_text = realloc(*insn_text, sizeof(char) * new_insn_text_len);
                *insn_text_len = new_insn_text_len;
        }
        
        /* Set *insn_text to the mnemonic */
        status = iga_opspec_mnemonic(op, *insn_text, &new_insn_text_len);
        if (status != IGA_SUCCESS) {
                if (debug) {
                        fprintf(stderr, "WARNING: Failed to disassemble insn.\n");
                        fprintf(stderr, "Error was: '%s'\n", iga_status_to_string(status));
                }
                return -1;
        }
        
        return 0;
}
