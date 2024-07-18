#pragma once

#include <assert.h>
#include <iga/iga.h>
#include <iga/kv.h>
#include "utils/hash_table.h"

use_hash_table(uint64_t, uint64_t);
struct shader_profile {
	/* The EU stalls. Key is the offset into the binary,
     value is a pointer to the struct of EU stall counts */
	hash_table(uint64_t, uint64_t) counts;
};

struct kv_t *iga_init(unsigned char *buff, size_t buff_len);
char iga_disassemble_insn(struct kv_t *kv, uint64_t offset, char **insn_text, size_t *insn_text_len);
