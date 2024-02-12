#pragma once

#include <assert.h>
#include <iga/iga.h>
#include "utils/hash_table.h"

use_hash_table(uint64_t, uint64_t);
struct shader_profile {
  /* The EU stalls. Key is the offset into the binary,
     value is a pointer to the struct of EU stall counts */
  hash_table(uint64_t, uint64_t) counts;
};

char *iga_status_to_str(iga_status_t status);
iga_context_t *iga_init();
char *iga_disassemble_single(iga_context_t *ctx, unsigned char *data);
void iga_disassemble_shader(iga_context_t *ctx, unsigned char *data, size_t data_sz);
