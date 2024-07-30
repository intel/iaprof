#pragma once

#include <assert.h>
#include <iga/iga.h>
#include <iga/kv.h>

struct kv_t *iga_init(unsigned char *buff, size_t buff_len);
char iga_disassemble_insn(struct kv_t *kv, uint64_t offset, char **insn_text,
                          size_t *insn_text_len);
