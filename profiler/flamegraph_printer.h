#pragma once

#include "event_collector.h"

char get_insn_text(struct buffer_profile *gem, uint64_t offset, char **insn_text, size_t *insn_text_len);
void print_kernel_flamegraph(struct buffer_profile *gem, char **insn_text, size_t *insn_text_len);
void print_flamegraph();
