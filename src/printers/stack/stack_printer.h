#pragma once

#include <inttypes.h>

int init_syms_cache();
void store_stack(uint32_t pid, int stackid, char **stack_str);
