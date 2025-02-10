#pragma once

#include <inttypes.h>

struct stack;

int init_syms_cache();
void deinit_syms_cache();
const char *store_kstack(const struct stack *stack);
const char *store_ustack(int pid, const struct stack *stack);
const char *get_stack(const struct stack *stack);
