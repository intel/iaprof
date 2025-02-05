#pragma once

#include <inttypes.h>

struct stack;

int init_syms_cache();
void deinit_syms_cache();
uint64_t store_kstack(const struct stack *stack);
uint64_t store_ustack(int pid, const struct stack *stack);
const char *get_stack_str(uint64_t key);
uint64_t stack_hash(const struct stack stack);
