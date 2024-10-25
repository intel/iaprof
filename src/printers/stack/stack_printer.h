#pragma once

#include <inttypes.h>

struct stack;

int init_syms_cache();
void deinit_syms_cache();
char *store_stack(int pid, int tid, struct stack *stack);
char *get_stack(struct stack *stack);
