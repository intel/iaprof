#pragma once

#include <inttypes.h>

struct stack;

int init_syms_cache();
void deinit_syms_cache();
char *store_kstack(struct stack *stack);
char *store_ustack(int pid, struct stack *stack);
char *get_stack(struct stack *stack);
