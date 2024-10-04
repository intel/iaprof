#pragma once

#include <inttypes.h>

int init_syms_cache();
void deinit_syms_cache();
void store_stack(int pid, int tid, int stackid);
char *get_stack(int stackid);
