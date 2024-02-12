#pragma once

#include <inttypes.h>
#include "trace_helpers.h"
#include "bpf/gem_collector.h"

int init_syms_cache();
void store_stack(uint32_t pid, int stackid, char **stack_str);
