#pragma once

#include <stdio.h>
#include <stdint.h>
#include <linux/types.h>
#include "collectors/bpf_i915/bpf/main.h"

void parse_interval_profile();
void print_stack(uint64_t key, const char *stack_str, const struct stack *stack, int last_index);
void print_interval(uint64_t interval);
