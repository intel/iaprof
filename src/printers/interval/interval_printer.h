#pragma once

#include <stdio.h>
#include <stdint.h>
#include <linux/types.h>
#include "collectors/bpf_i915/bpf/main.h"

void parse_interval_profile();
void print_string(const char *str);
void print_interval(uint64_t interval);
void (*get_profile_line_func(char *str, size_t *size)) (char *str);
