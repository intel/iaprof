#pragma once

#include <sys/types.h>
#include <inttypes.h>

void dump_buffer(unsigned char *kernel, uint64_t size, uint32_t id);
void print_map(pid_t pid);
unsigned char *copy_buffer(uint32_t pid, uint64_t ptr, uint64_t size);
