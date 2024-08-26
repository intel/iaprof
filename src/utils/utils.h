#pragma once

#include <sys/types.h>
#include <inttypes.h>

uint64_t next_power_of_2(uint64_t x);
void find_elf_magic_bytes(pid_t pid, char debug);
void dump_buffer(unsigned char *kernel, uint64_t size, uint64_t id);
void print_map(pid_t pid);
unsigned char *copy_buffer(uint32_t pid, uint64_t ptr, uint64_t size,
                           char debug);
int handle_binary(unsigned char **dst, unsigned char *src, uint64_t *dst_sz,
                  uint64_t src_sz);
int handle_binary_from_fd(int fd, unsigned char **buf, size_t size, uint64_t gpu_addr);
uint64_t str_hash(char *s);
int str_equ(char *a, char *b);
