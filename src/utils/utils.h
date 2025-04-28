/*
Copyright 2025 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
uint64_t noop_hash(uint64_t s);
int str_equ(char *a, char *b);
