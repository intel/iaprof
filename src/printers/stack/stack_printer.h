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

#include <inttypes.h>

struct stack;

int init_syms_cache();
void deinit_syms_cache();
const char *store_kstack(const struct stack *stack);
const char *store_ustack(int pid, const struct stack *stack);
const char *get_stack(const struct stack *stack);
