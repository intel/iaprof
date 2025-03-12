#pragma once

#include <bpf/bpf.h>

#include "stores/buffer_profile.h"
#include "collectors/bpf/bpf/main.h"
#include "collectors/eustall/eustall_collector.h"

#define EVENT_LEN 14
#define TIME_LEN 14
#define CPU_LEN 4
#define PID_LEN 8
#define TID_LEN 8

int print_header();
int print_vm_create(struct vm_create_info *info);
int print_vm_bind(struct vm_bind_info *info, uint32_t vm_bind_counter);
int print_vm_unbind(struct vm_unbind_info *info);
int print_execbuf(struct execbuf_info *info);

int print_total_eustall(uint64_t num, unsigned long long time);
int print_eustall(struct eustall_sample *sample, uint64_t gpu_addr,
                  uint64_t offset, uint32_t handle,
                  unsigned long long time);
int print_eustall_churn(struct eustall_sample *sample, uint64_t gpu_addr,
                        uint64_t offset, unsigned long long time);
int print_eustall_drop(struct eustall_sample *sample, uint64_t gpu_addr,
                       unsigned long long time);
int print_eustall_defer(struct eustall_sample *sample, uint64_t gpu_addr,
                        unsigned long long time);
int print_eustall_multichurn(struct eustall_sample *sample, uint64_t gpu_addr,
                             unsigned long long time);
