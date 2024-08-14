#pragma once

#include <bpf/bpf.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "collectors/eustall/eustall_collector.h"

#define EVENT_LEN 14
#define TIME_LEN 14
#define CPU_LEN 4
#define PID_LEN 8
#define TID_LEN 8

int print_header();
int print_mapping(struct mapping_info *info);
int print_unmap(struct unmap_info *info);
int print_userptr(struct userptr_info *info);
int print_vm_create(struct vm_create_info *info);
int print_vm_bind(struct vm_bind_info *info);
int print_vm_unbind(struct vm_unbind_info *info);
int print_batchbuffer(struct batchbuffer_info *info);
int print_execbuf_start(struct execbuf_start_info *info);
int print_execbuf_gem(struct buffer_profile *gem);
int print_execbuf_end(struct execbuf_end_info *einfo);
int print_request(struct request_info *rinfo);

int print_total_eustall(uint64_t num, unsigned long long time);
int print_eustall_reason(struct eustall_sample *sample);
int print_eustall(struct eustall_sample *sample, uint64_t gpu_addr,
                  uint64_t offset, uint32_t handle, uint16_t subslice,
                  unsigned long long time);
int print_eustall_churn(struct eustall_sample *sample, uint64_t gpu_addr,
                        uint64_t offset, uint16_t subslice,
                        unsigned long long time);
int print_eustall_drop(struct eustall_sample *sample, uint64_t gpu_addr,
                       uint16_t subslice, unsigned long long time);
int print_eustall_multichurn(struct eustall_sample *sample, uint64_t gpu_addr,
                             uint16_t subslice, unsigned long long time);
