// Copyright 2026 Intel Corporation
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "common.bpf.h"

__u32 prog_count;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, char*);
} prog_sec_names SEC(".maps");

SEC("uprobe//proc/self/exe:find_sec_def")
int BPF_UPROBE(probe_attach_usdt, const void *ret) {
    char *sec_name_ptr = (void*)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&prog_sec_names, &prog_count, &sec_name_ptr, 0);
    prog_count += 1;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
