// Copyright 2026 Intel Corporation
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "common.bpf.h"
#include "discover_types.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} discovered SEC(".maps");

SEC("fentry/xe_vm_bind_ioctl")
int BPF_PROG(xe_vm_bind_ioctl, struct drm_device *dev, void *data, struct drm_file *file) {
    __u32                            pid;
    __u32                           *lookup;
    struct discover_libze_intel_gpu *discover_info;
    long                             err;
    __u32                            one = 1;

    pid = bpf_get_current_pid_tgid() >> 32;

    lookup = bpf_map_lookup_elem(&discovered, &pid);

    if (lookup == NULL) {
        bpf_map_update_elem(&discovered, &pid, &one, 0);

        discover_info = bpf_ringbuf_reserve(&rb, sizeof(*discover_info), 0);
        if (!discover_info) {
            ERR_PRINTK("xe_vm_bind_ioctl failed to reserve in the ringbuffer.");
            err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
            DEBUG_PRINTK("Unconsumed data: %lu", err);
            return 0;
        }
        discover_info->type = DISCOVER_LIBZE_INTEL_GPU;
        discover_info->pid  = pid;
        bpf_ringbuf_submit(discover_info, BPF_RB_FORCE_WAKEUP);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
