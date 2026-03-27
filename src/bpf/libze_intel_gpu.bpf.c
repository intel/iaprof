// Copyright 2026 Intel Corporation
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "common.bpf.h"
#include "probes_types.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, (16 * 1024 * 1024));
} rb SEC(".maps");

USDT_SEC_PLACEHOLDER("level_zero:launch_kernel")
int BPF_USDT(launch_kernel, __u64 iba, __u64 gpu_addr, __u64 size, char *kernel_name) {
    struct probe_event_iba *iba_event;
    long                    err;
    struct probe_event_kernel_launch *kernel_launch_event;

    iba_event = bpf_ringbuf_reserve(&rb, sizeof(*iba_event), 0);
    if (!iba_event) {
        ERR_PRINTK("launch_kernel failed to reserve in the ringbuffer.");
        err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
        DEBUG_PRINTK("Unconsumed data: %lu", err);
        return 0;
    }
    iba_event->type = PROBE_EVENT_IBA;
    iba_event->addr = iba;
    iba_event->pid  = bpf_get_current_pid_tgid() >> 32;
    iba_event->tid  = bpf_get_current_pid_tgid();
    bpf_ringbuf_submit(iba_event, BPF_RB_FORCE_WAKEUP);

    kernel_launch_event = bpf_ringbuf_reserve(&rb, sizeof(*kernel_launch_event), 0);
    if (!kernel_launch_event) {
        ERR_PRINTK("launch_kernel failed to reserve in the ringbuffer.");
        err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
        DEBUG_PRINTK("Unconsumed data: %lu", err);
        return 0;
    }
    err = bpf_get_stack(ctx, &(kernel_launch_event->stack.addrs), sizeof(kernel_launch_event->stack.addrs), BPF_F_USER_STACK);
    if (err < 0) {
        WARN_PRINTK("launch_kernel failed to get a user stack: %ld", err);
    } else {
        kernel_launch_event->stack.len = err / sizeof(kernel_launch_event->stack.addrs[0]);
        kernel_launch_event->stack.pid = bpf_get_current_pid_tgid() >> 32;
    }
    kernel_launch_event->type = PROBE_EVENT_KERNEL_LAUNCH;
    kernel_launch_event->addr = gpu_addr;
    kernel_launch_event->pid  = bpf_get_current_pid_tgid() >> 32;
    kernel_launch_event->tid  = bpf_get_current_pid_tgid();
    kernel_launch_event->cpu  = bpf_get_smp_processor_id();
    kernel_launch_event->time = bpf_ktime_get_ns();
    kernel_launch_event->size = size;
    bpf_get_current_comm(kernel_launch_event->name, sizeof(kernel_launch_event->name));
    bpf_ringbuf_submit(kernel_launch_event, BPF_RB_FORCE_WAKEUP);

    return 0;
}

USDT_SEC_PLACEHOLDER("level_zero:compile_kernel")
int BPF_USDT(compile_kernel, char *file_name) {
    struct probe_event_kernel_path *kernel_path_event;
    long                            err;

    kernel_path_event = bpf_ringbuf_reserve(&rb, sizeof(*kernel_path_event), 0);
    if (!kernel_path_event) {
        ERR_PRINTK("compile_kernel failed to reserve in the ringbuffer.");
        err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
        DEBUG_PRINTK("Unconsumed data: %lu", err);
        return 0;
    }
    kernel_path_event->type = PROBE_EVENT_KERNEL_PATH;
    kernel_path_event->pid  = bpf_get_current_pid_tgid() >> 32;
    kernel_path_event->tid  = bpf_get_current_pid_tgid();
    bpf_probe_read_user_str(kernel_path_event->filename, sizeof(kernel_path_event->filename), file_name);

    bpf_ringbuf_submit(kernel_path_event, BPF_RB_FORCE_WAKEUP);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
