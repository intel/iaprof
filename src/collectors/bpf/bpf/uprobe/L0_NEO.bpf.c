// Copyright 2025 Intel Corporation
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <stdbool.h>
#include <bpf/usdt.bpf.h>

char null_symbol[MAX_SYMBOL_SIZE];

SEC("usdt//data/projects/iaprof/intel-graphics-stack/install/lib/libze_intel_gpu.so.1:level_zero:instruction_base_address")
int BPF_USDT(instruction_base_address, __u64 base_addr) {
        struct uprobe_iba_info     *iba_info;
        long                       err;
        
        ERR_PRINTK("instruction_base_address base_addr=0x%lx\n", base_addr);
        
        iba_info = bpf_ringbuf_reserve(&rb, sizeof(*iba_info), 0);
        if (!iba_info) {
                ERR_PRINTK("instruction_base_address failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }
        iba_info->type = BPF_EVENT_TYPE_UPROBE_IBA;
        iba_info->addr = base_addr;
        iba_info->pid  = bpf_get_current_pid_tgid() >> 32;
        iba_info->tid  = bpf_get_current_pid_tgid();
        bpf_ringbuf_submit(iba_info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

SEC("usdt//data/projects/iaprof/intel-graphics-stack/install/lib/libze_intel_gpu.so.1:level_zero:launch_kernel")
int BPF_USDT(launch_kernel, __u64 gpu_addr, __u64 size, char *kernel_name) {
        struct uprobe_ksp_info     *ksp_info;
        long                       err;
        
        ERR_PRINTK("launch_kernel gpu_addr=0x%lx\n", gpu_addr);
        
        /* Send the KSP_INFO */
        ksp_info = bpf_ringbuf_reserve(&rb, sizeof(*ksp_info), 0);
        if (!ksp_info) {
                ERR_PRINTK("launch_kernel failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }
        err = bpf_get_stack(ctx, &(ksp_info->ustack.addrs), sizeof(ksp_info->ustack.addrs), BPF_F_USER_STACK);
        if (err < 0) {
                WARN_PRINTK("launch_kernel failed to get a user stack: %ld", err);
        }
        ksp_info->type = BPF_EVENT_TYPE_UPROBE_KSP;
        ksp_info->addr = gpu_addr;
        ksp_info->pid  = bpf_get_current_pid_tgid() >> 32;
        ksp_info->tid  = bpf_get_current_pid_tgid();
        ksp_info->cpu  = bpf_get_smp_processor_id();
        ksp_info->time = bpf_ktime_get_ns();
        ksp_info->size = size;
        bpf_get_current_comm(ksp_info->name, sizeof(ksp_info->name));
        bpf_ringbuf_submit(ksp_info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

SEC("usdt//data/projects/iaprof/intel-graphics-stack/install/lib/libze_intel_gpu.so.1:level_zero:compile_kernel")
int BPF_USDT(compile_kernel, char *file_name) {
        struct uprobe_kernel_path  *kpath;
        long                       err;
        
        /* Send the KSP_INFO */
        kpath = bpf_ringbuf_reserve(&rb, sizeof(*kpath), 0);
        if (!kpath) {
                ERR_PRINTK("compile_kernel failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }
        kpath->type = BPF_EVENT_TYPE_UPROBE_KERNEL_PATH;
        kpath->pid  = bpf_get_current_pid_tgid() >> 32;
        kpath->tid  = bpf_get_current_pid_tgid();
        bpf_probe_read_user_str(kpath->filename, sizeof(kpath->filename), file_name);
        
        bpf_ringbuf_submit(kpath, BPF_RB_FORCE_WAKEUP);

        return 0;
}
