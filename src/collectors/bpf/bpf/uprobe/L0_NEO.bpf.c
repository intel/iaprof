struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, u32);
        __type(value, u64);
} setKernelStartPointer_wait_for_appendLaunchKernelWithParams SEC(".maps");


SEC("uprobe//home/ubuntu/intc/iaprof_scripts/tools/prefix/intel_graphics_stack_fp/lib/libze_intel_gpu.so.1:_ZN3NEO9XeHpcCore28tagINTERFACE_DESCRIPTOR_DATA21setKernelStartPointerEm")
int BPF_UPROBE(setKernelStartPointer, void *this, u64 addr) {
        u32 zero = 0;
        bpf_map_update_elem(&setKernelStartPointer_wait_for_appendLaunchKernelWithParams, &zero, &addr, 0);
        return 0;
}


SEC("uretprobe//home/ubuntu/intc/iaprof_scripts/tools/prefix/intel_graphics_stack_fp/lib/libze_intel_gpu.so.1:_ZN2L021CommandListCoreFamilyIL14GFXCORE_FAMILY3080EE28appendLaunchKernelWithParamsEPNS_6KernelERK17_ze_group_count_tPNS_5EventERNS_25CmdListKernelLaunchParamsE")
int BPF_URETPROBE(appendLaunchKernelWithParams) {
        u64                    *lookup;
        u32                     zero = 0;
        u64                     addr;
        struct uprobe_ksp_info *info;
        long                    err;

        lookup = bpf_map_lookup_elem(&setKernelStartPointer_wait_for_appendLaunchKernelWithParams, &zero);
        if (lookup == NULL) {
                WARN_PRINTK("appendLaunchKernelWithParams, but no setKernelStartPointer");
                return 0;
        }

        addr = *lookup & 0xFFFFFFFFFFC0;

        bpf_map_delete_elem(&setKernelStartPointer_wait_for_appendLaunchKernelWithParams, &zero);

        info = bpf_ringbuf_reserve(&rb, sizeof(*info), 0);
        if (!info) {
                ERR_PRINTK("appendLanuchKernelWithParams failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }

        info->type = BPF_EVENT_TYPE_UPROBE_KSP;

        info->addr = addr;

        err = bpf_get_stack(ctx, &(info->ustack.addrs), sizeof(info->ustack.addrs), BPF_F_USER_STACK);
        if (err < 0) {
                WARN_PRINTK("appendLaunchKernelWithParams failed to get a user stack: %ld", err);
        }

        info->pid   = bpf_get_current_pid_tgid() >> 32;
        info->tid   = bpf_get_current_pid_tgid();
        info->cpu   = bpf_get_smp_processor_id();
        info->time  = bpf_ktime_get_ns();
        bpf_get_current_comm(info->name, sizeof(info->name));

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
