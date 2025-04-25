typedef struct _ze_kernel_desc_t
{
    u32 stype;
    const void* pNext;
    u32 flags;
    const char* pKernelName;
} ze_kernel_desc_t;

struct zeKernelCreate_args {
        void             *hModule;
        ze_kernel_desc_t *descp;
        void             *phKernel;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, u32);
        __type(value, struct zeKernelCreate_args);
} zeKernelCreate_wait_for_ret SEC(".maps");

char null_symbol[MAX_SYMBOL_SIZE];

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, u64);
        __type(value, char[MAX_SYMBOL_SIZE]);
} kernel_symbols SEC(".maps");

SEC("uprobe//home/ubuntu/intc/iaprof_scripts/tools/prefix/intel_graphics_stack_fp/lib/libze_intel_gpu.so.1:_ZN2L014zeKernelCreateEP19_ze_module_handle_tPK17_ze_kernel_desc_tPP19_ze_kernel_handle_t")
int BPF_UPROBE(zeKernelCreate, void *hModule, ze_kernel_desc_t *descp, void *phKernel) {
        u32                        tid;
        struct zeKernelCreate_args args = {};

        tid = bpf_get_current_pid_tgid();

        args.hModule  = hModule;
        args.descp    = descp;
        args.phKernel = phKernel;

        bpf_map_update_elem(&zeKernelCreate_wait_for_ret, &tid, &args, 0);

        return 0;
}

SEC("uretprobe//home/ubuntu/intc/iaprof_scripts/tools/prefix/intel_graphics_stack_fp/lib/libze_intel_gpu.so.1:_ZN2L014zeKernelCreateEP19_ze_module_handle_tPK17_ze_kernel_desc_tPP19_ze_kernel_handle_t")
int BPF_URETPROBE(zeKernelCreate_ret) {
        u32                          tid;
        struct zeKernelCreate_args  *args;
        u64                          kernel_ptr;
        ze_kernel_desc_t             desc;
        char                       (*sym)[MAX_SYMBOL_SIZE];

        tid = bpf_get_current_pid_tgid();

        args = bpf_map_lookup_elem(&zeKernelCreate_wait_for_ret, &tid);
        if (args == NULL) { return 0; }

        bpf_probe_read_user(&kernel_ptr, sizeof(kernel_ptr), args->phKernel);
        bpf_probe_read_user(&desc, sizeof(desc), args->descp);

        bpf_map_update_elem(&kernel_symbols, &kernel_ptr, &null_symbol, 0);
        sym = bpf_map_lookup_elem(&kernel_symbols, &kernel_ptr);
        if (sym == NULL) { return 0; }

        bpf_probe_read_user_str(*sym, sizeof(*sym), desc.pKernelName);

        return 0;
}


struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, u32);
        __type(value, u64);
} setKernelStartPointer_wait_for_appendLaunchKernelWithParams SEC(".maps");

SEC("uprobe//home/ubuntu/intc/iaprof_scripts/tools/prefix/intel_graphics_stack_fp/lib/libze_intel_gpu.so.1:_ZN3NEO9XeHpcCore28tagINTERFACE_DESCRIPTOR_DATA21setKernelStartPointerEm")
int BPF_UPROBE(setKernelStartPointer, void *this, u64 addr) {
        u32 tid;

        tid = bpf_get_current_pid_tgid();

        bpf_map_update_elem(&setKernelStartPointer_wait_for_appendLaunchKernelWithParams, &tid, &addr, 0);

        return 0;
}

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, u32);
        __type(value, u64);
} appendLaunchKernelWithParams_wait_for_ret SEC(".maps");

SEC("uprobe//home/ubuntu/intc/iaprof_scripts/tools/prefix/intel_graphics_stack_fp/lib/libze_intel_gpu.so.1:_ZN2L021CommandListCoreFamilyIL14GFXCORE_FAMILY3080EE28appendLaunchKernelWithParamsEPNS_6KernelERK17_ze_group_count_tPNS_5EventERNS_25CmdListKernelLaunchParamsE")
int BPF_UPROBE(appendLaunchKernelWithParams, void *this, u64 kernel_ptr) {
        u32 tid;

        tid = bpf_get_current_pid_tgid();

        bpf_map_update_elem(&appendLaunchKernelWithParams_wait_for_ret, &tid, &kernel_ptr, 0);

        return 0;
}

SEC("uretprobe//home/ubuntu/intc/iaprof_scripts/tools/prefix/intel_graphics_stack_fp/lib/libze_intel_gpu.so.1:_ZN2L021CommandListCoreFamilyIL14GFXCORE_FAMILY3080EE28appendLaunchKernelWithParamsEPNS_6KernelERK17_ze_group_count_tPNS_5EventERNS_25CmdListKernelLaunchParamsE")
int BPF_URETPROBE(appendLaunchKernelWithParams_ret) {
        u32                         tid;
        u64                        *lookup;
        u64                         addr;
        struct uprobe_ksp_info     *ksp_info;
        long                        err;
        u64                        *kernel_ptr;
        char                      (*sym)[MAX_SYMBOL_SIZE];
        struct uprobe_kernel_info  *kernel_info;


        tid = bpf_get_current_pid_tgid();

        lookup = bpf_map_lookup_elem(&setKernelStartPointer_wait_for_appendLaunchKernelWithParams, &tid);
        if (lookup == NULL) {
                WARN_PRINTK("appendLaunchKernelWithParams, but no setKernelStartPointer");
                return 0;
        }

        addr = *lookup & 0xFFFFFFFFFFC0;

        bpf_map_delete_elem(&setKernelStartPointer_wait_for_appendLaunchKernelWithParams, &tid);

        ksp_info = bpf_ringbuf_reserve(&rb, sizeof(*ksp_info), 0);
        if (!ksp_info) {
                ERR_PRINTK("appendLanuchKernelWithParams failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }

        ksp_info->type = BPF_EVENT_TYPE_UPROBE_KSP;

        ksp_info->addr = addr;

        err = bpf_get_stack(ctx, &(ksp_info->ustack.addrs), sizeof(ksp_info->ustack.addrs), BPF_F_USER_STACK);
        if (err < 0) {
                WARN_PRINTK("appendLaunchKernelWithParams failed to get a user stack: %ld", err);
        }

        ksp_info->pid  = bpf_get_current_pid_tgid() >> 32;
        ksp_info->tid  = bpf_get_current_pid_tgid();
        ksp_info->cpu  = bpf_get_smp_processor_id();
        ksp_info->time = bpf_ktime_get_ns();
        bpf_get_current_comm(ksp_info->name, sizeof(ksp_info->name));

        bpf_ringbuf_submit(ksp_info, BPF_RB_FORCE_WAKEUP);

        kernel_ptr = bpf_map_lookup_elem(&appendLaunchKernelWithParams_wait_for_ret, &tid);
        if (kernel_ptr == NULL) { return 0; }

        sym = bpf_map_lookup_elem(&kernel_symbols, kernel_ptr);
        if (sym == NULL) { return 0; }

        kernel_info = bpf_ringbuf_reserve(&rb, sizeof(*kernel_info), 0);
        if (!kernel_info) {
                ERR_PRINTK("appendLanuchKernelWithParams failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }

        kernel_info->type = BPF_EVENT_TYPE_UPROBE_KERNEL_INFO;

        kernel_info->addr = addr;

        __builtin_memcpy(kernel_info->symbol, *sym, sizeof(kernel_info->symbol));

        bpf_ringbuf_submit(kernel_info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
