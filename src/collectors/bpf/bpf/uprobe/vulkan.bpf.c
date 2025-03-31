struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, u32);
        __type(value, u64);
} alloc_wait_for_shader_bin_create SEC(".maps");

struct anv_state {
   int64_t offset;
   uint32_t alloc_size;
   uint32_t idx;
   void *map;
};

/*
SEC("uprobe//home/ubuntu/intc/iaprof_scripts/tools/prefix/intel_graphics_stack_fp/lib/libze_intel_gpu.so.1:_ZN3NEO9XeHpcCore21tagSTATE_BASE_ADDRESS25setInstructionBaseAddressEm")
int BPF_UPROBE(setInstructionBaseAddress, void *this, u64 addr) {
        struct uprobe_iba_info *info;
        long                    err;

        info = bpf_ringbuf_reserve(&rb, sizeof(*info), 0);
        if (!info) {
                ERR_PRINTK("setInstructionBaseAddress failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }

        info->type = BPF_EVENT_TYPE_UPROBE_IBA;

        info->addr = addr;

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
*/

SEC("uretprobe//usr/lib/libvulkan_intel.so:anv_state_pool_alloc")
int BPF_URETPROBE(anv_state_pool_alloc, u64 ret) {
        u32 zero = 0;
        bpf_map_update_elem(&alloc_wait_for_shader_bin_create, &zero, &ret, 0);
        DEBUG_PRINTK("anv_state_pool_alloc 0x%llx", ret);
        return 0;
}

SEC("uretprobe//usr/lib/libvulkan_intel.so:anv_shader_bin_create")
int BPF_URETPROBE(anv_shader_bin_create, u64 ret) {
        u64                    *lookup;
        u32                     zero = 0;
        u64                     addr;
        struct uprobe_ksp_info *info;
        long                    err;
        struct anv_state       *in_state;
        struct anv_state        state = {};
        
        lookup = bpf_map_lookup_elem(&alloc_wait_for_shader_bin_create, &zero);
        if (lookup == NULL) {
                WARN_PRINTK("anv_shader_bin_create, but no anv_state_pool_alloc");
                return 0;
        }

        in_state = (struct anv_state *)*lookup;
        
        if (!in_state) {
          WARN_PRINTK("anv_shader_bin_create got a NULL anv_state");
          return 0;
        }
        
        err = bpf_probe_read_user(&state, sizeof(state), in_state);
        if (err) {
          WARN_PRINTK("anv_shader_bin_create failed to read the anv_state");
          return 0;
        }
        addr = state.offset & 0xFFFFFFFFFFC0;
        DEBUG_PRINTK("anv_shader_bin_create: 0x%llx\n", addr);

        bpf_map_delete_elem(&alloc_wait_for_shader_bin_create, &zero);

        info = bpf_ringbuf_reserve(&rb, sizeof(*info), 0);
        if (!info) {
                ERR_PRINTK("anv_shader_bin_create failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }

        info->type = BPF_EVENT_TYPE_UPROBE_KSP;

        info->addr = addr;

        err = bpf_get_stack(ctx, &(info->ustack.addrs), sizeof(info->ustack.addrs), BPF_F_USER_STACK);
        if (err < 0) {
                WARN_PRINTK("anv_shader_bin_create failed to get a user stack: %ld", err);
        }

        info->pid   = bpf_get_current_pid_tgid() >> 32;
        info->tid   = bpf_get_current_pid_tgid();
        info->cpu   = bpf_get_smp_processor_id();
        info->time  = bpf_ktime_get_ns();
        bpf_get_current_comm(info->name, sizeof(info->name));

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
