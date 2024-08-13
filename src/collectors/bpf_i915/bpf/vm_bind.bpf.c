/***************************************
* i915_gem_vm_bind_ioctl
*
* Look for virtual addresses that userspace is trying to [un]bind.
***************************************/

struct vm_bind_ioctl_wait_for_ret_val {
        struct prelim_drm_i915_gem_vm_bind *arg;
        u64 file;
};

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);
        __type(value, struct vm_bind_ioctl_wait_for_ret_val);
} vm_bind_ioctl_wait_for_ret SEC(".maps");

SEC("kprobe/i915_gem_vm_bind_ioctl")
int vm_bind_ioctl_kprobe(struct pt_regs *ctx)
{
        u32 cpu;
        struct vm_bind_ioctl_wait_for_ret_val val;
        struct prelim_drm_i915_gem_vm_bind *arg;

        __builtin_memset(&val, 0,
                         sizeof(struct vm_bind_ioctl_wait_for_ret_val));
        arg = (struct prelim_drm_i915_gem_vm_bind *)PT_REGS_PARM2(ctx);
        val.arg = arg;
        val.file = PT_REGS_PARM3(ctx);
        cpu = bpf_get_smp_processor_id();

        bpf_printk("vm_bind kprobe handle=%u gpu_addr=0x%lx", BPF_CORE_READ(arg, handle), BPF_CORE_READ(arg, start));

        bpf_map_update_elem(&vm_bind_ioctl_wait_for_ret, &cpu, &val, 0);

        return 0;
}

SEC("kretprobe/i915_gem_vm_bind_ioctl")
int vm_bind_ioctl_kretprobe(struct pt_regs *ctx)
{
        u32 cpu, handle, vm_id;
        u64 status, size;
        struct prelim_drm_i915_gem_vm_bind *arg;
        struct vm_bind_ioctl_wait_for_ret_val val;
        void *lookup;
        struct vm_bind_info *info;
        int retval = 0;
        u64 buff_sz;

        /* For getting the cpu_addr */
        u64 cpu_addr, gpu_addr;
        struct file_handle_pair pair = {};
        
        /* Bail if the bind failed */
        if (PT_REGS_RC(ctx) != 0) {
                bpf_printk("vm_bind failed");
                return -1;
        }

        /* Grab the argument from the kprobe */
        cpu = bpf_get_smp_processor_id();
        lookup = bpf_map_lookup_elem(&vm_bind_ioctl_wait_for_ret, &cpu);
        if (!lookup)
                return -1;
        __builtin_memcpy(&val, lookup,
                         sizeof(struct vm_bind_ioctl_wait_for_ret_val));
        arg = val.arg;
        
        bpf_printk("vm_bind kretprobe handle=%u gpu_addr=0x%lx", BPF_CORE_READ(arg, handle), BPF_CORE_READ(arg, start));
        
        /* Read arguments onto the stack */
        handle = BPF_CORE_READ(arg, handle);
        vm_id = BPF_CORE_READ(arg, vm_id);
        size = BPF_CORE_READ(arg, length);
        gpu_addr = BPF_CORE_READ(arg, start);
        cpu_addr = 0;

        /* Get the CPU address from any mappings that have happened */
        pair.handle = handle;
        pair.file = val.file;
        lookup = bpf_map_lookup_elem(&file_handle_mapping, &pair);
        if (!lookup) {
                bpf_printk("WARNING: vm_bind_ioctl failed to find a CPU address for gpu_addr=0x%lx.", gpu_addr);
        } else {
                /* Maintain a map of GPU->CPU addrs */
                cpu_addr = *((u64 *)lookup);
                if (size && gpu_addr) {
                        struct cpu_mapping cmapping = {};
                        struct gpu_mapping gmapping = {};
                        cmapping.size = size;
                        cmapping.addr = cpu_addr;
                        gmapping.addr = gpu_addr;
                        gmapping.vm_id = vm_id;
                        bpf_map_update_elem(&gpu_cpu_map, &gmapping, &cmapping, 0);
                }
        }
        
        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct vm_bind_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: vm_bind_ioctl failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return -1;
        }

        /* vm_bind specific values */
        info->file = val.file;
        info->handle = handle;
        info->vm_id = vm_id;
        info->gpu_addr = gpu_addr;
        info->size = size;
        info->offset = BPF_CORE_READ(arg, offset);
        info->flags = BPF_CORE_READ(arg, flags);

        info->cpu = bpf_get_smp_processor_id();
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
        info->time = bpf_ktime_get_ns();
        info->buff_sz = 0;
        
        if (cpu_addr) {
                /* Grab a copy of this buffer */
                buff_sz = size;
                if (buff_sz > MAX_BINARY_SIZE) {
                        buff_sz = MAX_BINARY_SIZE;
                }
                retval = bpf_probe_read_user(info->buff, buff_sz, (void *)cpu_addr);
                info->buff_sz = buff_sz;
                if (retval < 0) {
                        bpf_printk(
                                "WARNING: vm_bind_ioctl failed to copy %lu bytes from handle=%u cpu_addr=0x%lx.",
                                buff_sz, handle, cpu_addr);
                        info->buff_sz = 0;
                }
        }

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        /* Execbuffer needs to know that this GPU addr relates to this vm_id/handle combination. */

        /* 	bpf_printk("vm_bind kretprobe handle=%u gpu_addr=0x%lx", BPF_CORE_READ(arg, handle), BPF_CORE_READ(arg, start)); */

        return 0;
}

SEC("kprobe/i915_gem_vm_unbind_ioctl")
int vm_unbind_ioctl_kprobe(struct pt_regs *ctx)
{
        struct vm_unbind_info *info;
        struct prelim_drm_i915_gem_vm_bind *arg;
        u64 file, status, gpu_addr;
        u32 vm_id;
        struct gpu_mapping mapping = {};
        int retval = 0;

        arg = (struct prelim_drm_i915_gem_vm_bind *)PT_REGS_PARM2(ctx);
        file = PT_REGS_PARM3(ctx);

        /* Get the address and VM that's getting unbound */
        vm_id = BPF_CORE_READ(arg, vm_id);
        gpu_addr = BPF_CORE_READ(arg, start);

        /* Clean up this mapping in the gpu_cpu_map */
        mapping.vm_id = vm_id;
        mapping.addr = gpu_addr;
        retval = bpf_map_delete_elem(&gpu_cpu_map, &mapping);
        if (retval < 0) {
                bpf_printk(
                        "WARNING: vm_unbind_ioctl failed to delete from the gpu_cpu_map.");
        }

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct vm_unbind_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: vm_unbind_ioctl failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return -1;
        }

        /* vm_unbind specific values */
        info->file = file;
        info->handle = BPF_CORE_READ(arg, handle);
        info->vm_id = vm_id;
        info->gpu_addr = gpu_addr;
        info->size = BPF_CORE_READ(arg, length);
        info->offset = BPF_CORE_READ(arg, offset);

        info->cpu = bpf_get_smp_processor_id();
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->time = bpf_ktime_get_ns();

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
