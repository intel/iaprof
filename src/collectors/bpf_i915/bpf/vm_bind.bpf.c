/***************************************
* i915_gem_vm_bind_ioctl
*
* Look for virtual addresses that userspace is trying to [un]bind.
***************************************/

SEC("fexit/i915_gem_vm_bind_ioctl")
int BPF_PROG(i915_gem_vm_bind_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{
        u32 cpu, handle, vm_id;
        u64 status, size;
        void *lookup;
        struct vm_bind_info *info;
        struct prelim_drm_i915_gem_vm_bind *args;
        int retval = 0;

        /* For getting the cpu_addr */
        u64 cpu_addr, gpu_addr;
        struct file_handle_pair pair = {};

        args = (struct prelim_drm_i915_gem_vm_bind *)data;

        /* Read arguments onto the stack */
        handle = BPF_CORE_READ(args, handle);
        vm_id = BPF_CORE_READ(args, vm_id);
        size = BPF_CORE_READ(args, length);
        gpu_addr = BPF_CORE_READ(args, start);
        cpu_addr = 0;
        
        bpf_printk("vm_bind kretprobe handle=%u gpu_addr=0x%lx", handle, gpu_addr);

#ifndef BUFFER_COPY_METHOD_DEBUG
        /* Get the CPU address from any mappings that have happened */
        pair.handle = handle;
        pair.file = (u64)file;
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
                        bpf_map_update_elem(&cpu_gpu_map, &cmapping, &gmapping, 0);
                }
        }
#endif

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct vm_bind_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: vm_bind_ioctl failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return 0;
        }

        /* vm_bind specific values */
        info->type = BPF_EVENT_TYPE_VM_BIND;
        info->file = (u64)file;
        info->handle = handle;
        info->vm_id = vm_id;
        info->gpu_addr = gpu_addr;
        info->size = size;
        info->offset = BPF_CORE_READ(args, offset);
        info->flags = BPF_CORE_READ(args, flags);

        info->cpu = bpf_get_smp_processor_id();
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
        info->time = bpf_ktime_get_ns();

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

SEC("fentry/i915_gem_vm_unbind_ioctl")
int BPF_PROG(i915_gem_vm_unbind_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{
        struct vm_unbind_info *info;
        struct prelim_drm_i915_gem_vm_bind *arg;
        u64 status, gpu_addr;
        u32 vm_id;
        struct gpu_mapping gmapping = {};
        struct cpu_mapping cmapping = {};
        int retval = 0;
        void *lookup;

        arg = (struct prelim_drm_i915_gem_vm_bind *)data;

        /* Get the address and VM that's getting unbound */
        vm_id = BPF_CORE_READ(arg, vm_id);
        gpu_addr = BPF_CORE_READ(arg, start);

#ifndef BUFFER_COPY_METHOD_DEBUG

        /* Find the CPU mapping for this GPU address */
        gmapping.vm_id = vm_id;
        gmapping.addr = gpu_addr;
        lookup = bpf_map_lookup_elem(&gpu_cpu_map, &gmapping);
        if (!lookup) {
                bpf_printk(
                        "WARNING: vm_unbind_ioctl failed to delete gpu_addr=0x%lx from the gpu_cpu_map.", gpu_addr);
                return 0;
        }
        __builtin_memcpy(&cmapping, lookup,
                         sizeof(struct cpu_mapping));
                         
        /* Delete the element from the gpu_cpu_map and cpu_gpu_map */
        retval = bpf_map_delete_elem(&gpu_cpu_map, &gmapping);
        if (retval < 0) {
                bpf_printk(
                        "WARNING: vm_unbind_ioctl failed to delete gpu_addr=0x%lx from the gpu_cpu_map.", gpu_addr);
        }
        retval = bpf_map_delete_elem(&cpu_gpu_map, &cmapping);
        if (retval < 0) {
                bpf_printk(
                        "WARNING: vm_unbind_ioctl failed to delete cpu_addr=0x%lx from the cpu_gpu_map.", cmapping.addr);
        }
#endif

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct vm_unbind_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: vm_unbind_ioctl failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return 0;
        }

        /* vm_unbind specific values */
        info->type = BPF_EVENT_TYPE_VM_UNBIND;
        info->file = (u64)file;
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
