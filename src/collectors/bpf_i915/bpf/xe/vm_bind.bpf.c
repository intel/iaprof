/***************************************
* xe_vm_bind_ioctl
*
* Look for virtual addresses that userspace is trying to [un]bind.
***************************************/

#ifndef DISABLE_BPF

/* XXX: Remove once conflicts between bpftool-generated headers and uapi headers
   are fixed. */
#define DRM_XE_VM_BIND_OP_MAP    0x0
#define DRM_XE_VM_BIND_OP_UNMAP    0x1
#define DRM_XE_VM_BIND_OP_MAP_USERPTR  0x2
#define DRM_XE_VM_BIND_OP_UNMAP_ALL  0x3
#define DRM_XE_VM_BIND_OP_PREFETCH  0x4

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, u32);
        __type(value, struct drm_xe_vm_bind);
} tmp_arg_storage SEC(".maps");

SEC("fexit/xe_vm_bind_ioctl")
int BPF_PROG(xe_vm_bind_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{
        void *lookup;
        struct vm_bind_info *info;
        struct drm_xe_vm_bind *args;
        u32 tmp_arg_key;
        long retval;
        u64 page_idx, num_pages, page_addr;

        /* For getting the cpu_addr */
        struct file_handle_pair pair = {};

        /* Read the argument struct (which is large) into a per-cpu array */
        tmp_arg_key = 0;
        args = bpf_map_lookup_elem(&tmp_arg_storage, &tmp_arg_key);
        if (!args) {
                WARN_PRINTK("vm_bind_ioctl failed to reserve space for arguments.");
                return 0;
        }
        retval = bpf_core_read(args, sizeof(*args), data);
        if (retval) {
                WARN_PRINTK("vm_bind_ioctl failed to read arguments.");
                return 0;
        }

        DEBUG_PRINTK("vm_bind_ioctl handle=%u gpu_addr=0x%lx op=0x%x", args->bind.obj, args->bind.addr, args->bind.op);

        if (args->bind.op == DRM_XE_VM_BIND_OP_UNMAP) {
                DEBUG_PRINTK("vm_bind_ioctl unmap handle=%u gpu_addr=0x%lx", args->bind.obj, args->bind.addr);
        }

        if (args->bind.op == DRM_XE_VM_BIND_OP_PREFETCH) {
                DEBUG_PRINTK("vm_bind_ioctl prefetch handle=%u gpu_addr=0x%lx", args->bind.obj, args->bind.addr);
        }

        if ((args->bind.op != DRM_XE_VM_BIND_OP_MAP) &&
            (args->bind.op != DRM_XE_VM_BIND_OP_MAP_USERPTR)) {
                return 0;
        }

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct vm_bind_info), 0);
        if (!info) {
                ERR_PRINTK("vm_bind_ioctl failed to reserve in the ringbuffer.");
                dropped_event = 1;
                return 0;
        }

        /* vm_bind specific values */
        info->type = BPF_EVENT_TYPE_VM_BIND;
        info->file = (u64)file;
        info->handle = args->bind.obj;
        info->vm_id = args->vm_id;
        info->gpu_addr = args->bind.addr;
        info->size = args->bind.range;
        if (args->bind.op == DRM_XE_VM_BIND_OP_MAP_USERPTR) {
                info->userptr = 1;
                info->offset = args->bind.userptr;
        } else {
                info->userptr = 0;
                info->offset = args->bind.obj_offset;
        }
        info->pid = bpf_get_current_pid_tgid() >> 32;

        if (args->bind.op != DRM_XE_VM_BIND_OP_MAP_USERPTR) {
                /* Get the CPU address from any mappings that have happened */
                pair.handle = info->handle;
                pair.file = (u64)file;
                lookup = bpf_map_lookup_elem(&file_handle_mapping, &pair);
                if (!lookup) {
                        WARN_PRINTK("vm_bind_ioctl failed to find a CPU address for gpu_addr=0x%lx handle=%u.", info->gpu_addr, pair.handle);
                } else {
                        /* Maintain a map of GPU->CPU addrs */
                        if (info->size && info->gpu_addr) {
                                struct cpu_mapping cmapping = {};
                                struct gpu_mapping gmapping = {};
                                cmapping.size = info->size;
                                cmapping.addr = *((u64 *)lookup);
                                gmapping.addr = info->gpu_addr;
                                gmapping.vm_id = args->vm_id;
                                gmapping.file = (u64)file;
                                bpf_map_update_elem(&gpu_cpu_map, &gmapping, &cmapping, 0);
                                bpf_map_update_elem(&cpu_gpu_map, &cmapping, &gmapping, 0);
                                num_pages = info->size / PAGE_SIZE;
                                bpf_for(page_idx, 0, num_pages) {
                                        page_addr = gmapping.addr + (page_idx * PAGE_SIZE);
                                        bpf_map_update_elem(&page_map, &page_addr, &(gmapping.addr), 0);
                                        DEBUG_PRINTK("!!! adding 0x%llx to the page_map.", page_addr);
                                }
                        } else {
                                WARN_PRINTK("vm_bind_ioctl failed to insert into the gpu_cpu_map gpu_addr=0x%lx size=%lu", info->gpu_addr, info->size);
                        }
                }
        }

        DEBUG_PRINTK("vm_bind vm_id=%u handle=%u gpu_addr=0x%lx userptr=0x%lx num_binds=%u size=%lu file=0x%lx", info->vm_id, info->handle, info->gpu_addr, info->offset, args->num_binds, info->size, info->file);

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

#if 0
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

        /* Find the CPU mapping for this GPU address */
        gmapping.vm_id = vm_id;
        gmapping.addr = gpu_addr;
        gmapping.file = (u64)file;
        lookup = bpf_map_lookup_elem(&gpu_cpu_map, &gmapping);
        if (!lookup) {
                DEBUG_PRINTK(
                        "WARNING: vm_unbind_ioctl failed to delete gpu_addr=0x%lx from the gpu_cpu_map.", gpu_addr);
                return 0;
        }
        __builtin_memcpy(&cmapping, lookup,
                         sizeof(struct cpu_mapping));

        /* Delete the element from the gpu_cpu_map and cpu_gpu_map */
        retval = bpf_map_delete_elem(&gpu_cpu_map, &gmapping);
        if (retval < 0) {
                DEBUG_PRINTK(
                        "WARNING: vm_unbind_ioctl failed to delete gpu_addr=0x%lx from the gpu_cpu_map.", gpu_addr);
        }
        retval = bpf_map_delete_elem(&cpu_gpu_map, &cmapping);
        if (retval < 0) {
                DEBUG_PRINTK(
                        "WARNING: vm_unbind_ioctl failed to delete cpu_addr=0x%lx from the cpu_gpu_map.", cmapping.addr);
        }

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct vm_unbind_info), 0);
        if (!info) {
                DEBUG_PRINTK(
                        "WARNING: vm_unbind_ioctl failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", status);
                dropped_event = 1;
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
#endif

#endif
