// Copyright 2025 Intel Corporation
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

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
        struct drm_xe_vm_bind *args;
        u32 tmp_arg_key;
        long retval;
        u64 page_idx, num_pages, page_addr;

        /* For getting the cpu_addr */
        struct file_handle_pair pair = {};
        struct binding_info bindinfo = {};

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

        if (args->bind.op != DRM_XE_VM_BIND_OP_MAP_USERPTR) {
                /* Get the CPU address from any mappings that have happened */
                pair.handle = args->bind.obj;
                pair.file = (u64)file;

                bindinfo.gpu_addr = args->bind.addr;
                bindinfo.size = args->bind.range;
                bindinfo.vm_id = args->vm_id;

                /* Add this binding to the file_handle_binding map */
                bpf_map_update_elem(&file_handle_binding, &pair, &bindinfo, 0);

                lookup = bpf_map_lookup_elem(&file_handle_mapping, &pair);
                if (!lookup) {
                        WARN_PRINTK("vm_bind_ioctl failed to find a CPU address for gpu_addr=0x%lx handle=%u.", args->bind.addr, pair.handle);
                } else {
                        /* Maintain a map of GPU->CPU addrs */
                        if (args->bind.range && args->bind.addr) {
                                struct cpu_mapping cmapping = {};
                                struct gpu_mapping gmapping = {};
                                cmapping.size = args->bind.range;
                                cmapping.addr = *((u64 *)lookup);
                                gmapping.addr = args->bind.addr;
                                gmapping.vm_id = args->vm_id;
                                gmapping.file = (u64)file;
                                bpf_map_update_elem(&gpu_cpu_map, &gmapping, &cmapping, 0);
                                bpf_map_update_elem(&cpu_gpu_map, &cmapping, &gmapping, 0);
                                num_pages = args->bind.range / PAGE_SIZE;
                                bpf_for(page_idx, 0, num_pages) {
                                        page_addr = gmapping.addr + (page_idx * PAGE_SIZE);
                                        bpf_map_update_elem(&page_map, &page_addr, &(gmapping.addr), 0);
                                }
                        } else {
                                WARN_PRINTK("vm_bind_ioctl failed to insert into the gpu_cpu_map gpu_addr=0x%lx size=%lu", args->bind.addr, args->bind.range);
                        }
                }
        }

        u64 offset = 0;
        if (args->bind.op == DRM_XE_VM_BIND_OP_MAP_USERPTR) {
                offset = args->bind.userptr;
        } else {
                offset = args->bind.obj_offset;
        }

        DEBUG_PRINTK("vm_bind vm_id=%u handle=%u gpu_addr=0x%lx userptr=0x%lx num_binds=%u size=%lu file=0x%lx", args->vm_id, args->bind.obj, args->bind.addr, offset, args->num_binds, args->bind.range, (u64)file);

        return 0;
}

#endif
