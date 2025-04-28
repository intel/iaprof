/*
Copyright 2025 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

        DEBUG_PRINTK("vm_bind kretprobe handle=%u vm_id=%u gpu_addr=0x%lx", handle, vm_id, gpu_addr);

        /* Get the CPU address from any mappings that have happened */
        pair.handle = handle;
        pair.file = (u64)file;
        lookup = bpf_map_lookup_elem(&file_handle_mapping, &pair);
        if (!lookup) {
                WARN_PRINTK("vm_bind_ioctl failed to find a CPU address for gpu_addr=0x%lx.", gpu_addr);
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
                        gmapping.file = (u64)file;
                        bpf_map_update_elem(&gpu_cpu_map, &gmapping, &cmapping, 0);
                        bpf_map_update_elem(&cpu_gpu_map, &cmapping, &gmapping, 0);
                } else {
                        WARN_PRINTK("vm_bind_ioctl failed to insert into the gpu_cpu_map gpu_addr=0x%lx size=%lu", gpu_addr, size);
                }
        }

        return 0;
}

SEC("fentry/i915_gem_vm_unbind_ioctl")
int BPF_PROG(i915_gem_vm_unbind_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{
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
                WARN_PRINTK("vm_unbind_ioctl failed to delete gpu_addr=0x%lx from the gpu_cpu_map.", gpu_addr);
                return 0;
        }
        __builtin_memcpy(&cmapping, lookup,
                         sizeof(struct cpu_mapping));

        /* Delete the element from the gpu_cpu_map and cpu_gpu_map */
        retval = bpf_map_delete_elem(&gpu_cpu_map, &gmapping);
        if (retval < 0) {
                WARN_PRINTK("vm_unbind_ioctl failed to delete gpu_addr=0x%lx from the gpu_cpu_map.", gpu_addr);
        }
        retval = bpf_map_delete_elem(&cpu_gpu_map, &cmapping);
        if (retval < 0) {
                WARN_PRINTK("vm_unbind_ioctl failed to delete cpu_addr=0x%lx from the cpu_gpu_map.", cmapping.addr);
        }

        return 0;
}
