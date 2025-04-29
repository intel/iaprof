// Copyright 2025 Intel Corporation
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

/***************************************
* MMAP
*
* These BPF programs trace the various ways in which
* applications can create CPU-side mappings of GPU
* buffers. The purpose here is to capture CPU-side
* copies of those buffers and send them back to userspace.
***************************************/

#ifndef DISABLE_BPF

#include "main.h"

#define PAGE_SHIFT 12
#define pgoff_t unsigned long
#define pgprot_t unsigned long

/***************************************
* mmap_wait_for_unmap
*
* This map stores addresses and sizes that have been mapped
* using the `mmap`, `mmap_offset`, or `userptr` ioctls. These
* addresses, having simply been mapped, have not necessarily
* been *written* to, so we must wait until they're executed
* (e.g. being sent to the execbuffer ioctl) to know that data
* has been written into them.
*
* This map stores those pointers so that they can be found
* once executed, further down in this program.
***************************************/

struct fake_offset_pointer {
        u64 cpu_addr;
        u64 fake_offset;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_MAPPINGS);
        __type(key, struct fake_offset_pointer);
        __type(value, struct file_handle_pair);
} mmap_wait_for_unmap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_MAPPINGS);
        __type(key, struct file_handle_pair);
        __type(value, u64);
} file_handle_mapping SEC(".maps");

struct binding_info {
        u64 size;
        u64 gpu_addr;
        u32 vm_id;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_MAPPINGS);
        __type(key, struct file_handle_pair);
        __type(value, struct binding_info);
} file_handle_binding SEC(".maps");

int mmap_wait_for_unmap_insert(u64 file, u32 handle, u64 addr_arg, u64 vm_pgoff)
{
        struct file_handle_pair unmap_val = {};
        struct fake_offset_pointer foffset = {};
        int retval;
        u64 addr;

        /* We also want to let munmap calls do a lookup with the address */
        unmap_val.file = file;
        unmap_val.handle = handle;
        foffset.cpu_addr = addr_arg;
        foffset.fake_offset = vm_pgoff;
        retval = bpf_map_update_elem(&mmap_wait_for_unmap, &foffset, &unmap_val, 0);
        if (retval < 0) {
                DEBUG_PRINTK("mmap_wait_for_unmap_insert failed file=%p handle=%u cpu_addr=0x%lx",
                           file, handle, addr);
                return -1;
        }

        return 0;
}

/***************************************
* i915_gem_mmap_offset_ioctl and i915_gem_mmap
*
* If we see that an application has mmap'd a GEM to write it later, let's record that in an
* internal map, then output it to userspace after we know that it has been written (which is
* when i915_gem_do_execbuffer is called).
* This codepath differs from i915_gem_mmap_ioctl because it requires tracing i915_gem_mmap_offset_ioctl
* to get the GEM's handle, then i915_gem_mmap to see it get mmap'd.
***************************************/

/* Structs for mmap/mmap_offset */
struct mmap_offset_wait_for_mmap_val {
        u64 file;
        u32 handle;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_MAPPINGS);
        __type(key, u64);
        __type(value, struct mmap_offset_wait_for_mmap_val);
} mmap_offset_wait_for_mmap SEC(".maps");

SEC("fexit/xe_gem_mmap_offset_ioctl")
int BPF_PROG(xe_gem_mmap_offset_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{
        u32 cpu, handle;
        u64 fake_offset;
        void *lookup;
        struct mmap_offset_wait_for_mmap_val mmap_val;
        struct drm_xe_gem_mmap_offset *args;

        args = (struct drm_xe_gem_mmap_offset *)data;

        /* At this point, this pointer to a drm_i915_gem_mmap_offset contains a handle
           and a fake offset. Let's store them and read them when the mmap actually happens. */
        fake_offset = BPF_CORE_READ(args, offset);
        handle = BPF_CORE_READ(args, handle);

        __builtin_memset(&mmap_val, 0,
                         sizeof(struct mmap_offset_wait_for_mmap_val));
        mmap_val.file = (u64)file;
        mmap_val.handle = handle;
        bpf_map_update_elem(&mmap_offset_wait_for_mmap, &fake_offset, &mmap_val,
                            0);

        DEBUG_PRINTK("mmap_offset_ioctl_kretprobe fake_offset=0x%lx file=0x%lx handle=%u", fake_offset, file, handle);

        return 0;
}

#define drm_gem_ttm_of_gem(gem_obj) \
        container_of(gem_obj, struct ttm_buffer_object, base)

SEC("fexit/drm_gem_ttm_mmap")
int BPF_PROG(drm_gem_ttm_mmap,
             struct drm_gem_object *gem,
             struct vm_area_struct *vma)
{
        u64 vm_pgoff, vm_start, vm_end, status;
        void *lookup, *bind_lookup;
        struct binding_info *binding;
        struct mmap_offset_wait_for_mmap_val offset_val;
        struct file_handle_pair pair = {};
        u64 page_idx, num_pages, page_addr;

        vm_pgoff = BPF_CORE_READ(vma, vm_pgoff);
        vm_start = BPF_CORE_READ(vma, vm_start);
        vm_end = BPF_CORE_READ(vma, vm_end);
        vm_pgoff = vm_pgoff << PAGE_SHIFT;

        /* Get the handle from the previous i915_gem_mmap_offset_ioctl call. */
        lookup = bpf_map_lookup_elem(&mmap_offset_wait_for_mmap, &vm_pgoff);
        if (!lookup) {
                WARN_PRINTK("drm_gem_ttm_mmap failed to see mmap_offset on vm_pgoff=0x%lx",
                             vm_pgoff);
                return 0;
        }
        __builtin_memcpy(&offset_val, lookup,
                         sizeof(struct mmap_offset_wait_for_mmap_val));

        /* Add this file/handle/cpu_addr to be seen by a future vm_bind */
        pair.handle = offset_val.handle;
        pair.file = offset_val.file;
        bpf_map_update_elem(&file_handle_mapping, &pair, &vm_start, 0);
        
        /* Look up to see if we've seen a binding on this file/handle pair */
        bind_lookup = bpf_map_lookup_elem(&file_handle_binding, &pair);
        if (!bind_lookup) {
                WARN_PRINTK("drm_gem_ttm_mmap failed to find a GPU address for file=0x%lx handle=%u.", pair.file, pair.handle);
        } else {
                /* Maintain a map of GPU->CPU addrs */
                binding = (struct binding_info *)bind_lookup;
                struct cpu_mapping cmapping = {};
                struct gpu_mapping gmapping = {};
                cmapping.size = binding->size;
                cmapping.addr = vm_start;
                gmapping.addr = binding->gpu_addr;
                gmapping.vm_id = binding->vm_id;
                gmapping.file = (u64)pair.file;
                bpf_map_update_elem(&gpu_cpu_map, &gmapping, &cmapping, 0);
                bpf_map_update_elem(&cpu_gpu_map, &cmapping, &gmapping, 0);
                num_pages = binding->size / PAGE_SIZE;
                bpf_for(page_idx, 0, num_pages) {
                        page_addr = gmapping.addr + (page_idx * PAGE_SIZE);
                        bpf_map_update_elem(&page_map, &page_addr, &(gmapping.addr), 0);
                }
        }

        DEBUG_PRINTK("drm_gem_ttm_mmap cpu_addr=0x%lx handle=%u file=0x%lx", vm_start, offset_val.handle, pair.file);

        mmap_wait_for_unmap_insert(offset_val.file, offset_val.handle,
                                   vm_start, vm_pgoff);

        return 0;
}

/***************************************
* munmap
*
* Some GEMs are mapped, written, and immediately unmapped. For these,
* we need to read and copy them before they are unmapped, and do so
* synchronously with the kernel driver.
***************************************/

SEC("fentry/ttm_bo_vm_close")
int BPF_PROG(ttm_bo_vm_close,
             struct vm_area_struct *vma)
{
        long retval;
        struct ttm_buffer_object *bo;
        struct fake_offset_pointer foffset = {};
        struct file_handle_pair *val;
        struct cpu_mapping cmapping = {};
        struct gpu_mapping *gmapping;
        struct gpu_mapping save_gmapping = {};
        u64 fake_offset, size, cpu_addr, status;
        char one = 1;
        struct address_range range = {};

        bo = (struct ttm_buffer_object *)BPF_CORE_READ(vma, vm_private_data);
        cpu_addr = BPF_CORE_READ(vma, vm_start);
        size = BPF_CORE_READ(vma, vm_end) - cpu_addr;
        fake_offset = BPF_CORE_READ(bo, base).vma_node.vm_node.start << PAGE_SHIFT;

        if (!fake_offset) {
                WARN_PRINTK("ttm_bo_vm_close failed to get a fake_offset");
                return 0;
        }

        if (!cpu_addr) {
                WARN_PRINTK("ttm_bo_vm_close failed to get a cpu_addr");
                return 0;
        }
        foffset.cpu_addr = cpu_addr;
        foffset.fake_offset = fake_offset;
        val = bpf_map_lookup_elem(&mmap_wait_for_unmap, &foffset);
        if (!val) {
                return 0;
        }

        DEBUG_PRINTK("ttm_bo_vm_close cpu_addr=0x%lx file=0x%lx handle=%u", cpu_addr, val->file, val->handle);
        DEBUG_PRINTK("  size=%lu fake_offset=0x%lx", size, fake_offset);

        cmapping.size = size;
        cmapping.addr = cpu_addr;

        gmapping = bpf_map_lookup_elem(&cpu_gpu_map, &cmapping);
        save_gmapping.addr = 0;
        save_gmapping.vm_id = 0;
        save_gmapping.file = 0;
        if (gmapping) {
                range.start = gmapping->addr;
                range.end   = gmapping->addr + size;
                try_parse_deferred_batchbuffers(&range);

                DEBUG_PRINTK("  removing 0x%lx from the gpu_cpu_map", gmapping->addr);
                save_gmapping.addr = gmapping->addr;
                save_gmapping.vm_id = gmapping->vm_id;
                save_gmapping.file = gmapping->file;
                if (bpf_map_delete_elem(&gpu_cpu_map, gmapping)) {
                        WARN_PRINTK("munmap failed to delete gpu_addr=0x%lx from the gpu_cpu_map!", gmapping->addr);
                }
        } else {
            DEBUG_PRINTK("  no gpu mapping");
        }
        gmapping = NULL;
        if (bpf_map_delete_elem(&cpu_gpu_map, &cmapping)) {
                WARN_PRINTK("munmap failed to delete cpu_addr=0x%lx from the cpu_gpu_map!", cpu_addr);
        }

        return 0;
}

#endif
