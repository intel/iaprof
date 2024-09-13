/***************************************
* MMAP
*
* These BPF programs trace the various ways in which
* applications can create CPU-side mappings of GPU
* buffers. The purpose here is to capture CPU-side
* copies of those buffers and send them back to userspace.
***************************************/

#include "i915.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

#define PAGE_SHIFT 12

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
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct fake_offset_pointer);
        __type(value, struct file_handle_pair);
} mmap_wait_for_unmap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct file_handle_pair);
        __type(value, u64);
} file_handle_mapping SEC(".maps");

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
        retval =
                bpf_map_update_elem(&mmap_wait_for_unmap, &foffset, &unmap_val, 0);
        if (retval < 0) {
                DEBUG_PRINTK("mmap_wait_for_unmap_insert failed file=%p handle=%u cpu_addr=0x%lx",
                           file, handle, addr);
                return -1;
        }

        return 0;
}

/***************************************
* i915_gem_mmap_ioctl
*
* i915_gem_mmap_ioctl maps an i915 buffer into the CPU's address
* space. From it, we grab a CPU pointer, and place a
* `struct mapping_info` in the ringbuffer.
***************************************/

#if 0
SEC("fexit/i915_gem_mmap_ioctl")
int BPF_PROG(i915_gem_mmap_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{
        u32 handle;
        u64 addr;
        struct drm_i915_gem_mmap *arg;
        struct file_handle_pair pair = {};

        arg = (struct drm_i915_gem_mmap *)data;

        handle = BPF_CORE_READ(arg, handle);
        addr = BPF_CORE_READ(arg, addr_ptr);

        /* Add this file/handle/cpu_addr to be seen by a future vm_bind */
        pair.handle = handle;
        pair.file = (u64)file;
        bpf_map_update_elem(&file_handle_mapping, &pair, &addr, 0);

        mmap_wait_for_unmap_insert((u64)file, handle, addr);

        DEBUG_PRINTK("mmap cpu_addr=0x%lx handle=%u\n", addr, handle);

        return 0;
}
#endif

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
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u64);
        __type(value, struct mmap_offset_wait_for_mmap_val);
} mmap_offset_wait_for_mmap SEC(".maps");

SEC("fexit/i915_gem_mmap_offset_ioctl")
int BPF_PROG(i915_gem_mmap_offset_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{
        u32 cpu, handle;
        u64 fake_offset;
        void *lookup;
        struct mmap_offset_wait_for_mmap_val mmap_val;
        struct drm_i915_gem_mmap_offset *arg;

        arg = (struct drm_i915_gem_mmap_offset *)data;

        /* At this point, this pointer to a drm_i915_gem_mmap_offset contains a handle
           and a fake offset. Let's store them and read them when the mmap actually happens. */
        fake_offset = BPF_CORE_READ(arg, offset);
        handle = BPF_CORE_READ(arg, handle);

        __builtin_memset(&mmap_val, 0,
                         sizeof(struct mmap_offset_wait_for_mmap_val));
        mmap_val.file = (u64)file;
        mmap_val.handle = handle;
        bpf_map_update_elem(&mmap_offset_wait_for_mmap, &fake_offset, &mmap_val,
                            0);

        DEBUG_PRINTK("mmap_offset_ioctl_kretprobe fake_offset=0x%lx file=0x%lx handle=%u", fake_offset, file, handle);

        return 0;
}

SEC("fexit/i915_gem_mmap")
int BPF_PROG(i915_gem_mmap,
             struct file *filp,
             struct vm_area_struct *vma)
{
        int retval;
        u32 cpu;
        u64 vm_pgoff, vm_start, vm_end, status;
        void *lookup;
        struct mmap_offset_wait_for_mmap_val offset_val;
        struct mapping_info *info;
        struct file_handle_pair pair = {};

        vm_pgoff = BPF_CORE_READ(vma, vm_pgoff);
        vm_start = BPF_CORE_READ(vma, vm_start);
        vm_end = BPF_CORE_READ(vma, vm_end);
        vm_pgoff = vm_pgoff << PAGE_SHIFT;

        /* Get the handle from the previous i915_gem_mmap_offset_ioctl call. */
        lookup = bpf_map_lookup_elem(&mmap_offset_wait_for_mmap, &vm_pgoff);
        if (!lookup) {
                DEBUG_PRINTK("i915_gem_mmap failed to see mmap_offset on vm_pgoff=0x%lx",
                           vm_pgoff);
                return 0;
        }
        __builtin_memcpy(&offset_val, lookup,
                         sizeof(struct mmap_offset_wait_for_mmap_val));

        /* Add this file/handle/cpu_addr to be seen by a future vm_bind */
        pair.handle = offset_val.handle;
        pair.file = offset_val.file;
        bpf_map_update_elem(&file_handle_mapping, &pair, &vm_start, 0);

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct mapping_info), 0);
        if (!info) {
                DEBUG_PRINTK(
                        "WARNING: mmap_ioctl_kretprobe failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 0;
        }

        /* mapping specific values */
        info->type = BPF_EVENT_TYPE_MAPPING;
        info->file = offset_val.file;
        info->handle = offset_val.handle;
        info->cpu_addr = vm_start;
        info->size = vm_end - vm_start;
        info->offset = 0;

        info->cpu = bpf_get_smp_processor_id();
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
        info->time = bpf_ktime_get_ns();

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        DEBUG_PRINTK("i915_gem_mmap cpu_addr=0x%lx handle=%u", vm_start, offset_val.handle);

        mmap_wait_for_unmap_insert(offset_val.file, offset_val.handle,
                                   vm_start, vm_pgoff);

        return 0;
}

/***************************************
* i915_gem_userptr_ioctl
*
* Userspace can give the kernel driver a pointer (and size) to
* some CPU-allocated memory, which the kernel will then create a GEM from.
***************************************/

SEC("fexit/i915_gem_userptr_ioctl")
int BPF_PROG(i915_gem_userptr_ioctl,
             struct drm_device *dev,
             void *data,
             struct drm_file *file)
{
        int err;
        u32 handle;
        u64 size, status, cpu_addr;
        struct drm_i915_gem_userptr *arg;
        struct userptr_info *bin;
        char one = 1;

        arg = (struct drm_i915_gem_userptr *)data;

        cpu_addr = BPF_CORE_READ(arg, user_ptr);
        size = BPF_CORE_READ(arg, user_size);
        handle = BPF_CORE_READ(arg, handle);

        if (looks_like_batch_buffer((void*)cpu_addr, size)) {
                if (buffer_copy_add((void*)cpu_addr, size)) {
/*                         DEBUG_PRINTK("!!! BB 0 0 0x%lx %u", (u64)file, handle); */

                        /* Reserve some space on the ringbuffer */
                        bin = bpf_ringbuf_reserve(&rb, sizeof(struct userptr_info), 0);
                        if (!bin) {
                                handle = BPF_CORE_READ(arg, handle);
                                DEBUG_PRINTK(
                                        "WARNING: userptr_ioctl failed to reserve in the ringbuffer for handle %u.",
                                        handle);
                                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                                DEBUG_PRINTK("Unconsumed data: %lu", status);
                                dropped_event = 1;
                                return 0;
                        }


                        bin->type = BPF_EVENT_TYPE_USERPTR;
                        bin->file = (u64)file;
                        bin->handle = handle;
                        bin->cpu_addr = cpu_addr;

                        bin->cpu = bpf_get_smp_processor_id();
                        bin->pid = bpf_get_current_pid_tgid() >> 32;
                        bin->tid = bpf_get_current_pid_tgid();
                        bin->time = bpf_ktime_get_ns();


                        DEBUG_PRINTK("userptr cpu_addr=0x%lx handle=%u", cpu_addr, handle);

                        bpf_ringbuf_submit(bin, BPF_RB_FORCE_WAKEUP);
                }
        }

        return 0;
}

/***************************************
* munmap
*
* Some GEMs are mapped, written, and immediately unmapped. For these,
* we need to read and copy them before they are unmapped, and do so
* synchronously with the kernel driver.
***************************************/

SEC("fentry/unmap_region")
int BPF_PROG(unmap_region,
             struct mm_struct *mm,
             struct vm_area_struct *vma, struct vm_area_struct *prev,
             unsigned long start, unsigned long end)
{
        long retval;
        struct i915_mmap_offset *mmo;
        struct fake_offset_pointer foffset = {};
        struct file_handle_pair *val;
        struct unmap_info *bin;
        struct cpu_mapping cmapping = {};
        struct gpu_mapping *gmapping;
        struct gpu_mapping save_gmapping = {};
        u64 fake_offset, size, cpu_addr, status;
        char one = 1;

        mmo = (struct i915_mmap_offset *)BPF_CORE_READ(vma, vm_private_data);
        cpu_addr = BPF_CORE_READ(vma, vm_start);
        size = BPF_CORE_READ(vma, vm_end) - cpu_addr;
        fake_offset = BPF_CORE_READ(mmo, vma_node).vm_node.start << PAGE_SHIFT;

        if (!fake_offset) {
                return 0;
        }

        if (!cpu_addr) {
                return 0;
        }
        foffset.cpu_addr = cpu_addr;
        foffset.fake_offset = fake_offset;
        val = bpf_map_lookup_elem(&mmap_wait_for_unmap, &foffset);
        if (!val) {
                return 0;
        }

        DEBUG_PRINTK("unmap_region cpu_addr=0x%lx size=%lu fake_offset=0x%lx", cpu_addr, size, fake_offset);

        cmapping.size = size;
        cmapping.addr = cpu_addr;

        gmapping = bpf_map_lookup_elem(&cpu_gpu_map, &cmapping);
        save_gmapping.addr = 0;
        save_gmapping.vm_id = 0;
        if (gmapping) {
                save_gmapping.addr = gmapping->addr;
                save_gmapping.vm_id = gmapping->vm_id;
                if (!bpf_map_delete_elem(&gpu_cpu_map, gmapping)) {
                        DEBUG_PRINTK("munmap failed to delete gpu_addr=0x%lx from the gpu_cpu_map!", gmapping->addr);
                }
        }
        gmapping = NULL;
        if (!bpf_map_delete_elem(&cpu_gpu_map, &cmapping)) {
                DEBUG_PRINTK("munmap failed to delete cpu_addr=0x%lx from the cpu_gpu_map!", cpu_addr);
        }

        if (looks_like_batch_buffer((void*)cpu_addr, size)) {
                if (buffer_copy_add((void*)cpu_addr, size)) {
/*                         DEBUG_PRINTK("!!! BB 0 0 0x%lx %u", val->file, val->handle); */

                        /* Reserve some space on the ringbuffer */
                        bin = bpf_ringbuf_reserve(&rb, sizeof(struct unmap_info), 0);
                        if (!bin) {
                                DEBUG_PRINTK(
                                        "WARNING: munmap_tp failed to reserve in the ringbuffer for handle %u.",
                                        val->handle);
                                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                                DEBUG_PRINTK("Unconsumed data: %lu", status);
                                dropped_event = 1;
                                return 0;
                        }

                        bin->type = BPF_EVENT_TYPE_UNMAP;
                        bin->file = val->file;
                        bin->handle = val->handle;
                        bin->cpu_addr = cpu_addr;
                        bin->size = size;

                        bin->cpu = bpf_get_smp_processor_id();
                        bin->pid = bpf_get_current_pid_tgid() >> 32;
                        bin->tid = bpf_get_current_pid_tgid();
                        bin->time = bpf_ktime_get_ns();

                        bpf_ringbuf_submit(bin, BPF_RB_FORCE_WAKEUP);
                }
        }

        return 0;
}
