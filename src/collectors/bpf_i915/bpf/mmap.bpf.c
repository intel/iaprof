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

struct file_handle_pair {
        u64 file;
        u32 handle;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u64);
        __type(value, struct file_handle_pair);
} mmap_wait_for_unmap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct file_handle_pair);
        __type(value, u64);
} file_handle_mapping SEC(".maps");

int mmap_wait_for_unmap_insert(u64 file, u32 handle, u64 addr_arg)
{
        struct file_handle_pair unmap_val;
        int retval;
        u64 addr;

        /* We also want to let munmap calls do a lookup with the address */
        __builtin_memset(&unmap_val, 0, sizeof(struct file_handle_pair));
        unmap_val.file = file;
        unmap_val.handle = handle;
        addr = addr_arg;
        retval =
                bpf_map_update_elem(&mmap_wait_for_unmap, &addr, &unmap_val, 0);
        if (retval < 0) {
                bpf_printk("mmap_wait_for_unmap_insert failed file=%p handle=%u cpu_addr=0x%lx",
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

        bpf_printk("mmap cpu_addr=0x%lx handle=%u\n", addr, handle);

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

        bpf_printk("mmap_offset_ioctl_kretprobe fake_offset=0x%lx file=0x%lx handle=%u", fake_offset, file, handle);

        return 0;
}

SEC("fexit/i915_gem_mmap")
int BPF_PROG(i915_gem_mmap,
             struct file *filp,
             struct vm_area_struct *vma)
{
        int retval;
        u32 cpu, page_shift;
        u64 vm_pgoff, vm_start, vm_end, status;
        void *lookup;
        struct mmap_offset_wait_for_mmap_val offset_val;
        struct mapping_info *info;
        struct file_handle_pair pair = {};

        page_shift = 12;
        vm_pgoff = BPF_CORE_READ(vma, vm_pgoff);
        vm_start = BPF_CORE_READ(vma, vm_start);
        vm_end = BPF_CORE_READ(vma, vm_end);
        vm_pgoff = vm_pgoff << page_shift;

        /* Get the handle from the previous i915_gem_mmap_offset_ioctl call. */
        lookup = bpf_map_lookup_elem(&mmap_offset_wait_for_mmap, &vm_pgoff);
        if (!lookup) {
                bpf_printk("i915_gem_mmap failed to see mmap_offset on vm_pgoff=0x%lx",
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
                bpf_printk(
                        "WARNING: mmap_ioctl_kretprobe failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
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

        bpf_printk("i915_gem_mmap cpu_addr=0x%lx handle=%u", vm_start, offset_val.handle);

        mmap_wait_for_unmap_insert(offset_val.file, offset_val.handle,
                                   vm_start);

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

        arg = (struct drm_i915_gem_userptr *)data;

        /* Reserve some space on the ringbuffer */
        bin = bpf_ringbuf_reserve(&rb, sizeof(struct userptr_info), 0);
        if (!bin) {
                handle = BPF_CORE_READ(arg, handle);
                bpf_printk(
                        "WARNING: userptr_ioctl failed to reserve in the ringbuffer for handle %u.",
                        handle);
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return 0;
        }

        cpu_addr = BPF_CORE_READ(arg, user_ptr);
        handle = BPF_CORE_READ(arg, handle);

        bin->type = BPF_EVENT_TYPE_USERPTR;
        bin->file = (u64)file;
        bin->handle = handle;
        bin->cpu_addr = cpu_addr;

        bin->cpu = bpf_get_smp_processor_id();
        bin->pid = bpf_get_current_pid_tgid() >> 32;
        bin->tid = bpf_get_current_pid_tgid();
        bin->time = bpf_ktime_get_ns();

        size = BPF_CORE_READ(arg, user_size);
        buffer_copy_circular_array_add((void*)cpu_addr, size);

        bpf_printk("userptr cpu_addr=0x%lx handle=%u", cpu_addr, handle);

        bpf_ringbuf_submit(bin, BPF_RB_FORCE_WAKEUP);

        return 0;
}

/***************************************
* munmap
*
* Some GEMs are mapped, written, and immediately unmapped. For these,
* we need to read and copy them before they are unmapped, and do so
* synchronously with the kernel driver.
***************************************/

SEC("tracepoint/syscalls/sys_enter_munmap")
int munmap_tp(struct trace_event_raw_sys_enter *ctx)
{
        long retval;
        u64 size;
        struct vm_area_struct *vma;

        /* For checking */
        struct file_handle_pair *val;
        u64 addr, status;

        /* For sending to execbuffer */
        int zero = 0;
        struct unmap_info *bin;

        struct cpu_mapping cmapping = {};
        struct gpu_mapping *gmapping;

        /* First, make sure this is an i915 buffer */
        addr = ctx->args[0];
        size = ctx->args[1];
        if (!addr) {
                return -1;
        }
        val = bpf_map_lookup_elem(&mmap_wait_for_unmap, &addr);
        if (!val) {
                return -1;
        }

        cmapping.size = size;
        cmapping.addr = addr;
        gmapping = bpf_map_lookup_elem(&cpu_gpu_map, &cmapping);
        if (gmapping) {
                if (!bpf_map_delete_elem(&gpu_cpu_map, gmapping)) {
                        bpf_printk("munmap failed to delete gpu_addr=0x%lx from the gpu_cpu_map!", gmapping->addr);
                }
        }
        gmapping = NULL;
        if (!bpf_map_delete_elem(&cpu_gpu_map, &cmapping)) {
                bpf_printk("munmap failed to delete cpu_addr=0x%lx from the cpu_gpu_map!", addr);
        }

        /* Reserve some space on the ringbuffer */
        bin = bpf_ringbuf_reserve(&rb, sizeof(struct unmap_info), 0);
        if (!bin) {
                bpf_printk(
                        "WARNING: munmap_tp failed to reserve in the ringbuffer for handle %u.",
                        val->handle);
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return -1;
        }

        bin->type = BPF_EVENT_TYPE_UNMAP;
        bin->file = val->file;
        bin->handle = val->handle;
        bin->cpu_addr = addr;
        bin->size = size;

        bin->cpu = bpf_get_smp_processor_id();
        bin->pid = bpf_get_current_pid_tgid() >> 32;
        bin->tid = bpf_get_current_pid_tgid();
        bin->time = bpf_ktime_get_ns();

        buffer_copy_circular_array_add((void*)addr, size);

        bpf_ringbuf_submit(bin, BPF_RB_FORCE_WAKEUP);

        return 0;
}
