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
	if (retval < 0)
		return -1;

	return 0;
}

/***************************************
* i915_gem_mmap_ioctl
*
* i915_gem_mmap_ioctl maps an i915 buffer into the CPU's address
* space. From it, we grab a CPU pointer, and place a
* `struct mapping_info` in the ringbuffer.
***************************************/

/* Stores args between the kprobe and kretprobe */
struct mmap_ioctl_wait_for_ret_val {
	struct drm_i915_gem_mmap *arg;
	u64 file;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct mmap_ioctl_wait_for_ret_val);
} mmap_ioctl_wait_for_ret SEC(".maps");

/* Kprobe */
SEC("kprobe/i915_gem_mmap_ioctl")
int mmap_ioctl_kprobe(struct pt_regs *ctx)
{
	struct mmap_ioctl_wait_for_ret_val val;
	u32 cpu, pid;

	/* Pass two arguments to the kretprobe */
	__builtin_memset(&val, 0, sizeof(struct mmap_ioctl_wait_for_ret_val));
	val.arg = (struct drm_i915_gem_mmap *)PT_REGS_PARM2(ctx);
	val.file = PT_REGS_PARM3(ctx);
	cpu = bpf_get_smp_processor_id();

	pid = bpf_get_current_pid_tgid() >> 32;
	/*   bpf_printk("i915_gem_mmap_ioctl pid=%u\n", pid); */

	bpf_map_update_elem(&mmap_ioctl_wait_for_ret, &cpu, &val, 0);

	return 0;
}

/* Kretprobe */
SEC("kretprobe/i915_gem_mmap_ioctl")
int mmap_ioctl_kretprobe(struct pt_regs *ctx)
{
	u32 cpu, handle;
	u64 addr, status;
	int retval;
	void *lookup;
	struct mmap_ioctl_wait_for_ret_val val;
	struct drm_i915_gem_mmap *arg;
	struct mapping_info *info;

	/* Argument from the kprobe */
	cpu = bpf_get_smp_processor_id();
	lookup = bpf_map_lookup_elem(&mmap_ioctl_wait_for_ret, &cpu);
	if (!lookup)
		return -1;
	__builtin_memcpy(&val, lookup,
			 sizeof(struct mmap_ioctl_wait_for_ret_val));

	/* Reserve some space on the ringbuffer */
	info = bpf_ringbuf_reserve(&rb, sizeof(struct mapping_info), 0);
	if (!info) {
		bpf_printk(
			"WARNING: mmap_ioctl_kretprobe failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
		return -1;
	}

	/* mapping specific values */
	arg = val.arg;
	handle = BPF_CORE_READ(arg, handle);
	addr = BPF_CORE_READ(arg, addr_ptr);
	info->file = val.file;
	info->handle = handle;
	info->cpu_addr = addr;
	info->size = BPF_CORE_READ(arg, size);
	info->offset = BPF_CORE_READ(arg, offset);

	info->cpu = bpf_get_smp_processor_id();
	info->pid = bpf_get_current_pid_tgid() >> 32;
	info->tid = bpf_get_current_pid_tgid();
	info->stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	info->time = bpf_ktime_get_ns();

	bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

	mmap_wait_for_unmap_insert(val.file, handle, addr);

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
struct mmap_wait_for_ret_val {
	struct vm_area_struct *vma;
};
struct mmap_offset_wait_for_ret_val {
	struct drm_i915_gem_mmap_offset *arg;
	u64 file;
};
struct mmap_offset_wait_for_mmap_val {
	u64 file;
	u32 handle;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct mmap_offset_wait_for_ret_val);
} mmap_offset_wait_for_ret SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct mmap_offset_wait_for_mmap_val);
} mmap_offset_wait_for_mmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct mmap_wait_for_ret_val);
} mmap_wait_for_ret SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct file_handle_pair);
        __type(value, u64);
} file_handle_mapping SEC(".maps");

/* Capture any pointers that userspace has mmap'd. */
SEC("kprobe/i915_gem_mmap_offset_ioctl")
int mmap_offset_ioctl_kprobe(struct pt_regs *ctx)
{
	struct mmap_offset_wait_for_ret_val val;

	__builtin_memset(&val, 0, sizeof(struct mmap_offset_wait_for_ret_val));
	val.arg = (struct drm_i915_gem_mmap_offset *)PT_REGS_PARM2(ctx);
	val.file = PT_REGS_PARM3(ctx);
	u32 cpu = bpf_get_smp_processor_id();
	bpf_map_update_elem(&mmap_offset_wait_for_ret, &cpu, &val, 0);

	/* DEBUG */
	/*   bpf_printk("mmap_offset_ioctl_kprobe on cpu %u", cpu); */

	return 0;
}

/* We have to wait for this function to return to read its address */
SEC("kretprobe/i915_gem_mmap_offset_ioctl")
int mmap_offset_ioctl_kretprobe(struct pt_regs *ctx)
{
	u32 cpu, handle;
	u64 file, fake_offset;
	void *lookup;
	struct mmap_offset_wait_for_ret_val val;
	struct mmap_offset_wait_for_mmap_val mmap_val;
	struct drm_i915_gem_mmap_offset *arg;

	/* First, see if we've got the element from when this call first started */
	cpu = bpf_get_smp_processor_id();
	lookup = bpf_map_lookup_elem(&mmap_offset_wait_for_ret, &cpu);
	if (!lookup)
		return -1;
	__builtin_memcpy(&val, lookup,
			 sizeof(struct mmap_offset_wait_for_ret_val));

	/* At this point, this pointer to a drm_i915_gem_mmap_offset contains a handle
           and a fake offset. Let's store them and read them when the mmap actually happens. */
	arg = val.arg;
	file = val.file;
	fake_offset = BPF_CORE_READ(arg, offset);
	handle = BPF_CORE_READ(arg, handle);

	__builtin_memset(&mmap_val, 0,
			 sizeof(struct mmap_offset_wait_for_mmap_val));
	mmap_val.file = file;
	mmap_val.handle = handle;
	bpf_map_update_elem(&mmap_offset_wait_for_mmap, &fake_offset, &mmap_val,
			    0);

	/* DEBUG */
	/*   bpf_printk("mmap_offset_ioctl_kretprobe fake_offset=0x%lx file=0x%lx handle=%u", fake_offset, file, handle); */
	/*   bpf_printk("pid=%u", bpf_get_current_pid_tgid() >> 32); */

	return 0;
}

/* NOTE: This is NOT the same as i915_gem_mmap_ioctl.
   At this point we've seen the i915_gem_mmap_offset_ioctl call for this GEM, from
   which we extracted the handle and the fake offset. Let's use the offset as a key,
   and from i915_gem_mmap get the virtual address of the mapping. */
SEC("kprobe/i915_gem_mmap")
int mmap_kprobe(struct pt_regs *ctx)
{
	u32 cpu;
	struct mmap_wait_for_ret_val val;
	struct vm_area_struct *vma;

	/* We're just going to immediately send this to the kretprobe */
	__builtin_memset(&val, 0, sizeof(struct mmap_wait_for_ret_val));
	cpu = bpf_get_smp_processor_id();
	vma = (struct vm_area_struct *)PT_REGS_PARM2(ctx);
	val.vma = vma;
	bpf_map_update_elem(&mmap_wait_for_ret, &cpu, &val, 0);

	/* DEBUG */
	/*   bpf_printk("mmap_kprobe vma=0x%llx", vma); */

	return 0;
}

SEC("kretprobe/i915_gem_mmap")
int mmap_kretprobe(struct pt_regs *ctx)
{
	int retval;
	u32 cpu, page_shift;
	u64 vm_pgoff, vm_start, vm_end, status;
	void *lookup;
	struct mmap_wait_for_ret_val val;
	struct mmap_offset_wait_for_mmap_val offset_val;
	struct vm_area_struct *vma;
	struct mapping_info *info;
        struct file_handle_pair pair = {};

	/* Get the vma from the kprobe */
	cpu = bpf_get_smp_processor_id();
	lookup = bpf_map_lookup_elem(&mmap_wait_for_ret, &cpu);
	if (!lookup)
		return -1;
	__builtin_memcpy(&val, lookup, sizeof(struct mmap_wait_for_ret_val));

	page_shift = 12;
	vma = val.vma;
	vm_pgoff = BPF_CORE_READ(vma, vm_pgoff);
	vm_start = BPF_CORE_READ(vma, vm_start);
	vm_end = BPF_CORE_READ(vma, vm_end);
	vm_pgoff = vm_pgoff << page_shift;

	/* Get the handle from the previous i915_gem_mmap_offset_ioctl call. */
	lookup = bpf_map_lookup_elem(&mmap_offset_wait_for_mmap, &vm_pgoff);
	if (!lookup)
		return -1;
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
		return -1;
	}

	/* mapping specific values */
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

struct userptr_ioctl_wait_for_ret_val {
	struct drm_i915_gem_userptr *arg;
	u64 file;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct userptr_ioctl_wait_for_ret_val);
} userptr_ioctl_wait_for_ret SEC(".maps");

SEC("kprobe/i915_gem_userptr_ioctl")
int userptr_ioctl_kprobe(struct pt_regs *ctx)
{
	u32 cpu;
	struct userptr_ioctl_wait_for_ret_val val;

	cpu = bpf_get_smp_processor_id();
	__builtin_memset(&val, 0,
			 sizeof(struct userptr_ioctl_wait_for_ret_val));
	val.arg = (struct drm_i915_gem_userptr *)PT_REGS_PARM2(ctx);
	val.file = PT_REGS_PARM3(ctx);
	bpf_map_update_elem(&userptr_ioctl_wait_for_ret, &cpu, &val, 0);

	return 0;
}

SEC("kretprobe/i915_gem_userptr_ioctl")
int userptr_ioctl_kretprobe(struct pt_regs *ctx)
{
	int err;
	u32 cpu;
	u64 size, status;
        unsigned handle;
	struct drm_i915_gem_userptr *arg;
	void *lookup;
	struct userptr_info *bin;
	struct userptr_ioctl_wait_for_ret_val val;

	/* Get the pointer to the arguments from the kprobe */
	cpu = bpf_get_smp_processor_id();
	lookup = bpf_map_lookup_elem(&userptr_ioctl_wait_for_ret, &cpu);
	if (!lookup)
		return 1;
	__builtin_memcpy(&val, lookup,
			 sizeof(struct userptr_ioctl_wait_for_ret_val));
	arg = val.arg;

	/* Reserve some space on the ringbuffer */
	bin = bpf_ringbuf_reserve(&rb, sizeof(struct userptr_info), 0);
	if (!bin) {
                handle = BPF_CORE_READ(arg, handle);
		bpf_printk(
			"WARNING: userptr_ioctl failed to reserve in the ringbuffer for handle %u.", handle);
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
		return -1;
	}

	bin->file = val.file;
	bin->handle = BPF_CORE_READ(arg, handle);
	bin->cpu_addr = BPF_CORE_READ(arg, user_ptr);
	bin->size = BPF_CORE_READ(arg, user_size);

	bin->cpu = bpf_get_smp_processor_id();
	bin->pid = bpf_get_current_pid_tgid() >> 32;
	bin->tid = bpf_get_current_pid_tgid();
	bin->time = bpf_ktime_get_ns();

	size = bin->size;
	if (size > MAX_BINARY_SIZE) {
		size = MAX_BINARY_SIZE;
	}
	err = bpf_probe_read_user(bin->buff, size, (void *)bin->cpu_addr);
	if (err) {
		bpf_ringbuf_discard(bin, BPF_RB_FORCE_WAKEUP);
		bpf_printk("WARNING: userptr_ioctl failed to copy %lu bytes.",
			   size);
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
		return -1;
	}
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
	int err;
	u64 size;
	struct vm_area_struct *vma;

	/* For checking */
	struct file_handle_pair *val;
	u64 addr, status;

	/* For sending to execbuffer */
	int zero = 0;
	struct unmap_info *bin;

	/* First, make sure this is an i915 buffer */
	addr = ctx->args[0];
	if (!addr) {
		return -1;
	}
	val = bpf_map_lookup_elem(&mmap_wait_for_unmap, &addr);
	if (!val) {
		return -1;
	}

	/* Reserve some space on the ringbuffer */
	bin = bpf_ringbuf_reserve(&rb, sizeof(struct unmap_info), 0);
	if (!bin) {
		bpf_printk(
			"WARNING: munmap_tp failed to reserve in the ringbuffer for handle %u.", val->handle);
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
		return -1;
	}

	bin->file = val->file;
	bin->handle = val->handle;
	bin->cpu_addr = addr;
	bin->size = ctx->args[1];

	bin->cpu = bpf_get_smp_processor_id();
	bin->pid = bpf_get_current_pid_tgid() >> 32;
	bin->tid = bpf_get_current_pid_tgid();
	bin->time = bpf_ktime_get_ns();

	size = bin->size;
	if (size > MAX_BINARY_SIZE) {
		size = MAX_BINARY_SIZE;
	}
	err = bpf_probe_read_user(bin->buff, size, (void *)bin->cpu_addr);
	if (err) {
		bpf_ringbuf_discard(bin, BPF_RB_FORCE_WAKEUP);
		bpf_printk(
			"WARNING: munmap_tp failed to copy %lu bytes from cpu_addr=0x%lx.",
			size, addr);
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
		return -1;
	}
	bpf_ringbuf_submit(bin, BPF_RB_FORCE_WAKEUP);

	return 0;
}

#if 0
/***************************************
* i915_gem_pwrite_ioctl
*
* The i915_gem_pwrite_ioctl system call includes a userspace pointer
* from which the kernel should read, so we can immediately pass that along
* to our userspace profiler to be read.
***************************************/

SEC("kprobe/i915_gem_pwrite_ioctl")
int pwrite_kprobe(struct pt_regs *ctx)
{
  struct drm_i915_gem_pwrite *gem_pwrite = (struct drm_i915_gem_pwrite *) PT_REGS_PARM2(ctx);
  struct mapping_info *kinfo;
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  
  add_to_ringbuf(pid,
                 BPF_CORE_READ(gem_pwrite, handle),
                 BPF_CORE_READ(gem_pwrite, data_ptr),
                 BPF_CORE_READ(gem_pwrite, size),
                 0,
                 0);
  
  return 0;
}
#endif
