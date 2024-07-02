/***************************************
* i915 GEM Tracer
* 
* The purpose of this eBPF program is to trace, and send to userspace,
* all GEMs that are associated with an executing batchbuffer in the i915
* driver.  This includes at a minimum the virtual address and size of the
* buffer.
* 
* This program works by tracing a set of functions on the memory management
* side (functions which are used to create, allocate, bind, and/or write to
* buffers). Each of these callpaths eventually culminates in a virtual
* address and size of a buffer which userspace wants to send to the GPU.
* Once collected, we have no way of knowing if these buffers have actually
* been written to. So, we simply wait until they're referred to by an
* executing batchbuffer.
*
* Memory management is largely a matter of calling some mmap-like interface
* to get an integer ID for the buffer, then later passing it to a call to
* i915_gem_execbuffer2_ioctl. For discrete devices (like Ponte Vecchio),
* this is supplemented by maintaining a separate virtual address space
* (called a VM) using i915_gem_vm_bind_ioctl.
*
* From each function, we get:
*
* 1. i915_gem_mmap_ioctl
*    - handle ID
*    - CPU address
*    - size
*
* 2. i915_gem_mmap_offset_ioctl
*    - handle ID
*    - file offset (later passed to i915_gem_mmap_ioctl)
*
* 3. i915_gem_pwrite_ioctl
*    - handle ID
*    - CPU address
*    - size
*
* 4. i915_gem_userptr_ioctl
*    - handle ID
*    - CPU address
*    - size
*
* For discrete devices, we also trace:
* 
* 1. i915_gem_vm_bind_ioctl
*    - handle ID
*    - GPU address
*    - size
*    - VM ID
*
* 2. i915_gem_context_create_ioctl
*    - Context ID
*    - VM ID
***************************************/

#include "i915.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "gem_collector.h"

/***************************************
* HACKY DECLARATIONS
*
* These are definitions of macros that aren't available from the BTF
* dump of the i915 module; for example, those that are defined inside
* structs. Many of these *are* included in the regular uapi headers,
* but including those alongside BPF skeleton headers causes a host of
* compile errors, so this is the path of least resistance.
***************************************/

#define MAX_ENGINE_INSTANCE 8
#define I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS (1u << 0)
#define I915_CONTEXT_CREATE_EXT_SETPARAM 0
#define I915_CONTEXT_PARAM_VM 0x9

/***************************************
* OUTPUT MAP
*
* This is the "output" map, which userspace reads to get information
* about GPU kernels running on the system.
***************************************/

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, 5000);
} stackmap SEC(".maps");

/***************************************
* GPU->CPU Map
*
* This map uses `i915_gem_mmap_ioctl`, `i915_gem_mmap_offset_ioctl`, `i915_gem_mmap`
* to maintain a map of GPU addresses to CPU ones. We then copy buffers out of the CPU
* addresses when an execbuffer call is made.
***************************************/
struct cpu_mapping {
        u64 addr;
        u64 size;
};
struct gpu_mapping {
        u64 addr;
        u32 vm_id;
};
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct gpu_mapping);
        __type(value, struct cpu_mapping);
} gpu_cpu_map SEC(".maps");

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
* i915_gem_context_create_ioctl
*
* Look for gem contexts getting created, in order to see the association
* between VM ID and context ID.
***************************************/

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} context_create_wait_for_ret SEC(".maps");

/* The struct that execbuffer will use to lookup VM IDs */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u32);
} context_create_wait_for_exec SEC(".maps");

SEC("kprobe/i915_gem_context_create_ioctl")
int context_create_ioctl_kprobe(struct pt_regs *ctx)
{
	u64 arg = (u64)PT_REGS_PARM2(ctx);
	u32 cpu = bpf_get_smp_processor_id();

	bpf_map_update_elem(&context_create_wait_for_ret, &cpu, &arg, 0);

	return 0;
}

SEC("kretprobe/i915_gem_context_create_ioctl")
int context_create_ioctl_kretprobe(struct pt_regs *ctx)
{
	u32 cpu, i, ctx_id, vm_id, name;
	u64 param;
	void *arg;
	struct drm_i915_gem_context_create_ext *create_ext;
	struct i915_user_extension *ext;
	struct drm_i915_gem_context_create_ext_setparam *setparam_ext;

	/* Get the pointer to the arguments from the kprobe */
	cpu = bpf_get_smp_processor_id();
	arg = bpf_map_lookup_elem(&context_create_wait_for_ret, &cpu);
	if (!arg) {
		return 1;
	}

	/* Look for CONTEXT_CREATE extensions */
	create_ext = *((struct drm_i915_gem_context_create_ext **)arg);
	ctx_id = BPF_CORE_READ(create_ext, ctx_id);

	if (BPF_CORE_READ(create_ext, flags) &
	    I915_CONTEXT_CREATE_FLAGS_USE_EXTENSIONS) {
		ext = (struct i915_user_extension *)BPF_CORE_READ(create_ext,
								  extensions);

#pragma clang loop unroll(full)
		for (i = 0; i < 64; i++) {
			if (!ext)
				break;

			name = BPF_CORE_READ_USER(ext, name);
			if (name == I915_CONTEXT_CREATE_EXT_SETPARAM) {
				setparam_ext =
					(struct drm_i915_gem_context_create_ext_setparam
						 *)ext;
				param = BPF_CORE_READ_USER(setparam_ext, param)
						.param;
				if (param == I915_CONTEXT_PARAM_VM) {
					/* Someone is trying to set the VM for this context, let's store it */
					vm_id = BPF_CORE_READ_USER(setparam_ext,
								   param)
							.value;
					/*           bpf_printk("context_create_ioctl ctx_id=%u vm_id=%u", ctx_id, vm_id); */
					bpf_map_update_elem(
						&context_create_wait_for_exec,
						&ctx_id, &vm_id, 0);
				}
			}

			ext = (struct i915_user_extension *)BPF_CORE_READ_USER(
				ext, next_extension);
		}
	}

	return 0;
}

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

/* 	bpf_printk("vm_bind kprobe handle=%u gpu_addr=0x%lx", BPF_CORE_READ(arg, handle), BPF_CORE_READ(arg, start)); */

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

        /* For getting the cpu_addr */
        u64 cpu_addr, gpu_addr;
        struct file_handle_pair pair = {};
        struct cpu_mapping cmapping = {};
        struct gpu_mapping gmapping = {};

	/* Grab the argument from the kprobe */
	cpu = bpf_get_smp_processor_id();
	lookup = bpf_map_lookup_elem(&vm_bind_ioctl_wait_for_ret, &cpu);
	if (!lookup)
		return -1;
	__builtin_memcpy(&val, lookup,
			 sizeof(struct vm_bind_ioctl_wait_for_ret_val));
	arg = val.arg;

        /* Get the CPU address from any mappings that have happened */
        handle = BPF_CORE_READ(arg, handle);
        pair.handle = handle;
        pair.file = val.file;
        lookup = bpf_map_lookup_elem(&file_handle_mapping, &pair);
        if (!lookup)
                return -1;
        cpu_addr = *((u64 *)lookup);
        
        /* Maintain a map of GPU->CPU addrs */
        size = BPF_CORE_READ(arg, length);
        gpu_addr = BPF_CORE_READ(arg, start);
        if (size && gpu_addr) {
                vm_id = BPF_CORE_READ(arg, vm_id);
                cmapping.size = size;
                cmapping.addr = cpu_addr;
                gmapping.addr = gpu_addr;
                gmapping.vm_id = vm_id;
        	bpf_map_update_elem(&gpu_cpu_map, &gmapping, &cmapping, 0);
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

	info->cpu = bpf_get_smp_processor_id();
	info->pid = bpf_get_current_pid_tgid() >> 32;
	info->tid = bpf_get_current_pid_tgid();
	info->stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	info->time = bpf_ktime_get_ns();

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
	u64 file, status;

	arg = (struct prelim_drm_i915_gem_vm_bind *)PT_REGS_PARM2(ctx);
	file = PT_REGS_PARM3(ctx);

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
	info->vm_id = BPF_CORE_READ(arg, vm_id);
	info->gpu_addr = BPF_CORE_READ(arg, start);
	info->size = BPF_CORE_READ(arg, length);
	info->offset = BPF_CORE_READ(arg, offset);

	info->cpu = bpf_get_smp_processor_id();
	info->pid = bpf_get_current_pid_tgid() >> 32;
	info->tid = bpf_get_current_pid_tgid();
	info->time = bpf_ktime_get_ns();

	bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

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

/***************************************
* i915_gem_do_execbuffer
*
* Now we've got a map of GEM handles that have been mmap'd. Look through the
* GEM handles that are going to be executed, and send them to userspace.
***************************************/

struct execbuffer_wait_for_ret_val {
	u64 file;
	u64 execbuffer;
	u64 objects;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct execbuffer_wait_for_ret_val);
} execbuffer_wait_for_ret SEC(".maps");

struct vm_callback_ctx {
        u32 vm_id;
        u64 bits_to_match, bb_addr;
};

static long vm_callback(struct bpf_map *map, struct gpu_mapping *gmapping,
                        struct cpu_mapping *cmapping, struct vm_callback_ctx *ctx)
{
        int err;
        struct batchbuffer_info *info = NULL;
        u64 status, size;
        
        /*
           We only care about this buffer if it:
           1. Has the same vm_id as the batchbuffer for this execbuffer call.
           2. Has the same upper bits as the batchbuffer in this execbuffer call.
        */
        if ((gmapping->vm_id != ctx->vm_id) ||
            ((gmapping->addr & ctx->bits_to_match) != ctx->bits_to_match) ||
            (gmapping->addr == ctx->bb_addr)) {
                return 0;
        }
	info = bpf_ringbuf_reserve(&rb, sizeof(struct batchbuffer_info), 0);
	if (!info) {
		bpf_printk(
			"WARNING: vm_callback failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
		return 1;
        }
        
        /* Common stuff */
	info->cpu = bpf_get_smp_processor_id();
	info->pid = bpf_get_current_pid_tgid() >> 32;
	info->tid = bpf_get_current_pid_tgid();
	info->time = bpf_ktime_get_ns();

        info->gpu_addr = gmapping->addr;
        info->vm_id = ctx->vm_id;

	size = cmapping->size;
	if (size > MAX_BINARY_SIZE) {
		size = MAX_BINARY_SIZE;
	}
	err = bpf_probe_read_user(info->buff, size, (void *) cmapping->addr);
        info->buff_sz = size;
	if (err) {
		bpf_printk(
			"WARNING: vm_callback failed to copy %lu bytes.",
			size);
                info->buff_sz = 0;
	}
	bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
        bpf_printk("batchbuffer %u 0x%lx %lu", ctx->vm_id, gmapping->addr, cmapping->size);
        return 0;
}

SEC("kprobe/i915_gem_do_execbuffer")
int do_execbuffer_kprobe(struct pt_regs *ctx)
{
        int err;
	struct execbuffer_wait_for_ret_val val;
	u32 cpu, ctx_id, vm_id, handle, batch_index, batch_start_offset,
            buffer_count;
	u64 file, cpu_addr, batch_len, offset, size, status;
	struct execbuf_start_info *info;
	struct drm_i915_gem_execbuffer2 *execbuffer;
	struct drm_i915_gem_exec_object2 *objects;
	void *val_ptr;
        struct cpu_mapping cmapping = {};
        struct gpu_mapping gmapping = {};
        struct vm_callback_ctx vm_callback_ctx = {};

	/* Read arguments */
	file = (u64)PT_REGS_PARM2(ctx);
	execbuffer = (struct drm_i915_gem_execbuffer2 *)PT_REGS_PARM3(ctx);
	objects = (struct drm_i915_gem_exec_object2 *)PT_REGS_PARM4(ctx);

	/* Pass arguments to the kretprobe */
	__builtin_memset(&val, 0, sizeof(struct execbuffer_wait_for_ret_val));
	val.file = file;
	val.execbuffer = (u64)execbuffer;
	val.objects = (u64)objects;
	cpu = bpf_get_smp_processor_id();
	bpf_map_update_elem(&execbuffer_wait_for_ret, &cpu, &val, 0);

	/* Look up the VM ID based on the context ID (which is in execbuffer->rsvd1) */
	if (!execbuffer) {
		return -1;
	}
	ctx_id = (u32)BPF_CORE_READ(execbuffer, rsvd1);
	vm_id = 0;
	if (ctx_id) {
		val_ptr = bpf_map_lookup_elem(&context_create_wait_for_exec,
					      &ctx_id);
		if (val_ptr) {
			vm_id = *((u32 *)val_ptr);
		}
	}

        /* Determine where the batchbuffer is stored (and how long it is).
           The index that it's in is determined by a flag -- it can either
           be the first or the last batch. */
        batch_index =
                (BPF_CORE_READ(execbuffer, flags) & I915_EXEC_BATCH_FIRST) ?
                0 : BPF_CORE_READ(execbuffer, buffer_count) - 1;
        batch_start_offset = BPF_CORE_READ(execbuffer, batch_start_offset);
        batch_len = BPF_CORE_READ(execbuffer, batch_len);
        buffer_count = BPF_CORE_READ(execbuffer, buffer_count);
        if (batch_index == 0) {
                /* If the index is 0 (the vast majority of the time it is), we can
                   just directly read the `objects` pointer. */
                handle = BPF_CORE_READ(objects, handle);
                offset = BPF_CORE_READ(objects, offset);
        } else {
                handle = 0xffffffff;
                offset = 0xffffffffffffffff;
        }
        
        /* Now iterate over all buffers in the same VM as the batchbuffer */
        vm_callback_ctx.vm_id = vm_id;
        vm_callback_ctx.bits_to_match = offset & 0xffffffffff000000;
        vm_callback_ctx.bb_addr = offset;
        if (bpf_for_each_map_elem(&gpu_cpu_map, vm_callback, &vm_callback_ctx, 0) < 0) {
                bpf_printk("ERROR in vm_callback");
                return -1;
        }

	/* Reserve some space on the ringbuffer, into which we can copy things */
	info = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_start_info), 0);
	if (!info) {
		bpf_printk(
			"WARNING: execbuffer failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
		return -1;
        }

        /* Find a possible CPU mapping for the primary batchbuffer.
           If we can, go ahead and grab a copy of it! */
        gmapping.vm_id = vm_id;
        gmapping.addr = offset;
        val_ptr = bpf_map_lookup_elem(&gpu_cpu_map, &gmapping);
        if (val_ptr) {
        	__builtin_memcpy(&cmapping, val_ptr,
        			 sizeof(struct cpu_mapping));
        	size = cmapping.size;
        	if (size > MAX_BINARY_SIZE) {
        		size = MAX_BINARY_SIZE;
        	}
        	err = bpf_probe_read_user(info->buff, size, (void *) cmapping.addr);
                info->buff_sz = size;
        	if (err) {
        		bpf_printk(
        			"WARNING: execbuffer failed to copy %lu bytes.",
        			size);
                        info->buff_sz = 0;
        	}
                bpf_printk("execbuffer batchbuffer 0x%lx %lu", cmapping.addr, cmapping.size);
        } else {
                info->buff_sz = 0;
        }
        
	/* execbuffer-specific stuff */
	info->file = file;
	info->vm_id = vm_id;
	info->ctx_id = ctx_id;
	info->batch_start_offset = batch_start_offset;
        info->batch_len = BPF_CORE_READ(execbuffer, batch_len);
        info->bb_offset = offset;

	info->cpu = cpu;
	info->pid = bpf_get_current_pid_tgid() >> 32;
	info->tid = bpf_get_current_pid_tgid();
	info->stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	info->time = bpf_ktime_get_ns();
	bpf_get_current_comm(info->name, sizeof(info->name));
	bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

	return 0;
}

SEC("kretprobe/i915_gem_do_execbuffer")
int do_execbuffer_kretprobe(struct pt_regs *ctx)
{
	struct execbuf_end_info *einfo;
	struct execbuffer_wait_for_ret_val *val;
        struct drm_i915_gem_exec_object2 *objects;
	u32 cpu;

	cpu = bpf_get_smp_processor_id();
	void *arg = bpf_map_lookup_elem(&execbuffer_wait_for_ret, &cpu);
	if (!arg) {
		return -1;
	}
	val = (struct execbuffer_wait_for_ret_val *)arg;
        objects = (struct drm_i915_gem_exec_object2 *)val->objects;
        
	/* Output the end of an execbuffer to the ringbuffer */
	einfo = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_end_info), 0);
	if (!einfo)
		return -1;
	einfo->cpu = cpu;
	einfo->pid = bpf_get_current_pid_tgid() >> 32;
	einfo->tid = bpf_get_current_pid_tgid();
	einfo->time = bpf_ktime_get_ns();
        einfo->bb_handle = BPF_CORE_READ(objects, handle);
	bpf_ringbuf_submit(einfo, BPF_RB_FORCE_WAKEUP);

	return 0;
}

/***************************************
* i915_debugger_uuid_create
*
* With debugging features enabled in the driver, the Compute Runtime
* library will send an ELF binary (called a Zebin) of the GPU program
* to the kernel driver. This results in a call to i915_debugger_uuid_create,
* which we can trace here to intercept that ELF binary (which may
* contain debug data).
***************************************/

#if 0
SEC("kprobe/i915_debugger_uuid_create")
int uuid_create_kprobe(struct pt_regs *ctx)
{
        struct i915_uuid_resource *resource;
	struct uuid_create_info *bin;
        u64 size, status;
	int err;

	resource = (struct i915_uuid_resource *) PT_REGS_PARM2(ctx);
	if (!resource) {
		return -1;
	}

	/* Reserve some space on the ringbuffer */
	bin = bpf_ringbuf_reserve(&rb, sizeof(struct uuid_create_info), 0);
	if (!bin) {
		bpf_printk(
			"WARNING: uuid_create failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
		return -1;
	}

	bin->size = BPF_CORE_READ(resource, size);
        bin->cpu_addr = (__u64) BPF_CORE_READ(resource, ptr);
	bin->handle = BPF_CORE_READ(resource, handle);

	bin->cpu = bpf_get_smp_processor_id();
	bin->pid = bpf_get_current_pid_tgid() >> 32;
	bin->tid = bpf_get_current_pid_tgid();
	bin->time = bpf_ktime_get_ns();

/*         bpf_printk("uuid_create size=%llu cpu_addr=0x%lx handle=%u\n", bin->size, bin->cpu_addr, bin->handle); */

/*
	size = bin->size;
	if (size > MAX_BINARY_SIZE) {
		size = MAX_BINARY_SIZE;
	}
	err = bpf_probe_read_user(bin->buff, size, (void *) bin->cpu_addr);
	if (err) {
		bpf_ringbuf_discard(bin, 0);
		bpf_printk(
			"WARNING: uuid_create failed to copy %lu bytes.",
			size);
		return -1;
	}
*/
	bpf_ringbuf_submit(bin, BPF_RB_FORCE_WAKEUP);

	return 0;
}
#endif

char LICENSE[] SEC("license") = "GPL";

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
