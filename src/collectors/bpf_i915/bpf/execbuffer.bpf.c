/***************************************
* EXECBUFFER
* **********
* We need to keep track of which requests are being
* executed, so trace execbuffer calls and send those
* back to userspace.
***************************************/

#include "i915.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

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
	bpf_ringbuf_submit(einfo, BPF_RB_FORCE_WAKEUP);

	return 0;
}
