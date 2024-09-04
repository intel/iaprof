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

struct vm_callback_ctx {
        u32 vm_id;
        u64 bits_to_match, bb_addr;
        int stackid;
};

static long vm_callback(struct bpf_map *map, struct cpu_mapping *cmapping,
                        struct gpu_mapping *gmapping,
                        struct vm_callback_ctx *ctx)
{
        int err;
        struct batchbuffer_info *info = NULL;
        u64 status, size, addr;
        unsigned char buff[8];

        /*
           We only care about this buffer if it:
           1. Has the same vm_id as the batchbuffer for this execbuffer call.
           2. Isn't the primary batchbuffer (which we're copying elsewhere)
        */
        if (gmapping->vm_id != ctx->vm_id) {
                bpf_printk("vm_callback filtering by vm_id vm_id=%u gpu_addr=0x%lx",
                           gmapping->vm_id, gmapping->addr);
                return 0;
        }
        if (gmapping->addr == ctx->bb_addr) {
                bpf_printk("vm_callback filtering by bb_addr vm_id=%u gpu_addr=0x%lx",
                           gmapping->vm_id, gmapping->addr);
                return 0;
        }

        /* Look at the CPU mapping */
        addr = cmapping->addr;
        size = cmapping->size;

        /* Make a copy of the first 8 bytes, read them to see what the buffer type is */
        bpf_probe_read_user(buff, 8, (void *)addr);
        if (is_debug_area(buff, 8, gmapping, ctx->stackid)) {
                bpf_printk("vm_callback filtering debug area vm_id=%u gpu_addr=0x%lx",
                           gmapping->vm_id, gmapping->addr);
                return 0;
        }

        bpf_printk("vm_callback reading vm_id=%u gpu_addr=0x%lx",
                   gmapping->vm_id, gmapping->addr);

        info = bpf_ringbuf_reserve(&rb, sizeof(struct batchbuffer_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: vm_callback failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 1;
        }

        /* Common stuff */
        info->type = BPF_EVENT_TYPE_BATCHBUFFER;
        info->cpu = bpf_get_smp_processor_id();
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->time = bpf_ktime_get_ns();

        info->gpu_addr = gmapping->addr;
        info->vm_id = ctx->vm_id;

        buffer_copy_circular_array_add((void*)addr, size);

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

SEC("fexit/i915_gem_do_execbuffer")
int BPF_PROG(i915_gem_do_execbuffer,
             struct drm_device *dev,
             struct drm_file *file,
             struct drm_i915_gem_execbuffer2 *args,
             struct drm_i915_gem_exec_object2 *exec)
{
        int err;
        u32 cpu, handle, batch_index, batch_start_offset,
                buffer_count;
        u64 cpu_addr, batch_len, offset, size, status,
            file_ptr;
        struct execbuf_end_info *info;
        struct cpu_mapping cmapping = {};
        struct gpu_mapping gmapping = {};
        struct vm_callback_ctx vm_callback_ctx = {};

        int stackid;

        file_ptr = (u64)file;

        u32 ctx_id, vm_id;
        void *val_ptr;

        bpf_printk("execbuffer");

        /* Look up the VM ID based on the context ID (which is in execbuffer->rsvd1) */
        ctx_id = (u32)BPF_CORE_READ(args, rsvd1);
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
                (BPF_CORE_READ(args, flags) & I915_EXEC_BATCH_FIRST) ?
                        0 :
                        BPF_CORE_READ(args, buffer_count) - 1;
        batch_start_offset = BPF_CORE_READ(args, batch_start_offset);
        batch_len = BPF_CORE_READ(args, batch_len);
        buffer_count = BPF_CORE_READ(args, buffer_count);
        if (batch_index == 0) {
                /* If the index is 0 (the vast majority of the time it is), we can
                   just directly read the `objects` pointer. */
                handle = BPF_CORE_READ(exec, handle);
                offset = BPF_CORE_READ(exec, offset);
        } else {
                handle = 0xffffffff;
                offset = 0xffffffffffffffff;
        }

        /* Find a possible CPU mapping for the primary batchbuffer.
           If we can, go ahead and grab a copy of it! */
        gmapping.vm_id = vm_id;
        gmapping.addr = offset;
        val_ptr = bpf_map_lookup_elem(&gpu_cpu_map, &gmapping);
        if (val_ptr) {
                __builtin_memcpy(&cmapping, val_ptr,
                                 sizeof(struct cpu_mapping));
                cpu_addr = cmapping.addr;
                size = cmapping.size;
        } else {
                bpf_printk("WARNING: execbuffer couldn't find a CPU mapping for vm_id=%u gpu_addr=0x%lx",
                           vm_id, offset);
                cpu_addr = 0;
                size = 0;
        }

        stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);

        /* Now iterate over all buffers in the same VM as the batchbuffer */
        vm_callback_ctx.vm_id = vm_id;
        vm_callback_ctx.bits_to_match = offset & 0xffffffffff000000;
        vm_callback_ctx.bb_addr = offset;
        if (bpf_for_each_map_elem(&cpu_gpu_map, vm_callback, &vm_callback_ctx,
                                  0) < 0) {
                bpf_printk("ERROR in vm_callback");
                return 0;
        }

        /* Reserve some space on the ringbuffer, into which we can copy things */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_end_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: execbuffer failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 0;
        }

        bpf_printk("execbuffer batchbuffer 0x%lx %lu", cpu_addr, size);

        buffer_copy_circular_array_add((void*)cpu_addr, size);

        /* execbuffer-specific stuff */
        info->type = BPF_EVENT_TYPE_EXECBUF_END;
        info->file = file_ptr;
        info->vm_id = vm_id;
        info->ctx_id = ctx_id;
        info->buffer_count = buffer_count;
        info->batch_start_offset = batch_start_offset;
        info->batch_len = args->batch_len;
        info->bb_offset = offset;

        info->cpu = cpu;
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->stackid = stackid;
        info->time = bpf_ktime_get_ns();
        bpf_get_current_comm(info->name, sizeof(info->name));
        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
