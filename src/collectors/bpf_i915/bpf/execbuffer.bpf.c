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
        u64 file;
        int stackid;
};

static long vm_callback(struct bpf_map *map, struct cpu_mapping *cmapping,
                        struct gpu_mapping *gmapping,
                        struct vm_callback_ctx *ctx)
{
        int err;
        struct batchbuffer_info *info = NULL;
        u64 status, size, addr;
        char one = 1;

        if (bpf_map_lookup_elem(&known_not_batch_buffers, gmapping)) {
                return 0;
        }

        /* Look at the CPU mapping */
        addr = cmapping->addr;
        size = cmapping->size;

        /*
           We only care about this buffer if it:
           1. Is from the same driver handle (file).
           2. Has the same vm_id as the batchbuffer for this execbuffer call.
           3. Isn't the primary batchbuffer (which we're copying elsewhere)
        */

        /* Using bitwise OR here because the verifier won't give me any more
           branches in this prog :( */
        if ((gmapping->addr  == ctx->bb_addr)
        |   (gmapping->file  != ctx->file)
        |   (gmapping->vm_id != ctx->vm_id)) {

                DEBUG_PRINTK("vm_callback filtering by file=%llu vm_id=%u gpu_addr=0x%lx",
                           gmapping->file, gmapping->vm_id, gmapping->addr);
                return 0;
        }

        if (is_debug_area((void*)addr, size)) {
                send_debug_area_info(gmapping, ctx->stackid);
                DEBUG_PRINTK("vm_callback filtering debug area vm_id=%u gpu_addr=0x%lx",
                        gmapping->vm_id, gmapping->addr);
                bpf_map_update_elem(&known_not_batch_buffers, gmapping, &one, BPF_ANY);
                return 0;
        }


        if (looks_like_batch_buffer((void*)addr, size)) {
                DEBUG_PRINTK("vm_callback copying file=%llu vm_id=%u gpu_addr=0x%lx",
                             gmapping->file, gmapping->vm_id, gmapping->addr);

                if (buffer_copy_add((void*)addr, size)) {
/*                         DEBUG_PRINTK("!!! BB %u 0x%lx 0 0", */
/*                                      gmapping->vm_id, gmapping->addr); */

                        info = bpf_ringbuf_reserve(&rb, sizeof(struct batchbuffer_info), 0);
                        if (!info) {
                                DEBUG_PRINTK(
                                        "WARNING: vm_callback failed to reserve in the ringbuffer.");
                                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                                DEBUG_PRINTK("Unconsumed data: %lu", status);
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
                        info->vm_id = gmapping->vm_id;
                        info->file = gmapping->file;

                        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
                }
        } else {
/*                 bpf_map_update_elem(&known_not_batch_buffers, gmapping, &one, BPF_ANY); */
        }

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
        long stack_err;
        u32 cpu, handle, batch_index, batch_start_offset,
                buffer_count;
        u64 cpu_addr, batch_len, offset, size, status,
            file_ptr;
        struct execbuf_end_info *info;
        struct cpu_mapping cmapping = {};
        struct gpu_mapping gmapping = {};
        struct vm_callback_ctx vm_callback_ctx = {};
        struct file_ctx_pair pair = {};

        file_ptr = (u64)file;

        u32 ctx_id, vm_id;
        void *val_ptr;

        DEBUG_PRINTK("execbuffer");

        /* Look up the VM ID based on the context ID (which is in execbuffer->rsvd1) */
        ctx_id = (u32)BPF_CORE_READ(args, rsvd1);
        vm_id = 0;
        if (ctx_id) {
                pair.file = file_ptr;
                pair.ctx_id = ctx_id;
                val_ptr = bpf_map_lookup_elem(&context_create_wait_for_exec,
                                              &pair);
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
        gmapping.file = file_ptr;
        val_ptr = bpf_map_lookup_elem(&gpu_cpu_map, &gmapping);
        if (val_ptr) {
                __builtin_memcpy(&cmapping, val_ptr,
                                 sizeof(struct cpu_mapping));
                cpu_addr = cmapping.addr;
                size = cmapping.size;
        } else {
                DEBUG_PRINTK("WARNING: execbuffer couldn't find a CPU mapping for vm_id=%u gpu_addr=0x%lx ctx_id=%u",
                           vm_id, offset, ctx_id);
                return 0;
        }

        /* Now iterate over all buffers in the same VM as the batchbuffer */
        vm_callback_ctx.vm_id = vm_id;
        vm_callback_ctx.file = (u64)file;
        vm_callback_ctx.bits_to_match = offset & 0xffffffffff000000;
        vm_callback_ctx.bb_addr = offset;
        if (bpf_for_each_map_elem(&cpu_gpu_map, vm_callback, &vm_callback_ctx,
                                  0) < 0) {
                DEBUG_PRINTK("ERROR in vm_callback");
                return 0;
        }

        if (buffer_copy_add((void*)cpu_addr, size)) {
/*                 DEBUG_PRINTK("!!! BB %u 0x%lx 0 0", */
/*                                 gmapping.vm_id, gmapping.addr); */

                /* Reserve some space on the ringbuffer, into which we can copy things */
                info = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_end_info), 0);
                if (!info) {
                        DEBUG_PRINTK(
                                "WARNING: execbuffer failed to reserve in the ringbuffer.");
                        status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                        DEBUG_PRINTK("Unconsumed data: %lu", status);
                        dropped_event = 1;
                        return 0;
                }

                DEBUG_PRINTK("execbuffer batchbuffer cpu_addr=0x%lx gpu_addr=0x%lx size=%lu", cpu_addr, offset, size);

                stack_err = bpf_get_stack(ctx, &(info->stack.addrs), sizeof(info->stack.addrs), BPF_F_USER_STACK);
                if (stack_err < 0) {
                        DEBUG_PRINTK("WARNING: execbuffer failed to get a stack: %ld", stack_err);
                }
                
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
                info->time = bpf_ktime_get_ns();
                bpf_get_current_comm(info->name, sizeof(info->name));
                bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
        }

        return 0;
}
