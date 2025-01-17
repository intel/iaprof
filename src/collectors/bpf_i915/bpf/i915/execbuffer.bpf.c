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
#include "batchbuffer.bpf.c"

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
        struct cpu_mapping cmapping = {};
        struct gpu_mapping gmapping = {};
        struct file_ctx_pair pair = {};
        struct execbuf_info *info;

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
                WARN_PRINTK("execbuffer couldn't find a CPU mapping for vm_id=%u gpu_addr=0x%lx ctx_id=%u",
                           vm_id, offset, ctx_id);
                return 0;
        }


        DEBUG_PRINTK("execbuffer batchbuffer cpu_addr=0x%lx gpu_addr=0x%lx size=%lu", cpu_addr, offset, size);

        info = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_info), 0);
        if (!info) {
                ERR_PRINTK("execbuffer failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 0;
        }

        info->type = BPF_EVENT_TYPE_EXECBUF;

        info->vm_id = vm_id;
        info->file  = file_ptr;
        info->pid   = bpf_get_current_pid_tgid() >> 32;
        info->tid   = bpf_get_current_pid_tgid();
        info->cpu   = bpf_get_smp_processor_id();
        info->time  = bpf_ktime_get_ns();
        bpf_get_current_comm(info->name, sizeof(info->name));

        stack_err = bpf_get_stack(ctx, &(info->kstack.addrs), sizeof(info->kstack.addrs), 3 & BPF_F_SKIP_FIELD_MASK);
        if (stack_err < 0) {
                WARN_PRINTK("execbuffer failed to get a kernel stack: %ld", stack_err);
        }
        stack_err = bpf_get_stack(ctx, &(info->ustack.addrs), sizeof(info->ustack.addrs), BPF_F_USER_STACK);
        if (stack_err < 0) {
                WARN_PRINTK("execbuffer failed to get a user stack: %ld", stack_err);
        }

        if (parse_batchbuffer(cpu_addr, offset, size, offset + batch_start_offset, info) == 0) {
                if (info->iba || info->ksp || info->sip) {
                        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
                } else {
                        bpf_ringbuf_discard(info, 0);
                }
        } else {
                bpf_ringbuf_discard(info, 0);
                ERR_PRINTK("failure in batch buffer parsing");
                dropped_event = 1;
        }

        return 0;
}
