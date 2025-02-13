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

static __u64 eb_id;

SEC("fexit/i915_gem_do_execbuffer")
int BPF_PROG(i915_gem_do_execbuffer,
             struct drm_device *dev,
             struct drm_file *file,
             struct drm_i915_gem_execbuffer2 *args,
             struct drm_i915_gem_exec_object2 *exec)
{
        long err;
        u32 batch_start_offset, batch_index;
        u64 cpu_addr, offset, size,
            file_ptr, this_eb_id;
        struct cpu_mapping cmapping = {};
        struct gpu_mapping gmapping = {};
        struct file_ctx_pair pair = {};
        struct execbuf_info *info;
        static struct parse_cxt parse_cxt = {}; /* static to reduce pressure on stack size */
        struct execbuf_end_info *end_info;

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
        if (batch_index == 0) {
                /* If the index is 0 (the vast majority of the time it is), we can
                   just directly read the `objects` pointer. */
                offset = BPF_CORE_READ(exec, offset);
        } else {
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


        try_parse_deferred_batchbuffers(NULL);


        DEBUG_PRINTK("execbuffer batchbuffer cpu_addr=0x%lx gpu_addr=0x%lx size=%lu", cpu_addr, offset, size);

        info = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_info), 0);
        if (!info) {
                ERR_PRINTK("execbuffer failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }

        this_eb_id = __sync_fetch_and_add(&eb_id, 1);

        info->type = BPF_EVENT_TYPE_EXECBUF;

        info->eb_id = this_eb_id;
        info->vm_id = vm_id;
        info->file  = file_ptr;
        info->pid   = bpf_get_current_pid_tgid() >> 32;
        info->tid   = bpf_get_current_pid_tgid();
        info->cpu   = bpf_get_smp_processor_id();
        info->time  = bpf_ktime_get_ns();
        bpf_get_current_comm(info->name, sizeof(info->name));

        err = bpf_get_stack(ctx, &(info->kstack.addrs), sizeof(info->kstack.addrs), 3 & BPF_F_SKIP_FIELD_MASK);
        if (err < 0) {
                WARN_PRINTK("execbuffer failed to get a kernel stack: %ld", err);
        }
        err = bpf_get_stack(ctx, &(info->ustack.addrs), sizeof(info->ustack.addrs), BPF_F_USER_STACK);
        if (err < 0) {
                WARN_PRINTK("execbuffer failed to get a user stack: %ld", err);
        }

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        parse_cxt.eb_id      = this_eb_id;
        parse_cxt.ips[0]     = offset + batch_start_offset;
        parse_cxt.cpu_ips[0] = cpu_addr + batch_start_offset;

        if (parse_batchbuffer(&parse_cxt, 0) == DATA_NOT_READY) {
                defer_batchbuffer_parse(&parse_cxt);
        } else {
                end_info = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_end_info), 0);
                if (!end_info) {
                        ERR_PRINTK("execbuffer failed to reserve in the ringbuffer.");
                        err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                        DEBUG_PRINTK("Unconsumed data: %lu", err);
                        dropped_event = 1;
                        return 0;
                }
                end_info->type  = BPF_EVENT_TYPE_EXECBUF_END;
                end_info->eb_id = this_eb_id;
                bpf_ringbuf_submit(end_info, BPF_RB_FORCE_WAKEUP);
        }

        return 0;
}
