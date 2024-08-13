/***************************************
* REQUESTS
*
* Each execbuffer call in i915 results in one or more
* requests being submitted to a queue and executed on the GPU
* in a particular order. Keep track of these requests to know
* (approximately) when these requests have completed on the GPU.
***************************************/

struct request_submit_args {
        u64 x;
        u32 dev;
        u64 gem_ctx;
        u32 guc_id;
        u16 class;
        u16 instance;
        u32 seqno;
        u32 offset;
};

struct request_retire_args {
        u64 x;
        u32 dev;
        u64 gem_ctx;
        u32 guc_id;
        u16 class;
        u16 instance;
        u32 seqno;
        u32 offset;
};

struct request_in_args {
        u64 x;
        u32 dev;
        u64 gem_ctx;
        u16 class;
        u16 instance;
        u32 seqno;
        u32 port;
        u32 prio;
};

struct request_out_args {
        u64 x;
        u32 dev;
        u64 gem_ctx;
        u16 class;
        u16 instance;
        u32 seqno;
        u32 completed;
};

SEC("tracepoint/i915/i915_request_submit")
int request_submit_tp(struct request_submit_args *ctx)
{
        u64 status;
        struct request_info *info;

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct request_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: request_submit_tp failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return -1;
        }

        info->type = REQUEST_SUBMIT;
        info->seqno = ctx->seqno;
        info->gem_ctx = ctx->gem_ctx;
        info->class = ctx->class;
        info->instance = ctx->instance;
        info->time = bpf_ktime_get_ns();
        
        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

SEC("tracepoint/i915/i915_request_retire")
int request_retire_tp(struct request_retire_args *ctx)
{
        u64 status;
        struct request_info *info;

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct request_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: request_retire_tp failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return -1;
        }

        info->type = REQUEST_RETIRE;
        info->seqno = ctx->seqno;
        info->gem_ctx = ctx->gem_ctx;
        info->time = bpf_ktime_get_ns();

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

SEC("tracepoint/i915/i915_request_in")
int request_in_tp(struct request_in_args *ctx)
{
        u64 status;
        struct request_info *info;

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct request_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: request_in_tp failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return -1;
        }

        info->type = REQUEST_IN;
        info->seqno = ctx->seqno;
        info->gem_ctx = ctx->gem_ctx;
        info->time = bpf_ktime_get_ns();

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

SEC("tracepoint/i915/i915_request_out")
int request_out_tp(struct request_out_args *ctx)
{
        u64 status;
        struct request_info *info;

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct request_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: request_out_tp failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return -1;
        }

        info->type = REQUEST_OUT;
        info->seqno = ctx->seqno;
        info->gem_ctx = ctx->gem_ctx;
        info->time = bpf_ktime_get_ns();

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

#if 0
SEC("kprobe/i915_request_retire")
int request_retire_kprobe(struct pt_regs *ctx)
{
        struct i915_request *rq;
        struct i915_vma *vma;
        struct drm_mm_node *node;
        struct batchbuffer_info *info;
        struct intel_ring *ring;
        u64 gpu_addr, vaddr, addr, size;
        u32 head, tail;
        int err;
        
        struct gpu_mapping gmapping = {};
/*         struct cpu_mapping cmapping = {}; */
        
        /* Get the GPU address and VM ID that is associated with the batchbuffer
           that this request is for */
        rq = (struct i915_request *)PT_REGS_PARM1(ctx);
        vma = (struct i915_vma *) BPF_CORE_READ(rq, batch);
        ring = BPF_CORE_READ(rq, ring);
        node = (struct drm_mm_node *)(((char *)vma) + bpf_core_field_offset(struct i915_vma, node));
        gpu_addr = (u64) BPF_CORE_READ(node, start);
        
        head = BPF_CORE_READ(rq, head);
        tail = BPF_CORE_READ(rq, tail);
        vaddr = (u64) BPF_CORE_READ(ring, vaddr);
        
        info = bpf_ringbuf_reserve(&rb, sizeof(struct batchbuffer_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: request_submit_kprobe failed to reserve in the ringbuffer.");
                return 1;
        }

        /* Common stuff */
        info->cpu = bpf_get_smp_processor_id();
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->time = bpf_ktime_get_ns();

        info->gpu_addr = gpu_addr;
        info->vm_id = 0xfffffff;

        addr = vaddr + head;
        size = tail - head;
        if (size > MAX_BINARY_SIZE) {
                size = MAX_BINARY_SIZE;
        }
        info->buff_sz = size;
        err = bpf_probe_read_kernel(info->buff, size, (const void *)addr);
        if (err < 0) {
                bpf_printk(
                        "WARNING: i915_submit_kprobe failed to copy %lu bytes from 0x%lx: %d",
                        size, addr, err);
                info->buff_sz = 0;
        }
        bpf_ringbuf_submit(info, 0);
        
        return 0;
}
#endif
