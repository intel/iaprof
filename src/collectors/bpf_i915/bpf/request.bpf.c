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
        u64 ctx;
        u32 guc_id;
        u16 class;
        u16 instance;
        u32 seqno;
        u32 offset;
};

struct request_retire_args {
        u64 x;
        u32 dev;
        u64 ctx;
        u32 guc_id;
        u16 class;
        u16 instance;
        u32 seqno;
        u32 offset;
};

struct request_in_args {
        u64 x;
        u32 dev;
        u64 ctx;
        u16 class;
        u16 instance;
        u32 seqno;
        u32 port;
        u32 prio;
};

struct request_out_args {
        u64 x;
        u32 dev;
        u64 ctx;
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
        info->ctx = ctx->ctx;
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
        info->ctx = ctx->ctx;
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
        info->ctx = ctx->ctx;
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
        info->ctx = ctx->ctx;
        info->time = bpf_ktime_get_ns();

	bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
