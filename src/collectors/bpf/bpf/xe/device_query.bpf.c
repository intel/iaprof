#ifndef DISABLE_BPF

/***************************************
* See who is using the Xe driver, to attach to the eudebug interface.
***************************************/

SEC("fentry/xe_query_ioctl")
int BPF_PROG(xe_query_ioctl)
{
        struct device_query_info *info;
        long err;
        
        info = bpf_ringbuf_reserve(&rb, sizeof(struct device_query_info), 0);
        if (!info) {
                ERR_PRINTK("xe_query_ioctl failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return 0;
        }
        info->type = BPF_EVENT_TYPE_DEVICE_QUERY;
        info->pid  = bpf_get_current_pid_tgid() >> 32;
        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
        
        return 0;
}

#endif
