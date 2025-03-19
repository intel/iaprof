#ifndef DISABLE_BPF

/***************************************
* Look for gem contexts getting created, in order to see the association
* between VM ID and context ID.
***************************************/

/* The struct that execbuffer will use to lookup VM IDs */

struct file_ctx_pair {
        u64 file;
        u32 ctx_id;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_MAPPINGS);
        __type(key, struct file_ctx_pair);
        __type(value, u32);
} context_create_wait_for_exec SEC(".maps");

SEC("fexit/xe_exec_queue_create_ioctl")
int BPF_PROG(xe_exec_queue_create_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file, int retval)
{
        u32 ctx_id, vm_id;
        struct file_ctx_pair pair = {};
        struct drm_xe_exec_queue_create *args;

        if (retval) {
                DEBUG_PRINTK("!!! exec_queue_create returned with an error");
                return 0;
        }

        args = (struct drm_xe_exec_queue_create *)data;
        vm_id = BPF_CORE_READ(args, vm_id);
        ctx_id = BPF_CORE_READ(args, exec_queue_id);

        DEBUG_PRINTK("context_create_ioctl file=%llu ctx_id=%u vm_id=%u", (u64)file, ctx_id, vm_id);
        pair.file = (u64)file;
        pair.ctx_id = ctx_id;
        bpf_map_update_elem(
                &context_create_wait_for_exec,
                &pair, &vm_id, 0);

        return 0;
}

#endif
