/***************************************
* i915_gem_context_create_ioctl
*
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
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct file_ctx_pair);
        __type(value, u32);
} context_create_wait_for_exec SEC(".maps");

SEC("fexit/i915_gem_context_create_ioctl")
int BPF_PROG(i915_gem_context_create_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file, int retval)
{
        u32 cpu, i, ctx_id, vm_id, name;
        u64 param;
        struct drm_i915_gem_context_create_ext *create_ext;
        struct i915_user_extension *ext;
        struct drm_i915_gem_context_create_ext_setparam *setparam_ext;
        u64 status;
        struct file_ctx_pair pair = {};

        if (retval) {
                DEBUG_PRINTK("!!! context_create returned with an error");
                return 0;
        }

        /* Look for CONTEXT_CREATE extensions */
        create_ext = (struct drm_i915_gem_context_create_ext *)data;
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
                                                                   param).value;
                                        DEBUG_PRINTK("context_create_ioctl file=%llu ctx_id=%u vm_id=%u", (u64)file, ctx_id, vm_id);
                                        pair.file = (u64)file;
                                        pair.ctx_id = ctx_id;
                                        bpf_map_update_elem(
                                                &context_create_wait_for_exec,
                                                &pair, &vm_id, 0);
                                }
                        }

                        ext = (struct i915_user_extension *)BPF_CORE_READ_USER(
                                ext, next_extension);
                }
        }

        return 0;
}

#if 0
SEC("fexit/i915_gem_context_destroy_ioctl")
int BPF_PROG(i915_gem_context_destroy_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{

        DEBUG_PRINTK("!!! context_destroy_ioctl");

        return 0;
}
#endif

SEC("fexit/i915_gem_context_setparam_ioctl")
int BPF_PROG(i915_gem_context_setparam_ioctl,
             struct drm_device *dev, void *data,
             struct drm_file *file)
{
        struct drm_i915_gem_context_param *args = data;
        struct file_ctx_pair pair = {};
        u32 vm_id;

        if (BPF_CORE_READ(args, param) == I915_CONTEXT_PARAM_VM) {
                pair.file = (u64)file;
                pair.ctx_id = BPF_CORE_READ(args, ctx_id);
                vm_id = BPF_CORE_READ(args, value);
                bpf_map_update_elem(
                        &context_create_wait_for_exec,
                        &pair, &vm_id, 0);
                DEBUG_PRINTK("context_setparam PARAM_VM file=%llu ctx_id=%u vm_id=%u", pair.file, pair.ctx_id, vm_id);
        }

        return 0;
}

/***************************************
* i915_gem_vm_create_ioctl
*
* Look for new virtual address spaces that userspace is creating.
***************************************/

SEC("fexit/i915_gem_vm_create_ioctl")
int BPF_PROG(i915_gem_vm_create_ioctl, struct drm_device *dev, void *data,
             struct drm_file *file)
{
        struct vm_create_info *info;
        u64 status;
        u32 cpu, vm_id;
        void *lookup;
        struct drm_i915_gem_vm_control *args;

        args = (struct drm_i915_gem_vm_control *)data;
        vm_id = BPF_CORE_READ(args, vm_id);
        DEBUG_PRINTK("vm_create(ret): vm_id=%u", vm_id);

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct vm_create_info), 0);
        if (!info) {
                DEBUG_PRINTK(
                        "WARNING: vm_create_ioctl failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 0;
        }

        info->type = BPF_EVENT_TYPE_VM_CREATE;
        info->cpu = cpu;
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->time = bpf_ktime_get_ns();
        info->vm_id = vm_id;
        info->file = (u64)file;

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
