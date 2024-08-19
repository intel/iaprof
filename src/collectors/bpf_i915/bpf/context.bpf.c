/***************************************
* i915_gem_context_create_ioctl
*
* Look for gem contexts getting created, in order to see the association
* between VM ID and context ID.
***************************************/

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);
        __type(value, u64);
} context_create_wait_for_ret SEC(".maps");

/* The struct that execbuffer will use to lookup VM IDs */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);
        __type(value, u32);
} context_create_wait_for_exec SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);
        __type(value, u64);
} vm_create_wait_for_ret SEC(".maps");

SEC("kprobe/i915_gem_context_create_ioctl")
int context_create_ioctl_kprobe(struct pt_regs *ctx)
{
        u64 arg = (u64)PT_REGS_PARM2(ctx);
        u32 cpu = bpf_get_smp_processor_id();

        bpf_map_update_elem(&context_create_wait_for_ret, &cpu, &arg, 0);

        return 0;
}

SEC("kretprobe/i915_gem_context_create_ioctl")
int context_create_ioctl_kretprobe(struct pt_regs *ctx)
{
        u32 cpu, i, ctx_id, vm_id, name;
        u64 param;
        void *arg;
        struct drm_i915_gem_context_create_ext *create_ext;
        struct i915_user_extension *ext;
        struct drm_i915_gem_context_create_ext_setparam *setparam_ext;

        /* Get the pointer to the arguments from the kprobe */
        cpu = bpf_get_smp_processor_id();
        arg = bpf_map_lookup_elem(&context_create_wait_for_ret, &cpu);
        if (!arg) {
                return 1;
        }

        /* Look for CONTEXT_CREATE extensions */
        create_ext = *((struct drm_i915_gem_context_create_ext **)arg);
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
                                                                   param)
                                                        .value;
                                        /*           bpf_printk("context_create_ioctl ctx_id=%u vm_id=%u", ctx_id, vm_id); */
                                        bpf_map_update_elem(
                                                &context_create_wait_for_exec,
                                                &ctx_id, &vm_id, 0);
                                }
                        }

                        ext = (struct i915_user_extension *)BPF_CORE_READ_USER(
                                ext, next_extension);
                }
        }

        return 0;
}

/***************************************
* i915_gem_vm_create_ioctl
*
* Look for new virtual address spaces that userspace is creating.
***************************************/

SEC("kprobe/i915_gem_vm_create_ioctl")
int vm_create_ioctl_kprobe(struct pt_regs *ctx)
{
        u64 arg = (u64)PT_REGS_PARM2(ctx);
        u32 cpu = bpf_get_smp_processor_id();

        struct drm_i915_gem_vm_control *args;
        args = (void*)arg;
/*         bpf_printk("vm_create: flags=%x", BPF_CORE_READ(args, flags)); */

        bpf_map_update_elem(&vm_create_wait_for_ret, &cpu, &arg, 0);

        return 0;
}

SEC("kretprobe/i915_gem_vm_create_ioctl")
int vm_create_ioctl_kretprobe(struct pt_regs *ctx)
{
        struct vm_create_info *info;
        u64 status;
        u32 cpu;
        void *arg;
        struct drm_i915_gem_vm_control *args;

        /* Reserve some space on the ringbuffer */
        info = bpf_ringbuf_reserve(&rb, sizeof(struct vm_create_info), 0);
        if (!info) {
                bpf_printk(
                        "WARNING: vm_create_ioctl failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                bpf_printk("Unconsumed data: %lu", status);
                return -1;
        }

        cpu = bpf_get_smp_processor_id();

        info->type = BPF_EVENT_TYPE_VM_CREATE;
        info->cpu = cpu;
        info->pid = bpf_get_current_pid_tgid() >> 32;
        info->tid = bpf_get_current_pid_tgid();
        info->stackid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
        info->time = bpf_ktime_get_ns();


        info->vm_id = 0;

        arg = bpf_map_lookup_elem(&vm_create_wait_for_ret, &cpu);
        if (arg) {
                args = *(void**)arg;
/*                 bpf_printk("vm_create(ret): flags=%x vm_id=%u", BPF_CORE_READ(args, flags), BPF_CORE_READ(args, vm_id)); */
                info->vm_id = BPF_CORE_READ(args, vm_id);
        }

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);

        return 0;
}
