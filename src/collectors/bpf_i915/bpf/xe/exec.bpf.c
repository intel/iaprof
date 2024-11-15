/***************************************
* EXECBUFFER
* **********
* We need to keep track of which requests are being
* executed, so trace execbuffer calls and send those
* back to userspace.
***************************************/

#include "main.h"

/* HACKY DECLARATIONS */
#define GPU_MAPPING_MASK 0xffffffff0000
#define GPU_OFFSET_MASK 0xffff

struct vm_callback_ctx {
        u32 vm_id;
        u64 file, bb_addr;
        int stackid;
};

static long vm_callback(struct bpf_map *map, struct cpu_mapping *cmapping,
                        struct gpu_mapping *gmapping,
                        struct vm_callback_ctx *ctx)
{
        int err;
        struct batchbuffer_info *info = NULL;
        u32 *fault_count;
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

                DEBUG_PRINTK("vm_callback filtering by file=0x%lx vm_id=%u gpu_addr=0x%lx",
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
                DEBUG_PRINTK("vm_callback copying file=0x%lx vm_id=%u gpu_addr=0x%lx cpu_addr=0x%lx size=%lu",
                             gmapping->file, gmapping->vm_id, gmapping->addr, addr, size);

                fault_count = bpf_map_lookup_elem(&fault_count_map, &cmapping->addr);
                if (fault_count) {
                        size = 4096 * *fault_count;
                }
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

SEC("fexit/xe_exec_ioctl")
int BPF_PROG(xe_exec_ioctl, struct drm_device *dev, void *data, struct drm_file *file)
{
#if 0
        int err;
#endif
        struct vm_callback_ctx vm_callback_ctx = {};
        long stack_err;
        struct execbuf_end_info *info;
        struct cpu_mapping cmapping = {};
        struct gpu_mapping gmapping = {};
        struct file_ctx_pair pair = {};
        struct drm_xe_exec *args;
        u16 num_batch_buffer;
        u32 exec_queue_id, vm_id;
        u64 file_ptr, gpu_addr, gpu_page_addr,
            cpu_addr, size, status;
        void *val_ptr;
        u32 *fault_count;
        u64 *gpu_base;

        args = (struct drm_xe_exec *)data;
        file_ptr = (u64)file;

        /* Look up the VM ID based on the exec queue ID */
        exec_queue_id = BPF_CORE_READ(args, exec_queue_id);
        vm_id = 0;
        if (exec_queue_id) {
                pair.file = file_ptr;
                pair.ctx_id = exec_queue_id;
                val_ptr = bpf_map_lookup_elem(&context_create_wait_for_exec,
                                              &pair);
                if (val_ptr) {
                        vm_id = *((u32 *)val_ptr);
                }
        }
        
        gpu_addr = BPF_CORE_READ(args, address);
        gpu_page_addr = gpu_addr & PAGE_MASK;
        DEBUG_PRINTK("execbuffer vm_id=%u exec_queue_id=%u num_batch_buffer=%u address=0x%lx",
                     vm_id, exec_queue_id, num_batch_buffer, gpu_addr);
        num_batch_buffer = BPF_CORE_READ(args, num_batch_buffer);
                     
        /* Look up our base GPU address (the beginning of this mapping/binding)
           in a map that keeps track of all pages */
        gpu_base = (u64 *)bpf_map_lookup_elem(&page_map, &gpu_page_addr);
        if (!gpu_base) {
                DEBUG_PRINTK("WARNING: execbuffer couldn't find a page_map entry for vm_id=%u gpu_page_addr=0x%lx exec_queue_id=%u",
                             vm_id, gpu_page_addr, exec_queue_id);
                return 0;
        }

        /* Find a possible CPU mapping for the primary batchbuffer.
           If we can, go ahead and grab a copy of it! */
        gmapping.vm_id = vm_id;
        gmapping.addr = *gpu_base;
        gmapping.file = file_ptr;
        val_ptr = bpf_map_lookup_elem(&gpu_cpu_map, &gmapping);
        if (val_ptr) {
                __builtin_memcpy(&cmapping, val_ptr,
                                 sizeof(struct cpu_mapping));
                cpu_addr = cmapping.addr;
                size = cmapping.size;
        } else {
                DEBUG_PRINTK("WARNING: execbuffer couldn't find a CPU mapping for vm_id=%u gpu_addr=0x%lx exec_queue_id=%u",
                             vm_id, gpu_addr, exec_queue_id);
                return 0;
        }
        
        /* Now iterate over all buffers in the same VM as the batchbuffer */
        vm_callback_ctx.vm_id = vm_id;
        vm_callback_ctx.file = (u64)file_ptr;
        vm_callback_ctx.bb_addr = *gpu_base;
        if (bpf_for_each_map_elem(&cpu_gpu_map, vm_callback, &vm_callback_ctx,
                                  0) < 0) {
                DEBUG_PRINTK("ERROR in vm_callback");
                return 0;
        }

        fault_count = bpf_map_lookup_elem(&fault_count_map, &cpu_addr);
        if (fault_count) {
                size = 4096 * *fault_count;
        }

        if (buffer_copy_add((void*)cpu_addr, size)) {
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

                DEBUG_PRINTK("execbuffer batchbuffer cpu_addr=0x%lx gpu_addr=0x%lx size=%lu", cpu_addr, gpu_addr, size);

                stack_err = bpf_get_stack(ctx, &(info->kernel_stack.addrs), sizeof(info->kernel_stack.addrs), 3 & BPF_F_SKIP_FIELD_MASK);
                if (stack_err < 0) {
                        DEBUG_PRINTK("WARNING: execbuffer failed to get a kernel stack: %ld", stack_err);
                }
                stack_err = bpf_get_stack(ctx, &(info->stack.addrs), sizeof(info->stack.addrs), BPF_F_USER_STACK);
                if (stack_err < 0) {
                        DEBUG_PRINTK("WARNING: execbuffer failed to get a user stack: %ld", stack_err);
                }
                
                /* execbuffer-specific stuff */
                info->type = BPF_EVENT_TYPE_EXECBUF_END;
                info->file = file_ptr;
                info->vm_id = vm_id;
                info->ctx_id = exec_queue_id;
                info->buffer_count = num_batch_buffer;
                info->batch_start_offset = gpu_addr - (*gpu_base);
                info->bb_offset = *gpu_base;

                info->pid = bpf_get_current_pid_tgid() >> 32;
                info->tid = bpf_get_current_pid_tgid();
                info->time = bpf_ktime_get_ns();
                bpf_get_current_comm(info->name, sizeof(info->name));
                bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
        }

        return 0;
}
