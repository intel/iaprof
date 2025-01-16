/***************************************
* EXECBUFFER
* **********
* We need to keep track of which requests are being
* executed, so trace execbuffer calls and send those
* back to userspace.
***************************************/

#ifndef DISABLE_BPF

#include "main.h"

SEC("fexit/xe_exec_ioctl")
int BPF_PROG(xe_exec_ioctl, struct drm_device *dev, void *data, struct drm_file *file)
{
        long stack_err;
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
        u64 *gpu_base, offset;
        struct execbuf_info *info;

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
        offset = gpu_addr - *gpu_base;

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
        
        fault_count = bpf_map_lookup_elem(&fault_count_map, &cpu_addr);
        if (fault_count) {
                size = 4096 * *fault_count;
        }
        
        DEBUG_PRINTK("execbuffer batchbuffer cpu_addr=0x%lx gpu_addr=0x%lx size=%lu", cpu_addr, gpu_addr, size);
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

        if (parse_batchbuffer(cpu_addr, *gpu_base, size, *gpu_base + offset, info) == 0) {
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

#endif
