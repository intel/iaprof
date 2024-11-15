#include "printer.h"

#include "iaprof.h"

#include "collectors/bpf_i915/bpf/main.h"
#include "collectors/bpf_i915/bpf/main.skel.h"
#include "collectors/eustall/eustall_collector.h"

#include "printers/stack/stack_printer.h"

int print_header()
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "EVENT");
        fprintf(stderr, " %-*.*s", TIME_LEN, TIME_LEN, "TIMESTAMP");
        fprintf(stderr, " %-*.*s", CPU_LEN, CPU_LEN, "CPU");
        fprintf(stderr, " %-*.*s", PID_LEN, PID_LEN, "PID");
        fprintf(stderr, " %-*.*s", TID_LEN, TID_LEN, "TID");
        fprintf(stderr, " %s\n", "ARGS");
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_mapping(struct mapping_info *info)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "mmap");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, info->tid);

        /* ARGS */
        fprintf(stderr, " file=0x%llx handle=%u cpu_addr=0x%llx size=%llu offset=%llu ",
               info->file, info->handle, info->cpu_addr, info->size,
               info->offset);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_unmap(struct unmap_info *info)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "unmap");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, info->tid);
        fprintf(stderr, " file=0x%llx handle=%u cpu_addr=0x%llx size=%llu\n", info->file,
               info->handle, info->cpu_addr, info->size);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_userptr(struct userptr_info *info)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "userptr");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, info->tid);
        fprintf(stderr, " file=0x%llx handle=%u cpu_addr=0x%llx\n", info->file,
               info->handle, info->cpu_addr);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_debug_area(struct debug_area_info *info)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "debug_area");
        fprintf(stderr, " %-*llu", TIME_LEN, (unsigned long long)0);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " vm_id=%u gpu_addr=0x%llx\n",
               info->vm_id, info->gpu_addr);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_vm_create(struct vm_create_info *info)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "vm_create");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, info->tid);
        fprintf(stderr, " vm_id=%u\n", info->vm_id);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_vm_bind(struct vm_bind_info *info, uint32_t vm_bind_counter)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "vm_bind");
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " file=0x%llx handle=%u vm_id=%u gpu_addr=0x%llx vm_bind_counter=%u size=%llu\n",
               info->file, info->handle, info->vm_id, info->gpu_addr, vm_bind_counter,
               info->size);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_vm_unbind(struct vm_unbind_info *info)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "vm_unbind");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, info->tid);
        fprintf(stderr, " file=0x%llx handle=%u vm_id=%u gpu_addr=0x%llx size=%llu\n",
               info->file, info->handle, info->vm_id, info->gpu_addr,
               info->size);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_batchbuffer(struct batchbuffer_info *info)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "batchbuffer");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, info->tid);
        fprintf(stderr, " vm_id=%u gpu_addr=0x%llx\n", info->vm_id,
               info->gpu_addr);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

/* Prints buffers that an execbuffer referenced through its vm_id */
int print_execbuf_buffer(struct buffer_binding *bind)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "execbuf_bind");
        fprintf(stderr, " %-*lu", TIME_LEN, bind->time);
        fprintf(stderr, " %-*u", CPU_LEN, bind->cpu);
        fprintf(stderr, " %-*u", PID_LEN, bind->pid);
        fprintf(stderr, " %-*u", TID_LEN, bind->tid);
        fprintf(stderr, " ctx_id=%u", bind->ctx_id);
        fprintf(stderr, " file=0x%lx handle=%u vm_id=%u gpu_addr=0x%lx size=%lu\n",
               bind->file, bind->handle, bind->vm_id, bind->gpu_addr,
               bind->bind_size);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_execbuf_end(struct execbuf_end_info *einfo)
{
        static int counter;
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "execbuf_end");
        fprintf(stderr, " %-*llu", TIME_LEN, einfo->time);
        fprintf(stderr, " %-*u", CPU_LEN, einfo->cpu);
        fprintf(stderr, " %-*u", PID_LEN, einfo->pid);
        fprintf(stderr, " %-*u", TID_LEN, einfo->tid);
        fprintf(stderr, " ctx_id=%u gpu_addr=0x%llx buffer_count=%u, batch_start_offset=0x%x, counter=%d\n", einfo->ctx_id, einfo->bb_offset, einfo->buffer_count, einfo->batch_start_offset, counter);
        pthread_mutex_unlock(&debug_print_lock);

        counter++;

        return 0;
}

int print_total_eustall(uint64_t num, unsigned long long time)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " num=%" PRIu64 " \n", num);
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

static int print_eustall_reason(struct eustall_sample *sample)
{
        if (sample->active) {
                fprintf(stderr, "active=%u ", sample->active);
        }
        if (sample->other) {
                fprintf(stderr, "other=%u ", sample->other);
        }
        if (sample->control) {
                fprintf(stderr, "control=%u ", sample->control);
        }
        if (sample->pipestall) {
                fprintf(stderr, "pipestall=%u ", sample->pipestall);
        }
        if (sample->send) {
                fprintf(stderr, "send=%u ", sample->send);
        }
        if (sample->dist_acc) {
                fprintf(stderr, "dist_acc=%u ", sample->dist_acc);
        }
        if (sample->sbid) {
                fprintf(stderr, "sbid=%u ", sample->sbid);
        }
        if (sample->sync) {
                fprintf(stderr, "sync=%u ", sample->sync);
        }
        if (sample->inst_fetch) {
                fprintf(stderr, "inst_fetch=%u ", sample->inst_fetch);
        }

        return 0;
}

int print_eustall(struct eustall_sample *sample, uint64_t gpu_addr,
                  uint64_t offset, uint32_t handle, uint16_t subslice,
                  unsigned long long time)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " handle=%u gpu_addr=0x%lx offset=0x%lx subslice=%" PRIu16 " ",
               handle, gpu_addr, offset, subslice);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_eustall_churn(struct eustall_sample *sample, uint64_t gpu_addr,
                        uint64_t offset, uint16_t subslice,
                        unsigned long long time)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_churn");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " gpu_addr=0x%lx offset=0x%lx subslice=%" PRIu16 " ", gpu_addr,
               offset, subslice);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_eustall_drop(struct eustall_sample *sample, uint64_t gpu_addr,
                       uint16_t subslice, unsigned long long time)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_drop");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " gpu_addr=0x%lx subslice=%" PRIu16 " ", gpu_addr, subslice);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_eustall_defer(struct eustall_sample *sample, uint64_t gpu_addr,
                        uint16_t subslice, unsigned long long time)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_defer");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " gpu_addr=0x%lx subslice=%" PRIu16 " ", gpu_addr, subslice);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}

int print_eustall_multichurn(struct eustall_sample *sample, uint64_t gpu_addr,
                             uint16_t subslice, unsigned long long time)
{
        pthread_mutex_lock(&debug_print_lock);;
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_multichurn");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " gpu_addr=0x%lx subslice=%" PRIu16 " ", gpu_addr, subslice);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);;

        return 0;
}
