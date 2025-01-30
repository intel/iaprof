#include <stdio.h>
#include <linux/types.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "collectors/bpf_i915/bpf/main.skel.h"
#include "collectors/eustall/eustall_collector.h"

#include "printers/stack/stack_printer.h"

#include "printers/flamegraph/flamegraph_printer.h"

#include "stores/buffer_profile.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "utils/utils.h"

#include "printers/debug/debug_printer.h"

char debug = 0;
pthread_mutex_t debug_print_lock = PTHREAD_MUTEX_INITIALIZER;

void print_debug_binding(struct buffer_binding *bind)
{
        debug_printf("buffer handle=%u gpu_addr=0x%lx vm_id=%u has_stalls=%u\n",
               bind->handle, bind->gpu_addr, bind->vm_id,
               bind->stall_counts != NULL);
}

/* Prints all GPU kernels that we found */
void print_debug_profile()
{
        struct vm_profile *vm;
        struct buffer_binding *bind;
        uint64_t tot;

        if (!debug) {
                return;
        }

        debug_printf("buffer_bindings\n");

        /* Iterate over each buffer */
        FOR_BINDING(vm, bind, {
                print_debug_binding(bind);
        });


        tot = eustall_info.matched + eustall_info.unmatched + eustall_info.guessed;

        debug_printf("Matched eustalls: %lu (%.2f%%)\n", eustall_info.matched, tot > 0 ? (((double)eustall_info.matched) / ((double)tot) * 100.0) : 0);
        debug_printf("Unmatched eustalls: %lu (%.2f%%)\n", eustall_info.unmatched, tot > 0 ? (((double)eustall_info.unmatched) / ((double)tot) * 100.0) : 0);
        debug_printf("Guessed eustalls: %lu (%.2f%%)\n", eustall_info.guessed, tot > 0 ? (((double)eustall_info.guessed) / ((double)tot) * 100.0) : 0);
}

void print_header()
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "EVENT");
        fprintf(stderr, " %-*.*s", TIME_LEN, TIME_LEN, "TIMESTAMP");
        fprintf(stderr, " %-*.*s", CPU_LEN, CPU_LEN, "CPU");
        fprintf(stderr, " %-*.*s", PID_LEN, PID_LEN, "PID");
        fprintf(stderr, " %-*.*s", TID_LEN, TID_LEN, "TID");
        fprintf(stderr, " %s\n", "ARGS");
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_vm_create(struct vm_create_info *info)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "vm_create");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, info->tid);
        fprintf(stderr, " vm_id=%u\n", info->vm_id);
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_vm_bind(struct vm_bind_info *info, uint32_t vm_bind_counter)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "vm_bind");
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " file=0x%llx handle=%u vm_id=%u gpu_addr=0x%llx vm_bind_counter=%u size=%llu\n",
               info->file, info->handle, info->vm_id, info->gpu_addr, vm_bind_counter,
               info->size);
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_vm_unbind(struct vm_unbind_info *info)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "vm_unbind");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u", TID_LEN, info->tid);
        fprintf(stderr, " file=0x%llx handle=%u vm_id=%u gpu_addr=0x%llx size=%llu\n",
               info->file, info->handle, info->vm_id, info->gpu_addr,
               info->size);
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_execbuf(struct execbuf_info *info)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "execbuf");
        fprintf(stderr, " %-*llu", TIME_LEN, info->time);
        fprintf(stderr, " %-*u", CPU_LEN, info->cpu);
        fprintf(stderr, " %-*u", PID_LEN, info->pid);
        fprintf(stderr, " %-*u\n", TID_LEN, info->tid);
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_total_eustall(uint64_t num, unsigned long long time)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " num=%" PRIu64 " \n", num);
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

static void print_eustall_reason(struct eustall_sample *sample)
{
        if (!debug) {
                return;
        }
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

        return;
}

void print_eustall(struct eustall_sample *sample, uint64_t gpu_addr,
                  uint64_t offset, uint32_t handle,
                  unsigned long long time)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " handle=%u gpu_addr=0x%lx offset=0x%lx ",
               handle, gpu_addr, offset);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_eustall_churn(struct eustall_sample *sample, uint64_t gpu_addr,
                         uint64_t offset, unsigned long long time)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_churn");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " gpu_addr=0x%lx offset=0x%lx ", gpu_addr,
               offset);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_eustall_drop(struct eustall_sample *sample, uint64_t gpu_addr,
                       unsigned long long time)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_drop");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " gpu_addr=0x%lx ", gpu_addr);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_eustall_defer(struct eustall_sample *sample, uint64_t gpu_addr,
                        unsigned long long time)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_defer");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " gpu_addr=0x%lx ", gpu_addr);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);

        return;
}

void print_eustall_multichurn(struct eustall_sample *sample, uint64_t gpu_addr,
                             unsigned long long time)
{
        if (!debug) {
                return;
        }
        pthread_mutex_lock(&debug_print_lock);
        fprintf(stderr, "%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_multichurn");
        fprintf(stderr, " %-*llu", TIME_LEN, time);
        fprintf(stderr, " %-*u", CPU_LEN, 0);
        fprintf(stderr, " %-*u", PID_LEN, 0);
        fprintf(stderr, " %-*u", TID_LEN, 0);
        fprintf(stderr, " gpu_addr=0x%lx ", gpu_addr);
        print_eustall_reason(sample);
        fprintf(stderr, "\n");
        pthread_mutex_unlock(&debug_print_lock);

        return;
}
