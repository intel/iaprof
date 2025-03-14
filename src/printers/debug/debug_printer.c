#include <stdio.h>
#include <linux/types.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "collectors/bpf_i915/bpf/main.skel.h"
#include "collectors/eustall/eustall_collector.h"

#include "printers/stack/stack_printer.h"

#include "printers/flamegraph/flamegraph_printer.h"

#include "stores/gpu_kernel_stalls.h"

#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "utils/utils.h"

#include "printers/debug/debug_printer.h"

char debug = 0;
pthread_mutex_t debug_print_lock = PTHREAD_MUTEX_INITIALIZER;

void print_debug_shader(struct shader_binding *shader)
{
        debug_printf("buffer gpu_addr=0x%lx vm_id=%u\n",
               shader->gpu_addr, shader->vm_id);
}

/* Prints all shaders that we've found */
void print_debug_profile()
{
        struct vm_profile *vm;
        struct shader_binding *shader;
        uint64_t tot;

        if (!debug) {
                return;
        }

        debug_printf("shader_bindings\n");

        /* Iterate over each buffer */
        FOR_SHADER(vm, shader, {
                print_debug_shader(shader);
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
