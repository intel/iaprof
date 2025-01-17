#include "iaprof.h"

#include "printers/flamegraph/flamegraph_printer.h"

#include "stores/buffer_profile.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "utils/utils.h"

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
