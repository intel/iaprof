#include "iaprof.h"

#include "printers/flamegraph/flamegraph_printer.h"

#include "stores/buffer_profile.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "utils/utils.h"

void print_debug_buffer_profile(struct buffer_profile *gem)
{
        printf("buffer handle=%u gpu_addr=0x%lx vm_id=%u has_stalls=%u\n",
               gem->handle, gem->gpu_addr, gem->vm_id,
               gem->stall_counts != NULL);
}

/* Prints all GPU kernels that we found */
void print_debug_profile()
{
        struct vm_profile *vm;
        struct buffer_profile *gem;

        if (!debug) {
                return;
        }

        debug_printf("buffer_profiles\n");

        /* Iterate over each buffer */
        FOR_BUFFER_PROFILE(vm, gem, {
                print_debug_buffer_profile(gem);
        });
        
        printf("Matched eustalls: %lu\n", eustall_info.matched);
        printf("Unmatched eustalls: %lu\n", eustall_info.unmatched);
        printf("Guessed eustalls: %lu\n", eustall_info.guessed);
}
