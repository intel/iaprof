#include "iaprof.h"

#include "printers/flamegraph/flamegraph_printer.h"

#include "stores/buffer_profile.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "utils/utils.h"

void print_debug_buffer_profile(struct buffer_profile *gem, int gem_index)
{
        printf("buffer handle=%u gpu_addr=0x%llx vm_id=%u index=%d has_stalls=%u\n",
               gem->handle, gem->vm_bind_info.gpu_addr, gem->vm_id, gem_index,
               interval_profile_arr[gem_index].has_stalls);
}

/* Prints all GPU kernels that we found */
void print_debug_profile()
{
        int i;
        struct buffer_profile *gem;

        if (!debug) {
                return;
        }

        /* Iterate over each buffer */
        for (i = 0; i < buffer_profile_used; i++) {
                gem = &buffer_profile_arr[i];

                print_debug_buffer_profile(gem, i);
        }
}

void print_vms()
{
        uint32_t vm_index;
        struct vm_profile *vm;
        struct request_profile_list *rq;

        if (!debug) {
                return;
        }

        printf("vm_profile_arr:\n");
        for (vm_index = 0; vm_index < num_vms; vm_index++) {
                vm = &(vm_profile_arr[vm_index]);
                printf("  %u active=%d num_requests=%u\n", vm_index + 1,
                       vm->active, vm->num_requests);

                for (rq = vm->request_list; rq != NULL; rq = rq->next) {
                        if (rq->seqno && rq->gem_ctx) {
                                printf("    seqno=%u gem_ctx=%u retired=%d class=0x%x instance=0x%x\n",
                                       rq->seqno, rq->gem_ctx, rq->retired, (unsigned int) rq->class, (unsigned int) rq->instance);
                        }
                }
        }
}
