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
        struct buffer_profile *gem;

        if (!debug) {
                return;
        }

        printf("buffer_profiles\n");

        /* Iterate over each buffer */
        FOR_BUFFER_PROFILE(gem, {
                print_debug_buffer_profile(gem);
        });
}

void print_vms()
{
        uint64_t vm_id;
        struct vm_profile **vmp;
        struct vm_profile *vm;
        struct request_profile_list *rq;

        if (!debug) {
                return;
        }

        printf("vm_profile_arr:\n");

        hash_table_traverse(vm_profiles, vm_id, vmp) {
                vm = *vmp;

                printf("  vm_id=%lu active=%d num_requests=%u\n", vm_id,
                       vm->active, vm->num_requests);

                for (rq = vm->request_list; rq != NULL; rq = rq->next) {
                        if (rq->seqno && rq->gem_ctx) {
                                printf("    seqno=%u gem_ctx=%u retired=%d class=0x%x instance=0x%x\n",
                                       rq->seqno, rq->gem_ctx, rq->retired, (unsigned int) rq->class, (unsigned int) rq->instance);
                        }
                }
        }
}
