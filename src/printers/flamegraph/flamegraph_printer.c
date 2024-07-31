#include "iaprof.h"

#include "printers/flamegraph/flamegraph_printer.h"
#include "stores/proto_flame.h"
#include "collectors/debug_i915/debug_i915_collector.h"

void print_flamegraph()
{
        char *insn_text;
        struct proto_flame *flame;
        uint64_t index;

        for (index = 0; index < proto_flame_used; index++) {
                flame = &(proto_flame_arr[index]);

                /* Ensure we've got a GPU symbol */
                if (!(flame->gpu_symbol)) {
                        flame->gpu_symbol =
                                debug_i915_get_sym(flame->pid, flame->addr);
                }

                printf("%s;", flame->proc_name);
                printf("%u;", flame->pid);
                if (flame->cpu_stack) {
                        printf("%s", flame->cpu_stack);
                } else {
                        printf("[unknown];");
                }

                printf("-;");
                if (flame->gpu_symbol) {
                        printf("%s_[G];", flame->gpu_symbol);
                } else {
                        printf("[unknown]_[G];");
                }
                if (flame->insn_text) {
                        printf("%s_[g];", flame->insn_text);
                } else {
                        printf("[failed_decode]_[g];");
                }
                printf("%s_[g];", flame->stall_type);
                printf("0x%lx_[g] %lu\n", flame->offset, flame->count);
        }
}
