#include "iaprof.h"

#include "printers/flamegraph/flamegraph_printer.h"
#include "stores/proto_flame.h"
#include "collectors/debug_i915/debug_i915_collector.h"

void print_flamegraph()
{
        struct proto_flame *flame;
        int err;
        uint64_t index;

        for (index = 0; index < proto_flame_used; index++) {
                flame = &(proto_flame_arr[index]);

                /* Ensure we've got a GPU symbol */
                if (!(flame->gpu_symbol)) {
                        err = debug_i915_get_sym(flame->pid, flame->addr, &flame->gpu_symbol, &flame->gpu_file, &flame->gpu_line);
                        if (err) {
                                flame->gpu_symbol = NULL;
                                flame->gpu_file   = NULL;
                                flame->gpu_line   = 0;
                        }
                }

                printf("%s;", flame->proc_name);
                printf("%u;", flame->pid);
                if (flame->cpu_stack) {
                        printf("%s", flame->cpu_stack);
                } else {
                        printf("[unknown];");
                }

                printf("-;");
                if (flame->gpu_file) {
                        printf("%s_[G];", flame->gpu_file);
                } else {
                        printf("[unknown file]_[G];");
                }
                if (flame->gpu_symbol) {
                        if (flame->gpu_line) {
                                printf("%s line %d_[G];", flame->gpu_symbol, flame->gpu_line);
                        } else {
                                printf("%s_[G];", flame->gpu_symbol);
                        }
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
