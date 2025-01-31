#include "iaprof.h"

#include "printers/stack/stack_printer.h"
#include "printers/flamegraph/flamegraph_printer.h"
#include "stores/interval_profile.h"
#include "collectors/debug_i915/debug_i915_collector.h"


void print_flamegraph()
{
        struct sample      samp;
        uint64_t           *countp;
        uint64_t            count;
        int                 err;
        char               *gpu_symbol;
        char               *gpu_file;
        int                 gpu_line;
        const char         *ustack_str;
        const char         *kstack_str;
        const char         *stall_type_str;

        hash_table_traverse(interval_profile, samp, countp) {
                count = *countp;

                /* Ensure we've got a GPU symbol */
                err = debug_i915_get_sym(samp.pid, samp.addr, &gpu_symbol, &gpu_file, &gpu_line);
                if (err) {
                        gpu_symbol = NULL;
                        gpu_file   = NULL;
                        gpu_line   = 0;
                }

                printf("%s;", samp.proc_name);
                printf("%u;", samp.pid);

                ustack_str = samp.ustack_str;
                kstack_str = samp.kstack_str;
                if (ustack_str) {
                        printf("%s", ustack_str);
                        if (kstack_str) {
                                printf("%s", kstack_str);
                        }
                } else if (samp.is_debug) {
                        printf("L0 Debugger");
                } else {
                        printf("[unknown];");
                }

                printf("-;");

                if (gpu_file) {
                        printf("%s_[G];", gpu_file);
                } else {
                        printf("[unknown file]_[G];");
                }
                if (gpu_symbol) {
                        if (gpu_line) {
                                printf("%s line %d_[G];", gpu_symbol, gpu_line);
                        } else {
                                printf("%s_[G];", gpu_symbol);
                        }
                } else if (samp.is_sys) {
                        printf("System Routine (Exceptions);");
                } else {
                        printf("0x%lx_[G];", samp.addr);
                }
                if (samp.insn_text) {
                        printf("%s_[g];", samp.insn_text);
                } else {
                        printf("[failed_decode]_[g];");
                }

                switch (samp.stall_type) {
                        case STALL_TYPE_ACTIVE:     stall_type_str = "active";     break;
                        case STALL_TYPE_CONTROL:    stall_type_str = "control";    break;
                        case STALL_TYPE_PIPESTALL:  stall_type_str = "pipestall";  break;
                        case STALL_TYPE_SEND:       stall_type_str = "send";       break;
                        case STALL_TYPE_DIST_ACC:   stall_type_str = "dist_acc";   break;
                        case STALL_TYPE_SBID:       stall_type_str = "sbid";       break;
                        case STALL_TYPE_SYNC:       stall_type_str = "sync";       break;
                        case STALL_TYPE_INST_FETCH: stall_type_str = "inst_fetch"; break;
                        case STALL_TYPE_OTHER:      stall_type_str = "other";      break;
                        default:
                                stall_type_str = "unknown";
                                break;
                }

                printf("%s_[g];", stall_type_str);
                printf("0x%lx_[g] %lu\n", samp.offset, count);
        }
}
