#include "iaprof.h"

#include "printers/stack/stack_printer.h"
#include "printers/flamegraph/flamegraph_printer.h"
#include "stores/interval_profile.h"
#include "collectors/debug_i915/debug_i915_collector.h"

void print_stack(uint64_t key, const char *stack_str,
                 const struct stack *stack, int last_index)
{
        int i;
  
        printf("stack 0x%lx ", key);
        if (last_index == -1) {
                printf("0x0;");
        } else {
                for (i = last_index; i >= 0; i--) {
                        printf("0x%llx;", stack->addrs[i]);
                }
        }
        printf(" %s\n", stack_str);
}

void print_sample(struct sample *samp, uint64_t *countp)
{
        char               *gpu_symbol;
        char               *gpu_file;
        int                 gpu_line;
        int                 err;
        const char         *stall_type_str;
        
        /* Ensure we've got a GPU symbol */
        err = debug_i915_get_sym(samp->pid, samp->addr, &gpu_symbol, &gpu_file, &gpu_line);
        if (err) {
                gpu_symbol = NULL;
                gpu_file   = NULL;
                gpu_line   = 0;
        }

        printf("eustall\t");
        printf("%s\t", samp->proc_name);
        printf("%u\t", samp->pid);
        printf("0x%lx\t", samp->ustack_hash);
        printf("0x%lx\t", samp->kstack_hash);
        
        printf("%d\t", samp->is_debug);
        printf("%d\t", samp->is_sys);

        if (gpu_file) {
                printf("%s_[G]\t", gpu_file);
        } else {
                printf("[unknown file]_[G]\t");
        }
        
        if (gpu_symbol) {
                if (gpu_line) {
                        printf("%s line %d_[G]\t", gpu_symbol, gpu_line);
                } else {
                        printf("%s_[G]\t", gpu_symbol);
                }
        } else if (samp->is_sys) {
                printf("System Routine (Exceptions)\t");
        } else {
                printf("0x%lx_[G]\t", samp->addr);
        }
        
        if (samp->insn_text) {
                printf("%s_[g]\t", samp->insn_text);
        } else {
                printf("[failed_decode]_[g]\t");
        }

        switch (samp->stall_type) {
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
        printf("%s_[g]\t", stall_type_str);
        printf("0x%lx_[g]\t", samp->offset);
        printf("%lu\n", *countp);
}

void print_interval(uint64_t interval)
{
        struct sample      samp;
        uint64_t           *countp;
        
        printf("interval_start %lu\n", interval);

        hash_table_traverse(interval_profile, samp, countp) {
                print_sample(&samp, countp);
        }
        
        printf("interval_end %lu\n", interval);
}
