#include "iaprof.h"

#include "printers/flamegraph/flamegraph_printer.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/debug_i915/debug_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

/* Macro to print a flamegraph line */
#define PRINT_FRONT_STACK()                           \
	printf("%s;", gem->exec_info.name);           \
	printf("%u;", gem->exec_info.pid);            \
	if (gem->execbuf_stack_str) {                 \
                printf("%s", gem->execbuf_stack_str);\
	} else {                                      \
		printf("[unknown];");                 \
	}                                             \
	printf("-;");                                 \
        printf("%s;", tmp_gpu_symbol);                \
	printf("%s_[g];", tmp_insn_text);

/* Returns 0 on success, -1 for failure */
char get_insn_text(struct buffer_profile *gem, uint64_t offset, char **insn_text, size_t *insn_text_len)
{
        uint32_t opcode;
        char retval;
        
        if (!(gem->buff_sz) || !(gem->buff)) {
                return -1;
        }
        
	if (offset > gem->buff_sz) {
		if (debug) {
			fprintf(stderr,
				"WARNING: Got an EU stall past the end of a buffer. ");
			fprintf(stderr,
				"handle=%u cpu_addr=%p offset=0x%lx buff_sz=%lu\n",
				gem->mapping_info.handle,
				gem->buff, offset,
				gem->buff_sz);
		}
                return -1;
	} else {
                if (!gem->kv) {
                        gem->kv = iga_init(gem->buff, gem->buff_sz);
                        if (!gem->kv) {
                                if (debug) {
                                        fprintf(stderr, "ERROR: Failed to initialize IGA.\n");
                                }
                                return -1;
                        }
                }
                retval = iga_disassemble_insn(gem->kv, offset, insn_text, insn_text_len);
                if (retval != 0) {
                        return -1;
                }
                return 0;
	}

        return -1;
}

/* Prints the flamegraph for a single kernel */
void print_kernel_flamegraph(struct buffer_profile *gem, char **insn_text, size_t *insn_text_len)
{
        int n;
        uint64_t offset, *tmp, addr;
        struct offset_profile **found;
        char *failed_decode = "[failed_decode]";
        char *failed_gpu_symbols = "[failed gpu symbols]";
        char retval;
        char *tmp_insn_text, *tmp_gpu_symbol;
        
        printf("flamegraph for handle=%u pid=%d\n", gem->handle, gem->exec_info.pid);
        
        /* Iterate over the offsets that we have EU stalls for */
	hash_table_traverse(gem->shader_profile.counts, offset, tmp) {
		found = (struct offset_profile **) tmp;

                /* Get the GPU symbol, if available */
                if (gem->exec_info.pid) {
                        addr = gem->vm_bind_info.gpu_addr + offset;
                        tmp_gpu_symbol = debug_i915_get_sym(gem->exec_info.pid, addr);
                } else {
                        tmp_gpu_symbol = failed_gpu_symbols;
                }

                /* Disassemble to get the instruction */
                retval = get_insn_text(gem, offset, insn_text, insn_text_len);
                if (retval != 0) {
                        tmp_insn_text = failed_decode;
                } else {
                        tmp_insn_text = *insn_text;
                }

		if ((*found)->active) {
			PRINT_FRONT_STACK();
			printf("active_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->active);
		}
		if ((*found)->other) {
			PRINT_FRONT_STACK();
			printf("other_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->other);
		}
		if ((*found)->control) {
			PRINT_FRONT_STACK();
			printf("control_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->control);
		}
		if ((*found)->pipestall) {
			PRINT_FRONT_STACK();
			printf("pipestall_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->pipestall);
		}
		if ((*found)->send) {
			PRINT_FRONT_STACK();
			printf("send_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->send);
		}
		if ((*found)->dist_acc) {
			PRINT_FRONT_STACK();
			printf("dist_acc_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->dist_acc);
		}
		if ((*found)->sbid) {
			PRINT_FRONT_STACK();
			printf("sbid_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->sbid);
		}
		if ((*found)->sync) {
			PRINT_FRONT_STACK();
			printf("sync_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->sync);
		}
		if ((*found)->inst_fetch) {
			PRINT_FRONT_STACK();
			printf("inst_fetch_[g];");
			printf("0x%lx_[g] %u\n", offset,
			       (*found)->inst_fetch);
		}
	}
}

/* Prints a flamegraph for everything we've collected */
void print_flamegraph()
{
        int i;
        struct buffer_profile *gem;
        struct offset_profile **found;
        uint64_t tmp_offset, *tmp;
        
        /* For storing the mnemonic and the string's length */
        char *insn_text = 0;
        size_t insn_text_len = 0;
        
        /* Iterate over each buffer */
	for (i = 0; i < buffer_profile_used; i++) {
		gem = &buffer_profile_arr[i];

                /* Make sure the buffer is a GPU kernel, that we have a valid
                   PID, and that we have a copy of it */
		if (!gem->has_stalls)
			continue;
		if ((gem->exec_info.pid == 0) && debug) {
			fprintf(stderr, "WARNING: PID for handle %u is zero!\n",
				gem->handle);
		}
		if ((!gem->buff_sz) || (!gem->buff)) {
			if (debug) {
				fprintf(stderr,
					"WARNING: Got an EU stall on a buffer");
                                fprintf(stderr, " we haven't copied yet. handle=%u\n",
					gem->handle);
			}
		}

                print_kernel_flamegraph(gem, &insn_text, &insn_text_len);
	}
        
}
