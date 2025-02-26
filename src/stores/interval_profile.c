#include <stdbool.h>

#include "iaprof.h"
#include "stores/interval_profile.h"
#include "printers/interval/interval_printer.h"
#include "printers/debug/debug_printer.h"
#include "stores/gpu_kernel_stalls.h"
#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/debug_i915/debug_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"
#include "gpu_parsers/shader_decoder.h"
#include "utils/utils.h"

hash_table(sample_struct, uint64_t) interval_profile;

static uint64_t sample_hash(const struct sample a) {
        uint64_t hash;

        hash = 2654435761ULL;

        hash *= ((uint64_t)a.ustack_str >> 3) * ((uint64_t)a.kstack_str >> 3);

        hash ^= a.pid;
        hash ^= a.is_debug;

        hash ^= ((a.addr + a.offset) >> 3) << a.stall_type;

        hash ^= str_hash(a.insn_text);
        hash ^= str_hash(a.proc_name);

        return hash;
}

/* Returns 0 on success, -1 for failure */
static char get_insn_text(struct buffer_binding *bind, uint64_t offset,
                   char **insn_text, size_t *insn_text_len)
{
        char retval;
        struct shader_binary *bin;

        retval = 0;

        pthread_mutex_lock(&debug_i915_shader_binaries_lock);
        bin = get_shader_binary(bind->gpu_addr);

        if (bin == NULL) {
                if (debug) {
                        WARN("Can't find a shader at 0x%lx\n", bind->gpu_addr);
                }
                retval = -1;
                goto out;
        }

        /* Paranoid check */
        if (offset >= bin->size) {
                if (debug) {
                        WARN("Got an EU stall past the end of a buffer. ");
                        fprintf(stderr, "offset=0x%lx size=%lu\n", offset, bin->size);
                }
                retval = -1;
                goto out;
        }

        /* Initialize the kernel view */
        if (!bind->kv) {
                bind->kv = iga_init(bin->bytes, bin->size);
                if (!bind->kv) {
                        if (debug) {
                                WARN("Failed to initialize IGA.\n");
                        }
                        retval = -1;
                        goto out;
                }
        }

        /* Disassemble */
        retval = iga_disassemble_insn(bind->kv, offset, insn_text,
                                      insn_text_len);
        if (retval != 0) {
                if (debug) {
                        WARN("Disassembly failed on shader at 0x%lx\n", bind->gpu_addr);
                }
                goto out;
        }

out:;
        pthread_mutex_unlock(&debug_i915_shader_binaries_lock);

        return retval;
}

static void update_sample(const struct sample *samp, uint64_t count) {
        uint64_t           *lookup;
        struct sample      samp_copy;

        lookup = hash_table_get_val(interval_profile, *samp);

        if (lookup != NULL) {
                *lookup += count;
        } else {
                memcpy(&samp_copy, samp, sizeof(samp_copy));
                samp_copy.proc_name = strdup(samp_copy.proc_name);
                samp_copy.insn_text = strdup(samp_copy.insn_text);

                hash_table_insert(interval_profile, samp_copy, count);
        }
}

/* Stores a profile for a single kernel */
void store_kernel_profile(struct buffer_binding *bind)
{
        struct sample samp;
        uint64_t offset, addr;
        struct offset_profile *profile;
        char *failed_decode = "[failed_decode]";
        char retval;
        char *insn_text;
        size_t insn_text_len;
        int stall_type;
        uint64_t count;

        memset(&samp, 0, sizeof(samp));

        samp.proc_name   = strdup(bind->name);
        samp.pid         = bind->pid;
        samp.ustack_str  = bind->execbuf_ustack_str;
        samp.kstack_str  = bind->execbuf_kstack_str;
        samp.is_debug    = bind->type == BUFFER_TYPE_DEBUG_AREA;
        samp.is_sys      = bind->type == BUFFER_TYPE_SYSTEM_ROUTINE;

        /* Iterate over the offsets that we have EU stalls for */
        hash_table_traverse(bind->stall_counts, offset, profile) {
                addr = bind->gpu_addr + offset;

                samp.addr = addr;
                samp.offset = offset;

                /* Disassemble to get the instruction */
                insn_text = NULL;
                insn_text_len = 0;
                retval = get_insn_text(bind, offset, &insn_text, &insn_text_len);
                if (retval != 0) {
                        insn_text = failed_decode;
                }

                samp.insn_text = insn_text;

                /* NOTE: We do late symbolization of GPU addresses because we may be slightly behind
                 * collecting ELF info from the debug interface. See print_flamegraph(). */

                for (stall_type = 0; stall_type < NR_STALL_TYPES; stall_type += 1) {
                        samp.stall_type = stall_type;

                        count = profile->counts[stall_type];
                        if (count > 0) {
                                update_sample(&samp, count);
                        }
                }

                if (insn_text != failed_decode) {
                        free(insn_text);
                }
        }

        free(samp.proc_name);
}

void store_interval_profile(uint64_t interval)
{
        struct vm_profile *vm;
        struct buffer_binding *bind;
        
        interval_profile = hash_table_make(sample_struct, uint64_t, sample_hash);
        
        FOR_BINDING(vm, bind, {
                /* Make sure the buffer is a GPU kernel, that we have a valid
                   PID, and that we have a copy of it */
                if (bind->stall_counts == NULL) {
                        goto next;
                }

                store_kernel_profile(bind);

/* Jump here so that the macro releases locks. */
next:;
        });
        
        print_interval(interval);
        
        hash_table_free(interval_profile);
}
