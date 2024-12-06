#include "iaprof.h"

#include "proto_flame.h"

#include "stores/buffer_profile.h"
#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/debug_i915/debug_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "utils/utils.h"

hash_table(proto_flame_struct, uint64_t) flame_samples;

static uint64_t proto_flame_hash(const struct proto_flame a) {
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

void init_flames() {
        flame_samples = hash_table_make(proto_flame_struct, uint64_t, proto_flame_hash);
}


/* Returns 0 on success, -1 for failure */
static char get_insn_text(struct buffer_binding *bind, uint64_t offset,
                   char **insn_text, size_t *insn_text_len)
{
        char retval;
        struct buffer_object *bo;

        retval = 0;

        bo = acquire_buffer(bind->file, bind->handle);

        if (!bo) {
                if (debug) {
                        fprintf(stderr, "WARNING: Can't find a BO for file=0x%lx handle=%u\n",
                                bind->file, bind->handle);
                }
                retval = -1;
                goto out;
        }

        /* If we don't have a copy, can't disassemble it! */
        if (!(bo->buff_sz)) {
                if (debug) {
                        fprintf(stderr,
                                "WARNING: Don't have a copy of vm_id=%u gpu_addr=0x%lx so can't decode.\n",
                                bind->vm_id, bind->gpu_addr);
                }
                retval = -1;
                goto out;
        }

        /* Paranoid check */
        if (offset >= bo->buff_sz) {
                if (debug) {
                        fprintf(stderr,
                                "WARNING: Got an EU stall past the end of a buffer. ");
                        fprintf(stderr,
                                "file=0x%lx handle=%u offset=0x%lx buff_sz=%lu\n",
                                bo->file, bo->handle, offset, bo->buff_sz);
                }
                retval = -1;
                goto out;
        }

        /* Initialize the kernel view */
        if (!bind->kv) {
                bind->kv = iga_init(bo->buff, bo->buff_sz);
                if (!bind->kv) {
                        if (debug) {
                                fprintf(stderr,
                                        "WARNING: Failed to initialize IGA.\n");
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
                        fprintf(stderr, "WARNING: Disassembly failed on file=0x%lx handle=%u\n", bo->file, bo->handle);
                }
                goto out;
        }

out:;
        if (bo != NULL) {
                release_buffer(bo);
        }

        return retval;
}

static void update_flame(const struct proto_flame *flame, uint64_t count) {
        uint64_t           *lookup;
        struct proto_flame  flame_copy;

        lookup = hash_table_get_val(flame_samples, *flame);

        if (lookup != NULL) {
                *lookup += count;
        } else {
                memcpy(&flame_copy, flame, sizeof(flame_copy));
                flame_copy.proc_name = strdup(flame_copy.proc_name);
                flame_copy.insn_text = strdup(flame_copy.insn_text);

                hash_table_insert(flame_samples, flame_copy, count);
        }
}

/* Prints the flamegraph for a single kernel */
void store_kernel_flames(struct buffer_binding *bind)
{
        struct proto_flame flame;
        uint64_t offset, addr;
        struct offset_profile *profile;
        char *failed_decode = "[failed_decode]";
        char retval;
        char *insn_text;
        size_t insn_text_len;
        int stall_type;
        uint64_t count;

        if (debug) {
                debug_printf("storing flamegraph for vm_id=%u gpu_addr=0x%lx pid=%d\n", bind->vm_id, bind->gpu_addr,
                       bind->pid);
        }

        memset(&flame, 0, sizeof(flame));

        flame.proc_name  = strdup(bind->name);
        flame.pid        = bind->pid;
        flame.ustack_str = bind->execbuf_ustack_str;
        flame.kstack_str = bind->execbuf_kstack_str;
        flame.is_debug   = bind->type == BUFFER_TYPE_DEBUG_AREA;
        flame.is_sys     = bind->type == BUFFER_TYPE_SYSTEM_ROUTINE;

        /* Iterate over the offsets that we have EU stalls for */
        hash_table_traverse(bind->stall_counts, offset, profile) {
                addr = bind->gpu_addr + offset;

                flame.addr = addr;
                flame.offset = offset;

                /* Disassemble to get the instruction */
                insn_text = NULL;
                insn_text_len = 0;
                retval = get_insn_text(bind, offset, &insn_text, &insn_text_len);
                if (retval != 0) {
                        insn_text = failed_decode;
                }

                flame.insn_text = insn_text;

                /* NOTE: We do late symbolization of GPU addresses because we may be slightly behind
                 * collecting collecting ELF info from the debug interface. See print_flamegraph(). */

                for (stall_type = 0; stall_type < NR_STALL_TYPES; stall_type += 1) {
                        flame.stall_type = stall_type;

                        count = profile->counts[stall_type];
                        if (count > 0) {
                                update_flame(&flame, count);
                        }
                }

                if (insn_text != failed_decode) {
                        free(insn_text);
                }
        }

        free(flame.proc_name);
}

void store_interval_flames()
{
        struct vm_profile *vm;
        struct buffer_binding *bind;

        FOR_BINDING(vm, bind, {
                /* Make sure the buffer is a GPU kernel, that we have a valid
                   PID, and that we have a copy of it */
                if (bind->stall_counts == NULL) {
                        goto next;
                }

                store_kernel_flames(bind);

/* Jump here so that the macro releases locks. */
next:;
        });
}
