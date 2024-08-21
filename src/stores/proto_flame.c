#include "iaprof.h"

#include "proto_flame.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/debug_i915/debug_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

pthread_rwlock_t proto_flame_lock = PTHREAD_RWLOCK_INITIALIZER;
struct proto_flame *proto_flame_arr = NULL;
size_t proto_flame_size = 0, proto_flame_used = 0;

/* Ensure we have enough room for another proto-flame. */
uint64_t grow_proto_flames()
{
        size_t old_size;

        /* Ensure there's enough room in the array */
        if (proto_flame_size == proto_flame_used) {
                /* Not enough room in the array */
                old_size = proto_flame_size;

                proto_flame_size += 64;

                proto_flame_arr =
                        realloc(proto_flame_arr,
                                proto_flame_size * sizeof(struct proto_flame));

                memset(proto_flame_arr + proto_flame_used, 0,
                       (proto_flame_size - old_size) *
                               sizeof(struct proto_flame));
        }

        proto_flame_used++;
        return proto_flame_used - 1;
}
void store_cpu_side(uint64_t index, struct buffer_profile *gem)
{
        proto_flame_arr[index].proc_name = strdup(gem->name);
        proto_flame_arr[index].pid = gem->pid;
        if (gem->execbuf_stack_str) {
                proto_flame_arr[index].cpu_stack =
                        strdup(gem->execbuf_stack_str);
        } else {
                proto_flame_arr[index].cpu_stack = NULL;
        }
}

/* Returns 0 on success, -1 for failure */
char get_insn_text(struct buffer_profile *gem, uint64_t offset,
                   char **insn_text, size_t *insn_text_len)
{
        char retval;

        /* If we don't have a copy, can't disassemble it! */
        if (!(gem->buff_sz)) {
                if (debug) {
                        fprintf(stderr,
                                "WARNING: Don't have a copy of vm_id=%u, gpu_addr=0x%lx so can't decode.\n",
                                gem->vm_id, gem->gpu_addr);
                }
                return -1;
        }

        /* Paranoid check */
        if (offset >= gem->buff_sz) {
                if (debug) {
                        fprintf(stderr,
                                "WARNING: Got an EU stall past the end of a buffer. ");
                        fprintf(stderr,
                                "vm_id=%u gpu_addr=0x%lx offset=0x%lx buff_sz=%lu\n",
                                gem->vm_id, gem->gpu_addr, offset, gem->buff_sz);
                }
                return -1;
        }

        /* Initialize the kernel view */
        if (!gem->kv) {
                gem->kv = iga_init(gem->buff, gem->buff_sz);
                if (!gem->kv) {
                        if (debug) {
                                fprintf(stderr,
                                        "WARNING: Failed to initialize IGA.\n");
                        }
                        return -1;
                }
        }

        /* Disassemble */
        retval = iga_disassemble_insn(gem->kv, offset, insn_text,
                                      insn_text_len);
        if (retval != 0) {
                if (debug) {
                        fprintf(stderr, "WARNING: Disassembly failed on vm_id=%u, gpu_addr=0x%lx\n", gem->vm_id, gem->gpu_addr);
                }
                return -1;
        }

        return 0;
}

void store_gpu_side(uint64_t index, char *stall_type, uint64_t count,
                    uint64_t addr, uint64_t offset, char *insn_text)
{
        proto_flame_arr[index].stall_type = strdup(stall_type);
        proto_flame_arr[index].addr = addr;
        proto_flame_arr[index].offset = offset;
        proto_flame_arr[index].count = count;
        proto_flame_arr[index].insn_text = strdup(insn_text);
        proto_flame_arr[index].gpu_symbol = NULL;
}

/* Prints the flamegraph for a single kernel */
void store_kernel_flames(struct buffer_profile *gem)
{
        uint64_t offset, *tmp, addr, index;
        struct offset_profile **found;
        char *failed_decode = "[failed_decode]";
        char retval;
        char *insn_text;
        size_t insn_text_len;

        if (debug) {
                debug_printf("storing flamegraph for vm_id=%u gpu_addr=0x%lx pid=%d\n", gem->vm_id, gem->gpu_addr,
                       gem->pid);
        }

        /* Iterate over the offsets that we have EU stalls for */
        hash_table_traverse(gem->stall_counts, offset, tmp)
        {
                found = (struct offset_profile **)tmp;

                /* Disassemble to get the instruction */
                insn_text = NULL;
                insn_text_len = 0;
                retval = get_insn_text(gem, offset, &insn_text, &insn_text_len);
                if (retval != 0) {
                        insn_text = failed_decode;
                }

                addr = gem->gpu_addr + offset;

                if ((*found)->active) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "active", (*found)->active, addr,
                                       offset, insn_text);
                }
                if ((*found)->other) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "other", (*found)->other, addr,
                                       offset, insn_text);
                }
                if ((*found)->control) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "control", (*found)->control,
                                       addr, offset, insn_text);
                }
                if ((*found)->pipestall) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "pipestall", (*found)->pipestall,
                                       addr, offset, insn_text);
                }
                if ((*found)->send) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "send", (*found)->send, addr,
                                       offset, insn_text);
                }
                if ((*found)->dist_acc) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "dist_acc", (*found)->dist_acc,
                                       addr, offset, insn_text);
                }
                if ((*found)->sbid) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "sbid", (*found)->sbid, addr,
                                       offset, insn_text);
                }
                if ((*found)->sync) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "sync", (*found)->sync, addr,
                                       offset, insn_text);
                }
                if ((*found)->inst_fetch) {
                        index = grow_proto_flames();
                        store_cpu_side(index, gem);
                        store_gpu_side(index, "inst_fetch",
                                       (*found)->inst_fetch, addr, offset,
                                       insn_text);
                }

                if (insn_text != failed_decode) {
                        free(insn_text);
                }
        }
}

void store_interval_flames()
{
        struct vm_profile *vm;
        struct buffer_profile *gem;

        FOR_BUFFER_PROFILE(vm, gem, {
                /* Make sure the buffer is a GPU kernel, that we have a valid
                   PID, and that we have a copy of it */
                if (gem->stall_counts == NULL) {
                        goto next;
                }

                store_kernel_flames(gem);

/* Jump here so that the macro releases locks. */
next:;
        });
}
