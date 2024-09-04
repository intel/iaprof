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
void store_cpu_side(uint64_t index, struct buffer_binding *bind)
{
        proto_flame_arr[index].proc_name = strdup(bind->name);
        proto_flame_arr[index].pid = bind->pid;
        if (bind->execbuf_stack_str) {
                proto_flame_arr[index].cpu_stack =
                        strdup(bind->execbuf_stack_str);
        } else {
                proto_flame_arr[index].cpu_stack = NULL;
        }
}

/* Returns 0 on success, -1 for failure */
char get_insn_text(struct buffer_binding *bind, uint64_t offset,
                   char **insn_text, size_t *insn_text_len)
{
        char retval;
        struct buffer_object *bo;

        retval = 0;

        bo = acquire_buffer(bind->file, bind->handle);

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
        release_buffer(bo);

        return retval;
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
void store_kernel_flames(struct buffer_binding *bind)
{
        uint64_t offset, *tmp, addr, index;
        struct offset_profile **found;
        char *failed_decode = "[failed_decode]";
        char retval;
        char *insn_text;
        size_t insn_text_len;

        if (debug) {
                debug_printf("storing flamegraph for vm_id=%u gpu_addr=0x%lx pid=%d\n", bind->vm_id, bind->gpu_addr,
                       bind->pid);
        }

        /* Iterate over the offsets that we have EU stalls for */
        hash_table_traverse(bind->stall_counts, offset, tmp)
        {
                found = (struct offset_profile **)tmp;

                /* Disassemble to get the instruction */
                insn_text = NULL;
                insn_text_len = 0;
                retval = get_insn_text(bind, offset, &insn_text, &insn_text_len);
                if (retval != 0) {
                        insn_text = failed_decode;
                }

                addr = bind->gpu_addr + offset;

                if ((*found)->active) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
                        store_gpu_side(index, "active", (*found)->active, addr,
                                       offset, insn_text);
                }
                if ((*found)->other) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
                        store_gpu_side(index, "other", (*found)->other, addr,
                                       offset, insn_text);
                }
                if ((*found)->control) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
                        store_gpu_side(index, "control", (*found)->control,
                                       addr, offset, insn_text);
                }
                if ((*found)->pipestall) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
                        store_gpu_side(index, "pipestall", (*found)->pipestall,
                                       addr, offset, insn_text);
                }
                if ((*found)->send) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
                        store_gpu_side(index, "send", (*found)->send, addr,
                                       offset, insn_text);
                }
                if ((*found)->dist_acc) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
                        store_gpu_side(index, "dist_acc", (*found)->dist_acc,
                                       addr, offset, insn_text);
                }
                if ((*found)->sbid) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
                        store_gpu_side(index, "sbid", (*found)->sbid, addr,
                                       offset, insn_text);
                }
                if ((*found)->sync) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
                        store_gpu_side(index, "sync", (*found)->sync, addr,
                                       offset, insn_text);
                }
                if ((*found)->inst_fetch) {
                        index = grow_proto_flames();
                        store_cpu_side(index, bind);
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
