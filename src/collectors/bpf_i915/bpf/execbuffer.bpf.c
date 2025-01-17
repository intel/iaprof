/***************************************
* EXECBUFFER
* **********
* We need to keep track of which requests are being
* executed, so trace execbuffer calls and send those
* back to userspace.
***************************************/

#include "i915.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

#define BB_DEBUG

#define BB_PRINTK(...) ;

#ifdef DEBUG
#ifdef BB_DEBUG
#undef BB_PRINTK
#define BB_PRINTK(...) DEBUG_PRINTK(__VA_ARGS__)
#endif
#endif

#ifdef BB_DEBUG
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1<<15);
        __type(key, u32);
        __type(value, const char *);
} bb_cmd_names SEC(".maps");
#endif

struct batch_buffer {
        u64 size;
        u64 gpu_base;
        u32 dwords[MAX_BB_DWORDS];
};

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 3);
        __type(key, u32);
        __type(value, struct batch_buffer);
} bb_parse_buffers SEC(".maps");

static unsigned char bb_cmd_lookup[1<<15] = {
#define ELEM(name, type, opcode, num_dwords) [name] = num_dwords,
        LIST_COMMANDS(ELEM)
#undef ELEM
};

struct callback_cxt {
    u64 bbsp;
    u64 gpu_base;
    u64 cpu_base;
    u64 size;
};

static __u64 find_batchbuffer(struct bpf_map *map, struct gpu_mapping *gmapping, struct cpu_mapping *cmapping, struct callback_cxt *cxt) {
        if (gmapping->addr <= cxt->bbsp && cxt->bbsp < gmapping->addr + cmapping->size) {
                cxt->gpu_base = gmapping->addr;
                cxt->cpu_base = cmapping->addr;
                cxt->size     = cmapping->size;
                return 1;
        }
        return 0;
}

struct parse_cxt {
        u32 level;
        u64 ips[4]; /* 4 because we use a bitmask trick to soothe the verifier. Level 4 is not used. */
        u64 stop_addr;
        u8  bb2l;
        u64 iba;
        u64 sip;
        u64 ksp;
};

__attribute__((noinline))
u32 dword_to_op(u32 dword) {
        if (CMD_TYPE(dword) == CMD_TYPE_UNKNOWN) { return 0; }

        return GET_OPCODE(dword);
}

__attribute__((noinline))
u8 op_lookup(u32 op) {
        return bb_cmd_lookup[op & 0x7fff];
}

__attribute__((noinline))
int read_batch_buffer(u64 bbsp, struct batch_buffer *buff) {
        struct callback_cxt data = {
                .bbsp     = bbsp,
                .gpu_base = 0,
                .cpu_base = 0,
                .size     = 0
        };

        if (buff == NULL) { return -1; }

        bpf_for_each_map_elem(&gpu_cpu_map, find_batchbuffer, &data, 0);

        if (data.gpu_base == 0 || data.cpu_base == 0) { return -1; }

        if (data.size > MAX_BB_BYTES) { data.size = MAX_BB_BYTES; }

        bpf_probe_read_user(buff->dwords, data.size, (void*)(data.cpu_base + (bbsp - data.gpu_base)));

        buff->gpu_base = bbsp;

        return 0;
}

__attribute__((noinline))
int parse_next(struct parse_cxt *cxt) {
        u32                   lvl;
        int                   i;
        struct batch_buffer  *buff;
        u8                    to_consume;
        u64                   cur_ip;
        u32                   dword_off;
        u32                   dword;
        u32                   last_dword;
        u32                   op;
        u8                    cmd_len;
        u8                    which_dword;
        u64                   bbsp;
        u64                   size;
#ifdef BB_DEBUG
        const char           *op_name;
        const char          **op_name_lookup;
#endif


        if (cxt == NULL) { return -1; }

        lvl = cxt->level;

        to_consume = 0;
        dword      = 0;
        last_dword = 0;
        op         = 0;

        buff = bpf_map_lookup_elem(&bb_parse_buffers, &lvl);
        if (buff == NULL) { return -1; }

        /* 39 is the maximum number of DWORDS for a single command we've seen (COMPUTE_WALKER).
         * Use this as an upper bound on the number of DWORDS processed per command to reduce
         * verifier work. */
        for (i = 0; i < 39; i += 1) {
                last_dword = dword;

                cur_ip    = cxt->ips[lvl & 3];
                dword_off = (cur_ip - buff->gpu_base) / sizeof(u32);
                if (dword_off > MAX_BB_DWORDS_IDX) {
                        ERR_PRINTK("exceeded the maximum number of DWORDS");
                        return -1;
                }

                dword = buff->dwords[dword_off & MAX_BB_DWORDS_IDX];

                if (to_consume) {
                        BB_PRINTK("BB 0x%llx: . 0x%x", cur_ip, dword);
                } else {
                        op = dword_to_op(dword);

                        to_consume = cmd_len = op_lookup(op);

                        if (cmd_len == 0) {
                                BB_PRINTK("BB 0x%llx: Unknown BB command: dword = 0x%x", cur_ip, dword);
                                return -1;
                        }

#ifdef BB_DEBUG
                        op_name_lookup = bpf_map_lookup_elem(&bb_cmd_names, &op);
                        if (op_name_lookup == NULL) {
                                op_name = "???";
                        } else {
                                op_name = *op_name_lookup;
                        }

                        BB_PRINTK("BB 0x%llx: %s (%u dwords)", cur_ip, op_name, cmd_len);
#endif
                }


                which_dword = cmd_len - to_consume;

                if (op == NOOP) {
                    return 1;
                }


                if ((op == BATCH_BUFFER_START) && (which_dword == 0)) {
                        cxt->bb2l = MI_BATCH_BUFFER_START_2ND_LEVEL(dword);

                } else if ((op == BATCH_BUFFER_START) && (which_dword == 2)) {
                        if (cxt->stop_addr == 0) {
                                cxt->stop_addr = cur_ip + sizeof(u32);
                        }
                        bbsp = (((u64)dword) << 32) | last_dword;
                        BB_PRINTK("  BBSP: 0x%llx", bbsp);

/*                         if (bbsp == cxt->stop_addr) { */
/*                                 BB_PRINTK("  Jump back to ring. Stopping."); */
/*                                 return 1; */
/*                         } */

                        if (!!cxt->bb2l && (lvl < 2)) {
                                cxt->level += 1;
                                lvl = cxt->level;
                        }

                        buff = bpf_map_lookup_elem(&bb_parse_buffers, &lvl);
                        if (buff == NULL) { return -1; }

                        if (read_batch_buffer(bbsp, buff) != 0) {
                                ERR_PRINTK("failed to look up batch buffer address 0x%llx", bbsp);
                                return -1;
                        }

                        cxt->ips[lvl & 3] = bbsp - sizeof(u32); /* Will be advanced back to bbsp at bottom of dword loop. */

                        BB_PRINTK("  Jumping to new buffer.");

                } else if ((op == BATCH_BUFFER_END) && (which_dword == 0)) {
                        if (lvl == 0) { return 1; }
                        cxt->level -= 1;
                        lvl = cxt->level;

                } else if ((op == COMPUTE_WALKER) && (which_dword == 19)) {
                        cxt->ksp = ((((u64)dword) & 0xFFFF) << 32) | (((u64)last_dword) & 0xFFFFFFC0);
                        BB_PRINTK("  KSP: 0x%llx", cxt->ksp);

                } else if ((op == STATE_BASE_ADDRESS) && (which_dword == 11)) {
                        cxt->iba = (((u64)dword) << 32) | (((u64)last_dword) & 0xFFFFF000);
                        BB_PRINTK("  IBA: 0x%llx", cxt->iba);
                }

                cxt->ips[lvl & 3] += sizeof(u32);

                to_consume -= 1;
                if (to_consume == 0) { break; }
        }

        return 0;
}

__u64 counter;

static int parse_batchbuffer(u64 primary_bb_cpu_base, u64 primary_bb_gpu_base, u64 primary_bb_size, u64 initial_ip, struct execbuf_info *info) {
        u64                  size;
        int                  i;
        int                  stop;
        struct batch_buffer *buff;
#ifdef BB_DEBUG
        u32                  op_code;
        const char          *op_name;
#endif


#ifdef BB_DEBUG
#define ELEM(name, type, opcode, num_dwords)                           \
            op_code = name;                                            \
            op_name = #name;                                           \
            bpf_map_update_elem(&bb_cmd_names, &op_code, &op_name, 0);

            LIST_COMMANDS(ELEM)
#undef ELEM
#endif

        size = primary_bb_size;
        if (size > MAX_BB_BYTES) { size = MAX_BB_BYTES; }

        struct parse_cxt cxt = {};
        cxt.ips[0] = initial_ip;

        buff = bpf_map_lookup_elem(&bb_parse_buffers, &cxt.level);
        if (buff == NULL) { return -1; }
        cxt.level = 0; /* Just invalidated. */

        buff->gpu_base = initial_ip;

        bpf_probe_read_user(buff->dwords, size, (void*)(primary_bb_cpu_base + (initial_ip - primary_bb_gpu_base)));

        BB_PRINTK("BB %llu Parsing @ 0x%llx", counter, cxt.ips[0]);
        counter += 1;

        stop = 0;
        for (i = 0; i < MAX_BB_COMMANDS && stop == 0; i += 1) {
                stop = parse_next(&cxt);
        }

        if (stop == 0) {
                ERR_PRINTK("exceeded the maximum number of batch buffer commands");
                return -1;
        } else if (stop < 0) {
                /* Some error condition occurred. */
                return -1;
        }

        info->iba = cxt.iba;
        info->sip = cxt.sip;
        info->ksp = cxt.ksp;

        return 0;
}

SEC("fexit/i915_gem_do_execbuffer")
int BPF_PROG(i915_gem_do_execbuffer,
             struct drm_device *dev,
             struct drm_file *file,
             struct drm_i915_gem_execbuffer2 *args,
             struct drm_i915_gem_exec_object2 *exec)
{
        int err;
        long stack_err;
        u32 cpu, handle, batch_index, batch_start_offset,
                buffer_count;
        u64 cpu_addr, batch_len, offset, size, status,
            file_ptr;
        struct cpu_mapping cmapping = {};
        struct gpu_mapping gmapping = {};
        struct file_ctx_pair pair = {};
        struct execbuf_info *info;

        file_ptr = (u64)file;

        u32 ctx_id, vm_id;
        void *val_ptr;

        DEBUG_PRINTK("execbuffer");

        /* Look up the VM ID based on the context ID (which is in execbuffer->rsvd1) */
        ctx_id = (u32)BPF_CORE_READ(args, rsvd1);
        vm_id = 0;
        if (ctx_id) {
                pair.file = file_ptr;
                pair.ctx_id = ctx_id;
                val_ptr = bpf_map_lookup_elem(&context_create_wait_for_exec,
                                              &pair);
                if (val_ptr) {
                        vm_id = *((u32 *)val_ptr);
                }
        }

        /* Determine where the batchbuffer is stored (and how long it is).
           The index that it's in is determined by a flag -- it can either
           be the first or the last batch. */
        batch_index =
                (BPF_CORE_READ(args, flags) & I915_EXEC_BATCH_FIRST) ?
                        0 :
                        BPF_CORE_READ(args, buffer_count) - 1;
        batch_start_offset = BPF_CORE_READ(args, batch_start_offset);
        batch_len = BPF_CORE_READ(args, batch_len);
        buffer_count = BPF_CORE_READ(args, buffer_count);
        if (batch_index == 0) {
                /* If the index is 0 (the vast majority of the time it is), we can
                   just directly read the `objects` pointer. */
                handle = BPF_CORE_READ(exec, handle);
                offset = BPF_CORE_READ(exec, offset);
        } else {
                handle = 0xffffffff;
                offset = 0xffffffffffffffff;
        }

        /* Find a possible CPU mapping for the primary batchbuffer.
           If we can, go ahead and grab a copy of it! */
        gmapping.vm_id = vm_id;
        gmapping.addr = offset;
        gmapping.file = file_ptr;
        val_ptr = bpf_map_lookup_elem(&gpu_cpu_map, &gmapping);
        if (val_ptr) {
                __builtin_memcpy(&cmapping, val_ptr,
                                 sizeof(struct cpu_mapping));
                cpu_addr = cmapping.addr;
                size = cmapping.size;
        } else {
                WARN_PRINTK("execbuffer couldn't find a CPU mapping for vm_id=%u gpu_addr=0x%lx ctx_id=%u",
                           vm_id, offset, ctx_id);
                return 0;
        }


        DEBUG_PRINTK("execbuffer batchbuffer cpu_addr=0x%lx gpu_addr=0x%lx size=%lu", cpu_addr, offset, size);

        info = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_info), 0);
        if (!info) {
                ERR_PRINTK("execbuffer failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 0;
        }

        info->type = BPF_EVENT_TYPE_EXECBUF;

        info->vm_id = vm_id;
        info->file  = file_ptr;
        info->pid   = bpf_get_current_pid_tgid() >> 32;
        info->tid   = bpf_get_current_pid_tgid();
        info->cpu   = bpf_get_smp_processor_id();
        info->time  = bpf_ktime_get_ns();
        bpf_get_current_comm(info->name, sizeof(info->name));

        stack_err = bpf_get_stack(ctx, &(info->kstack.addrs), sizeof(info->kstack.addrs), 3 & BPF_F_SKIP_FIELD_MASK);
        if (stack_err < 0) {
                WARN_PRINTK("execbuffer failed to get a kernel stack: %ld", stack_err);
        }
        stack_err = bpf_get_stack(ctx, &(info->ustack.addrs), sizeof(info->ustack.addrs), BPF_F_USER_STACK);
        if (stack_err < 0) {
                WARN_PRINTK("execbuffer failed to get a user stack: %ld", stack_err);
        }

        if (parse_batchbuffer(cpu_addr, offset, size, offset + batch_start_offset, info) == 0) {
                if (info->iba || info->ksp || info->sip) {
                        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
                } else {
                        bpf_ringbuf_discard(info, 0);
                }
        } else {
                bpf_ringbuf_discard(info, 0);
                ERR_PRINTK("failure in batch buffer parsing");
                dropped_event = 1;
        }

        return 0;
}
