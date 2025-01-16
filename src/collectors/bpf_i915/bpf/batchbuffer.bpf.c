/***************************************
* BATCHBUFFER
* **********
* Batch buffer detection routine. Uses
* BB command constants defined in
* gpu_parsers/bb_parser_defs.h
***************************************/

#ifdef XE_DRIVER
#include "xe.h"
#else
#include "i915.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "main.h"

static unsigned char cmd_lookup[1<<15] = {
#define ELEM(name, type, opcode, num_dwords) [name] = num_dwords,
        LIST_COMMANDS(ELEM)
#undef ELEM
};

#define BB_SCAN_MAX_DWORDS (16)
/* #define BB_SCAN_MAX_MISSES (4) */

int looks_like_batch_buffer(void *user_addr, u64 size) {
        u32  dwords[BB_SCAN_MAX_DWORDS];
        u32  hit;
/*         u32  miss; */
        u32  lookup;
        u64  i;
        u32  type;
        u16  op;

        if (user_addr == NULL) {
                return 0;
        }

        if (size < (BB_SCAN_MAX_DWORDS * sizeof(u32))) {
                return 0;
        }

        if (bpf_probe_read_user(dwords, sizeof(dwords), user_addr) != 0) {
                return 0;
        }

/*         miss = 0; */
        lookup = 0;
        for (i = 0; i < BB_SCAN_MAX_DWORDS; i += 1) {
                if (lookup) {
                        lookup -= 1;
                        continue;
                }

                type = CMD_TYPE(dwords[i]);

                if (type == CMD_TYPE_UNKNOWN) {
                        return 0;
                }

                op = GET_OPCODE(dwords[i]);

                if (op == NOOP) {
                        return 0;
                }

                if (op == BATCH_BUFFER_START || op == BATCH_BUFFER_END) {
                        /* If this batch is over or jumping somewhere else, there's
                         * likely nothing else to parse. Just accept it. */
                        return 1;
                }

                lookup = cmd_lookup[op];

/*                 DEBUG_PRINTK("dword=%x op=%x", dwords[i], op); */
/*                 DEBUG_PRINTK("lookup=%u", lookup); */

                if (lookup == 0) {
/*                         miss += 1; */
/*                         if (miss > BB_SCAN_MAX_MISSES) { */
                                return 0;
/*                         } */
                } else {
                        lookup -= 1;
                }
        }

        return 1;
}
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

        /* 40 is the maximum number of DWORDS for a single command we've seen (COMPUTE_WALKER).
         * Use this as an upper bound on the number of DWORDS processed per command to reduce
         * verifier work. */
        for (i = 0; i < 40; i += 1) {
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


                if ((op == BATCH_BUFFER_START) && (which_dword == 0)) {
                        cxt->bb2l = MI_BATCH_BUFFER_START_2ND_LEVEL(dword);

                } else if ((op == BATCH_BUFFER_START) && (which_dword == 2)) {
                        if (cxt->stop_addr == 0) {
                                cxt->stop_addr = cur_ip + sizeof(u32);
                        }
                        bbsp = (((u64)dword) << 32) | last_dword;
                        BB_PRINTK("  BBSP: 0x%llx", bbsp);

                        if (bbsp == cxt->stop_addr) {
                                BB_PRINTK("  Jump back to ring. Stopping.");
                                return 1;
                        }

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

                } else if ((op == COMPUTE_WALKER) && (which_dword == 20)) {
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

        BB_PRINTK("BB Parsing @ 0x%llx", cxt.ips[0]);

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
