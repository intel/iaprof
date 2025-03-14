/***************************************
* BATCHBUFFER
* **********
* Batch buffer detection routine. Uses
* BB command constants defined in
* gpu_parsers/bb_parser_defs.h
***************************************/
#pragma once


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
        __uint(max_entries, 1);
        __type(key, u32);
        __type(value, const char *);
} bb_cmd_name SEC(".maps");

#define ELEM(name, type, opcode, num_dwords) const char op_name_##name[] = #name;
        LIST_COMMANDS(ELEM)
#undef ELEM
const char op_name_unknown[] = "???";


__attribute__((noinline))
int install_op_name(u16 op) {
        const char *addr = NULL;
        u32         zero = 0;

        switch (op) {

#define ELEM(name, type, opcode, num_dwords) case opcode: addr = op_name_##name; break;
        LIST_COMMANDS(ELEM)
#undef ELEM

                default:
                        addr = op_name_unknown;
                        break;
        }

        bpf_map_update_elem(&bb_cmd_name, &zero, &addr, 0);

        return 0;
}

#define OP_NAME(_op) ({                                                 \
        install_op_name(_op);                                           \
        u32 zero = 0;                                                   \
        const char **lookup = bpf_map_lookup_elem(&bb_cmd_name, &zero); \
        lookup == NULL ? NULL : *lookup;                                \
})
#endif

struct batch_buffer {
        u64 cpu_base;
        u64 gpu_base;
        u32 dwords[MAX_BB_DWORDS];
};

struct address_range {
        u64 start;
        u64 end;
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
};

static __u64 _find_batchbuffer(struct bpf_map *map, struct gpu_mapping *gmapping, struct cpu_mapping *cmapping, struct callback_cxt *cxt) {
        if (gmapping->addr <= cxt->bbsp && cxt->bbsp < gmapping->addr + cmapping->size) {
                cxt->gpu_base = gmapping->addr;
                cxt->cpu_base = cmapping->addr;
                return 1;
        }
        return 0;
}

struct parse_cxt {
        u64 eb_id;
        u64 ips[4]; /* 4 because we use a bitmask trick to soothe the verifier. Level 4 is not used. */
        u64 cpu_ips[4];
        u64 iba;
        u64 sip;
        u8  level;
        u8  attempts;
        u8  bb2l;
        u8  has_ksps;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_BB_DEFERRED);
        __type(key, u64);
        __type(value, struct parse_cxt);
} deferred_parse SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_BB_DEFERRED);
        __type(key, u64);
        __type(value, struct parse_cxt);
} tmp_deffered_add SEC(".maps");

#ifdef BB_DEBUG
static int n_deferred;
#endif

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
        __uint(max_entries, MAX_BB_KSP);
        __type(key, u64);
        __type(value, char);
} bb_ksps SEC(".maps");


static __u64 _clear_one_ksp(struct bpf_map *map, u64 *key, char *val, void *cxt) {
        (void)cxt;
        bpf_map_delete_elem(map, key);
        return 0;
}

static void clear_ksps(void) {
        bpf_for_each_map_elem(&bb_ksps, _clear_one_ksp, NULL, 0);
}

static __u64 _send_ksp(struct bpf_map *map, u64 *key, char *val, u64 *eb_id) {
        struct ksp_info *ksp_info;
        u64              status;

        ksp_info = bpf_ringbuf_reserve(&rb, sizeof(struct ksp_info), 0);
        if (!ksp_info) {
                ERR_PRINTK("_send_ksp failed to reserve in the ringbuffer.");
                status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", status);
                dropped_event = 1;
                return 1;
        }
        ksp_info->type  = BPF_EVENT_TYPE_KSP;
        ksp_info->eb_id = *eb_id;
        ksp_info->addr  = *key;
        bpf_ringbuf_submit(ksp_info, BPF_RB_FORCE_WAKEUP);

        return 0;
}

static void send_ksps(struct parse_cxt *cxt) {
        u64 eb_id;

        eb_id = cxt->eb_id;
        bpf_for_each_map_elem(&bb_ksps, _send_ksp, &eb_id, 0);
}


__attribute__((noinline))
u32 dword_to_op(u32 dword) {
        if (CMD_TYPE(dword) == CMD_TYPE_UNKNOWN) { return 0; }

        return GET_OPCODE(dword);
}


/* Returns the length of a command. In the case of a few commands,
   can be based on the value of some bits in the dword. */
__attribute__((noinline))
u8 command_len(u32 op, u32 dword) {
#if PLATFORM_HAS_MI_MATH
        if (op == MATH) {
                return dword & 7;
        }
#endif
#if PLATFORM_HAS_3DSTATE_CONSTANT_ALL
        if (op == _3DSTATE_CONSTANT_ALL) {
                return ((dword & 0xff) + 2);
        }
#endif
#if PLATFORM_HAS_3DSTATE_VERTEX_BUFFERS
        if (op == _3DSTATE_VERTEX_BUFFERS) {
                return ((dword & 0xff) + 2);
        }
#endif
#if PLATFORM_HAS_3DSTATE_VERTEX_ELEMENTS
        if (op == _3DSTATE_VERTEX_ELEMENTS) {
                return ((dword & 0xff) + 2);
        }
#endif
#if PLATFORM_HAS_3DPRIMITIVE
        if (op == _3DPRIMITIVE) {
                return ((dword & 0xff) + 2);
        }
#endif
#if PLATFORM_HAS_3DSTATE_BTD
        if (op == _3DSTATE_BTD) {
                return ((dword & 0xff) + 2);
        }
#endif
        if (op == LOAD_REGISTER_IMM) {
                return ((dword & 0xff) + 2);
        }
        
        return bb_cmd_lookup[op & 0x7fff];
}
#define COMMAND_LEN(_op, _dword) command_len((_op), (_dword))

__attribute__((noinline))
int read_batch_buffer(u64 bbsp, struct batch_buffer *buff) {
        struct callback_cxt data = {
                .bbsp     = bbsp,
                .gpu_base = 0,
                .cpu_base = 0,
        };

        if (buff == NULL) { return -1; }

        bpf_for_each_map_elem(&gpu_cpu_map, _find_batchbuffer, &data, 0);

        if (data.gpu_base == 0 || data.cpu_base == 0) { return -1; }

        buff->cpu_base = data.cpu_base + (bbsp - data.gpu_base);

        bpf_probe_read_user(buff->dwords, MAX_BB_BYTES, (void*)buff->cpu_base);

        buff->gpu_base = bbsp;

        return 0;
}


#define BB_STOP      (1)
#define BB_TRY_AGAIN (2)

#define BB_BUFF_CONTAINS_IP(_buff, _ip)                                                        \
        (  (_buff)->gpu_base <= (_ip)                                                          \
        && (_ip) < ((_buff)->gpu_base + MAX_BB_BYTES)                                          \
        && (_buff)->dwords[(((_ip) - buff->gpu_base) / sizeof(u32)) & MAX_BB_DWORDS_IDX] != 0) /* If it's a NOOP, don't reuse. */

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
        u32                   b;
        u32                   bi;
        struct batch_buffer  *other_buff;
        u64                   ksp;
        char                  one = 1;

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

                cur_ip = cxt->ips[lvl & 3];

                dword_off = (cur_ip - buff->gpu_base) / sizeof(u32);
                if (dword_off > MAX_BB_DWORDS_IDX) {
                        buff->gpu_base = cur_ip;
                        buff->cpu_base = cxt->cpu_ips[lvl & 3];

                        if (buff->cpu_base != 0) {
                                bpf_probe_read_user(buff->dwords, MAX_BB_BYTES, (void*)buff->cpu_base);
                        }

                        dword_off = 0;
                }

                dword = buff->dwords[dword_off & MAX_BB_DWORDS_IDX];

                if (to_consume) {
                        BB_PRINTK("BB 0x%llx: . 0x%x", cur_ip, dword);
                } else {
                        op = dword_to_op(dword);

                        to_consume = cmd_len = COMMAND_LEN(op, dword);

                        if (cmd_len == 0) {
                                ERR_PRINTK("BB 0x%llx: Unknown BB command: dword = 0x%x", cur_ip, dword);
                                return -1;
                        }

                        BB_PRINTK("BB 0x%llx: %s (%u dwords)", cur_ip, OP_NAME(op), cmd_len);
                }


                which_dword = cmd_len - to_consume;


                if (op == NOOP) {
                        return BB_TRY_AGAIN;
                }


                if ((op == BATCH_BUFFER_START) && (which_dword == 0)) {
                        cxt->bb2l = MI_BATCH_BUFFER_START_2ND_LEVEL(dword);

                } else if ((op == BATCH_BUFFER_START) && (which_dword == 2)) {
                        bbsp = (((u64)dword & 0xffff) << 32) | last_dword;
                        BB_PRINTK("  BBSP: 0x%llx", bbsp);

                        if (!!cxt->bb2l && (lvl < 2)) {
                                cxt->level += 1;
                                lvl = cxt->level;
                        }

                        buff = bpf_map_lookup_elem(&bb_parse_buffers, &lvl);
                        if (buff == NULL) { return -1; }

                        /* See if the bbsp points to somewhere that we've already read from userspace
                         * in some other level's chunk to avoid an additional read. The intuition behind
                         * this is that it is common for BATCH_BUFFER_START commands to jump somewhere
                         * nearby or to jump back to some command area that we were previously parsing.
                         * If this is succesful, we save a bpf_for_each_map_elem() as well as a
                         * bpf_probe_read_user() (both in read_batch_buffer()), which is huge. */
                        for (b = 0; b < 3; b += 1) {
                                bi = b;
                                other_buff = bpf_map_lookup_elem(&bb_parse_buffers, &bi);
                                if (other_buff == NULL) { return -1; }
                                if (BB_BUFF_CONTAINS_IP(other_buff, bbsp)) {
                                        bpf_map_update_elem(&bb_parse_buffers, &lvl, other_buff, 0);
                                        goto next_level_loaded;
                                }
                        }

                        if (read_batch_buffer(bbsp, buff) != 0) {
                                ERR_PRINTK("failed to look up batch buffer address 0x%llx", bbsp);
                                return -1;
                        }
next_level_loaded:;

                        cxt->ips[lvl & 3]     = bbsp - sizeof(u32); /* Will be advanced back to bbsp at bottom of dword loop. */
                        cxt->cpu_ips[lvl & 3] = (buff->cpu_base + (bbsp - buff->gpu_base)) - sizeof(u32);

                        BB_PRINTK("  Jumping to new buffer.");

                } else if ((op == BATCH_BUFFER_END) && (which_dword == 0)) {
                        if (lvl == 0) { return BB_STOP; }
                        cxt->level -= 1;
                        lvl = cxt->level;

                } else if (
                           ((op == COMPUTE_WALKER) && (which_dword == COMPUTE_WALKER_KSP_DWORD))
#ifdef XE_DRIVER
                           || (((op == _3DSTATE_VS) || (op == _3DSTATE_GS) || (op == _3DSTATE_DS)) && (which_dword == 2))
                           || (((op == _3DSTATE_HS) && (which_dword == 3)))
                           || (((op == _3DSTATE_PS) && ((which_dword == 2) || (which_dword == 9) || (which_dword == 11))))
#endif
        			  ) {
                             
                        ksp = ((((u64)dword) & 0xFFFF) << 32) | (((u64)last_dword) & 0xFFFFFFC0);
                        
                        if (ksp) {
                                cxt->has_ksps = 1;
                                BB_PRINTK("  KSP: 0x%llx", ksp);
                                bpf_map_update_elem(&bb_ksps, &ksp, &one, 0);
                        }
                        
                } else if ((op == STATE_BASE_ADDRESS) && (which_dword == 11)) {
                        cxt->iba = (((u64)dword) << 32) | (((u64)last_dword) & 0xFFFFF000);
                        BB_PRINTK("  IBA: 0x%llx", cxt->iba);

                } else if ((op == STATE_SIP) && (which_dword == 2)) {
                        cxt->sip = (((u64)dword) << 32) | (((u64)last_dword) & 0xFFFFFFF0);
                        BB_PRINTK("  SIP: 0x%llx", cxt->sip);
                }

                cxt->ips[lvl & 3]     += sizeof(u32);
                cxt->cpu_ips[lvl & 3] += sizeof(u32);

                to_consume -= 1;
                if (to_consume == 0) { break; }
        }

        return 0;
}

static void defer_batchbuffer_parse(struct parse_cxt *parse_cxt) {
        u64 ip;
#ifdef BB_DEBUG
        int exists;
#endif

        ip = parse_cxt->ips[parse_cxt->level & 3];

#ifdef BB_DEBUG
        exists = bpf_map_lookup_elem(&deferred_parse, &ip) != NULL;
#endif

        if (bpf_map_update_elem(&deferred_parse, &ip, parse_cxt, 0) != 0) {
                ERR_PRINTK("unable to defer parse.. deferred batch buffer parsing piled up");
                dropped_event = 1;
        }

#ifdef BB_DEBUG
        if (!exists) {
                __sync_fetch_and_add(&n_deferred, 1);
        }
#endif

        BB_PRINTK("Adding 0x%lx to deferred parse map. %d entries", ip, n_deferred);
}


static int parse_batchbuffer(struct parse_cxt *cxt, int from_deferred) {
        u64                  initial_ip;
        u64                  initial_cpu_ip;
        struct batch_buffer *buff;
        int                  stop;
        int                  i;
        u64                  status;
        struct iba_info     *iba_info;
        struct ksp_info     *ksp_info;
        struct sip_info     *sip_info;

        clear_ksps();

        initial_ip     = cxt->ips[cxt->level & 3];
        initial_cpu_ip = cxt->cpu_ips[cxt->level & 3];

        if (from_deferred) {
                BB_PRINTK("DEFERRED");
        }
        BB_PRINTK("BB Parsing @ 0x%llx (level %u)", initial_ip, cxt->level);


        buff = bpf_map_lookup_elem(&bb_parse_buffers, &cxt->level);
        if (buff == NULL) { return -1; }

        /* Can we reuse a chunk from the last batch buffer? Maybe it was
         * written sequentially. Won't work for deferred parsing since we
         * need the data to be fresh. */
        if (from_deferred || !BB_BUFF_CONTAINS_IP(buff, initial_ip)) {
                buff->gpu_base = initial_ip;
                buff->cpu_base = initial_cpu_ip;

                bpf_probe_read_user(buff->dwords, MAX_BB_BYTES, (void*)initial_cpu_ip);
        }

        stop = 0;
        for (i = 0; i < MAX_BB_COMMANDS && stop == 0; i += 1) {
                stop = parse_next(cxt);
        }

        if (stop == 0) {
                stop = BB_TRY_AGAIN;
/*                 defer_batchbuffer_parse(cxt); */
/*                 ERR_PRINTK("exceeded the maximum number of batch buffer commands"); */
/*                 dropped_event = 1; */
/*                 return -1; */
        } else if (stop < 0) {
                /* Some error condition occurred. */
/*                 dropped_event = 1; */
                return -1;
        }

        if (cxt->iba) {
                iba_info = bpf_ringbuf_reserve(&rb, sizeof(struct iba_info), 0);
                if (!iba_info) {
                        ERR_PRINTK("parse_batchbuffer failed to reserve in the ringbuffer.");
                        status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                        DEBUG_PRINTK("Unconsumed data: %lu", status);
                        dropped_event = 1;
                        return -1;
                }
                iba_info->type  = BPF_EVENT_TYPE_IBA;
                iba_info->eb_id = cxt->eb_id;
                iba_info->addr  = cxt->iba;
                bpf_ringbuf_submit(iba_info, BPF_RB_FORCE_WAKEUP);

                cxt->iba = 0;
        }

        if (cxt->has_ksps) {
                send_ksps(cxt);

                cxt->has_ksps = 0;
        }

        if (cxt->sip) {
                sip_info = bpf_ringbuf_reserve(&rb, sizeof(struct sip_info), 0);
                if (!sip_info) {
                        ERR_PRINTK("parse_batchbuffer failed to reserve in the ringbuffer.");
                        status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                        DEBUG_PRINTK("Unconsumed data: %lu", status);
                        dropped_event = 1;
                        return -1;
                }
                sip_info->type  = BPF_EVENT_TYPE_SIP;
                sip_info->eb_id = cxt->eb_id;
                sip_info->addr  = cxt->sip;
                bpf_ringbuf_submit(sip_info, BPF_RB_FORCE_WAKEUP);

                cxt->sip = 0;
        }

        return stop;
}

static __u64 _try_parse_deferred_batchbuffer(struct bpf_map *map, u64 *ip, struct parse_cxt *parse_cxt, struct address_range *range) {
        struct execbuf_end_info *end_info;
        u64                      new_ip;
        u64                      status;

        if (range != NULL && (*ip < range->start || *ip >= range->end)) {
                return 0;
        }

        bpf_map_delete_elem(map, ip);

#ifdef BB_DEBUG
        __sync_fetch_and_add(&n_deferred, -1);
#endif

        if (parse_batchbuffer(parse_cxt, 1) == BB_TRY_AGAIN) {
                WARN_PRINTK("deferred batch buffer still not ready");

                new_ip = parse_cxt->ips[parse_cxt->level & 3];

                parse_cxt->attempts += 1;

                if (parse_cxt->attempts == MAX_BB_ATTEMPTS) {
                        WARN_PRINTK("dropping batch buffer after %d attempts", MAX_BB_ATTEMPTS);
                } else {
                        if (bpf_map_update_elem(&tmp_deffered_add, &new_ip, parse_cxt, 0) != 0) {
                                ERR_PRINTK("unable to defer parse.. deferred batch buffer parsing piled up");
                                dropped_event = 1;
                        }
                }
        } else {
                end_info = bpf_ringbuf_reserve(&rb, sizeof(struct execbuf_end_info), 0);
                if (!end_info) {
                        ERR_PRINTK("_try_parse_deferred_batchbuffer failed to reserve in the ringbuffer.");
                        status = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                        DEBUG_PRINTK("Unconsumed data: %lu", status);
                        dropped_event = 1;
                        return 0;
                }
                end_info->type  = BPF_EVENT_TYPE_EXECBUF_END;
                end_info->eb_id = parse_cxt->eb_id;
                bpf_ringbuf_submit(end_info, BPF_RB_FORCE_WAKEUP);
        }

        return 0;
}

static __u64 _add_tmp_deferred(struct bpf_map *map, u64 *ip, struct parse_cxt *parse_cxt, void *cxt) {
        defer_batchbuffer_parse(parse_cxt);
        bpf_map_delete_elem(map, ip);
        return 0;
}

static void try_parse_deferred_batchbuffers(struct address_range *range) {
        bpf_for_each_map_elem(&deferred_parse, _try_parse_deferred_batchbuffer, range, 0);
        bpf_for_each_map_elem(&tmp_deffered_add, _add_tmp_deferred, NULL, 0);
}
