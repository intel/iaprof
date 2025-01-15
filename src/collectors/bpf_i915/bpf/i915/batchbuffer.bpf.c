/***************************************
* BATCHBUFFER
* **********
* Batch buffer detection routine. Uses
* BB command constants defined in
* gpu_parsers/bb_parser_defs.h
***************************************/

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
