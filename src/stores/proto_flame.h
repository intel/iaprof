#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/types.h>
#include <pthread.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "gpu_parsers/shader_decoder.h"

#include "utils/hash_table.h"
#include "utils/array.h"

/***************************************
* Proto Flamegraph
**********************
* Stores the individual components necessary to produce a Flamegraph,
* so that we can build it up as we go.
***************************************/

/* Stores a single "flame" of a flamegraph. */
struct proto_flame {
        char       *proc_name;
        const char *ustack_str;
        const char *kstack_str;

        uint32_t    pid;
        int         is_debug;
        int         is_sys;

        uint64_t    addr;
        uint64_t    offset;
        char       *insn_text;
        int         stall_type;
};

typedef struct proto_flame proto_flame_struct;

static inline int proto_flame_equ(const struct proto_flame a, const struct proto_flame b) {
        /* Check the stack strings by pointer value since they are uniquely stored
         * and retrieved via {store,get}_stack(). */
        if (a.ustack_str != b.ustack_str)          { return 0; }
        if (a.kstack_str != b.kstack_str)          { return 0; }

        if (a.pid        != b.pid)                 { return 0; }
        if (a.is_debug   != b.is_debug)            { return 0; }
        if (a.is_sys     != b.is_sys)              { return 0; }
        if (a.addr       != b.addr)                { return 0; }
        if (a.offset     != b.offset)              { return 0; }
        if (a.stall_type != b.stall_type)          { return 0; }

        if (a.insn_text == NULL || b.insn_text == NULL) {
                if (a.insn_text != b.insn_text) {
                        return 0;
                }
        } else if (strcmp(a.insn_text, b.insn_text) != 0) {
                return 0;
        }

        if (a.proc_name == NULL || b.proc_name == NULL) {
                if (a.proc_name != b.proc_name) {
                        return 0;
                }
        } else if (strcmp(a.proc_name, b.proc_name) != 0) {
                return 0;
        }

        return 1;
}

use_hash_table_e(proto_flame_struct, uint64_t, proto_flame_equ);

extern hash_table(proto_flame_struct, uint64_t) flame_samples;

void init_flames();
void store_interval_flames();
void store_unknown_flames(array_t *waitlist);
