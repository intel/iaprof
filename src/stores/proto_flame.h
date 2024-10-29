#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/types.h>
#include <pthread.h>

#include "collectors/bpf_i915/bpf/main.h"
#include "gpu_parsers/shader_decoder.h"

#include "utils/hash_table.h"

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

        uint64_t    addr;
        uint64_t    offset;
        char       *insn_text;
        int         stall_type;
};

typedef struct proto_flame proto_flame_struct;
int proto_flame_equ(const struct proto_flame a, const struct proto_flame b);
use_hash_table_e(proto_flame_struct, uint64_t, proto_flame_equ);

extern hash_table(proto_flame_struct, uint64_t) flame_samples;

void init_flames();
void store_interval_flames();
