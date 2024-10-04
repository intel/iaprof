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

uint64_t grow_proto_flames();
void store_interval_flames();

/* Stores a single "frame" of a flamegraph. */
struct proto_flame {
        char *proc_name;
        uint32_t pid;
        int cpu_stackid;
        int is_debug;
        
        char *stall_type;
        uint64_t count;
        uint64_t addr;
        uint64_t offset;
        char *insn_text;
        char *gpu_symbol;
        char *gpu_file;
        int   gpu_line;
};

extern pthread_rwlock_t proto_flame_lock;
extern struct proto_flame *proto_flame_arr;
extern size_t proto_flame_size, proto_flame_used;
