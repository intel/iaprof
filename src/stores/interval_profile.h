#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <linux/types.h>
#include <pthread.h>

#include "collectors/bpf/bpf/main.h"
#include "gpu_parsers/shader_decoder.h"

#include "utils/hash_table.h"
#include "utils/array.h"

/***************************************
* Interval Profile
**********************
* Stores per-interval profiles, so that we can build
* an in-memory profile that maintains which interval
* each sample was collected in.
***************************************/

/* Stores an aggregated sample within an interval's profile */
struct sample {
        char       *proc_name;
        const char *ustack_str;
        const char *kstack_str;

        uint32_t    pid;
        int         is_debug;
        int         is_sys;

        uint64_t    addr;
        uint64_t    offset;
        uint64_t    insn_id;
        int         stall_type;
};

typedef struct sample sample_struct;

static inline int sample_equ(const struct sample a, const struct sample b) {
        /* Check the stack strings by pointer value since they are uniquely stored
         * and retrieved via {store,get}_stack(). */
        if (a.ustack_str != b.ustack_str)        { return 0; }
        if (a.kstack_str != b.kstack_str)        { return 0; }

        if (a.pid        != b.pid)                 { return 0; }
        if (a.is_debug   != b.is_debug)            { return 0; }
        if (a.is_sys     != b.is_sys)              { return 0; }
        if (a.addr       != b.addr)                { return 0; }
        if (a.offset     != b.offset)              { return 0; }
        if (a.stall_type != b.stall_type)          { return 0; }
        if (a.insn_id    != b.insn_id)             { return 0; }
        
        if (a.proc_name == NULL || b.proc_name == NULL) {
                if (a.proc_name != b.proc_name) {
                        return 0;
                }
        } else if (strcmp(a.proc_name, b.proc_name) != 0) {
                return 0;
        }

        return 1;
}

/* Stores a single interval's profile */
use_hash_table_e(sample_struct, uint64_t, sample_equ);
extern hash_table(sample_struct, uint64_t) interval_profile;

void init_interval_profile();
void store_interval_profile(uint64_t interval);
void store_unknown_flames(array_t *waitlist);
