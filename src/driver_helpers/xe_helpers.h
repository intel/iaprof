#pragma once

#include "drm_helpers/drm_helpers.h"

#define PAGE_SIZE (4096)

/*******************
*    Utilities     *
*******************/
#define GEN8_GTT_ADDRESS_WIDTH 48

static int64_t sign_extend64(uint64_t value, int index);
static inline uint64_t CANONICAL(uint64_t offset);
#define DECANONICAL(offset) (offset & ((1ull << GEN8_GTT_ADDRESS_WIDTH) - 1))

/*******************
*   GPU Commands   *
*******************/

/* Offsets in the instruction fields */
#define INSTR_MI_CLIENT 0x0
#define INSTR_CLIENT_SHIFT 29
#define __INSTR(client) ((client) << INSTR_CLIENT_SHIFT)

/* Memory interface instructions */
#define MI_INSTR(opcode, flags) \
        (__INSTR(INSTR_MI_CLIENT) | (opcode) << 23 | (flags))
#define MI_BATCH_BUFFER_END MI_INSTR(0x0a, 0)

/*******************
*     CONTEXT      *
*******************/

#define for_each_gt(gts__, gt__)                      \
        /* Beginning condition */                     \
        for (int iter__ = 0; /* Finished condition */ \
             (iter__ < gts__->num_gt) &&              \
             (gt__ = &(gts__->gt_list[iter__]),       \
             1); /* Incrementing */                   \
             iter__ += 1)

int xe_query_gts(int fd, struct drm_xe_query_gt_list **qg);
int xe_query_eu_stalls(int fd, struct drm_xe_query_eu_stall **stall_info);
int xe_init_eustall(struct device_info *devinfo);
