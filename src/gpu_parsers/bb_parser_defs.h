#pragma once

/* General-purpose registers */
#define GPR_OFFSET 0x2600
#define GPR_REG(i) (GPR_OFFSET + (i)*8)

/* Predicate constants */
#define PREDICATE_SRC0 0x2400
#define PREDICATE_SRC1 0x2408
#define PREDICATE_RESULT 0x2418

/******************************************************************************
* Commands
* *********
* These are constants that represent batch buffer commands.
******************************************************************************/


#define CMD_MI           (0)
#define CMD_TYPE_UNKNOWN (1)
#define CMD_XY           (2)
#define CMD_GFXPIPE      (3)

#define OP_LEN_MI      (9)
#define OP_LEN_XY      (10)
#define OP_LEN_GFXPIPE (16)
#define OP_LEN_MFX_VC  (16)
#define OP_LEN_VEBOX   (16)


/* GFXPIPE Commands: Pipeline Type(28:27) Opcode(26:24) Sub Opcode(23:16) */
#define OP_GFXPIPE(sub_type, opcode, sub_opcode) \
        ((3 << 13) | ((sub_type) << 11) | ((opcode) << 8) | (sub_opcode))
#define OP_3D ((3 << 13) | (0xF << 11) | (0xF << 8) | (0xFF))

#define CMD_TYPE(dword) (((dword) >> 29) & 7)

#define CMD_TYPE_LEN(cmd_type)                 \
( ((cmd_type) == CMD_MI)      ? OP_LEN_MI      \
: ((cmd_type) == CMD_GFXPIPE) ? OP_LEN_GFXPIPE \
: ((cmd_type) == CMD_XY)      ? OP_LEN_XY      \
: 0)

#define CMD_TYPE_OPCODE_MASK(cmd_type)         \
( ((cmd_type) == CMD_MI)      ? -1             \
: ((cmd_type) == CMD_GFXPIPE) ? OP_3D          \
: ((cmd_type) == CMD_XY)      ? 0x7f           \
: 0)

#define GET_OPCODE(dword) (((dword) >> (32 - CMD_TYPE_LEN(CMD_TYPE(dword)))) & CMD_TYPE_OPCODE_MASK(CMD_TYPE(dword)))

#define MI_BATCH_BUFFER_START_2ND_LEVEL(x) ((x) >> 22 & 1U)

/* This table defines the constants for each batch buffer command that we recognize and parse.
 * Important note:
 *   Enums and arrays are generated from this table based on the value of the opcode.
 *   As of this comment, I have not seen batch buffer commands of different types with the
 *   same opcode. If we do encounter this in the future, we will need to rework some of the
 *   generated code from this table. (Most likely just generate 3 separate versions for each
 *   command type.
 */

#define LIST_COMMANDS(X)                                                                                \
/*        NAME,                              TYPE,        OPCODE,                         NUM_DWORDS */ \
        X(NOOP,                              CMD_MI,        0x00,                                  1)   \
        X(BATCH_BUFFER_START,                CMD_MI,        0x31,                                  3)   \
        X(PRT_BATCH_BUFFER_START,            CMD_MI,        0x39,                                  3)   \
        X(CONDITIONAL_BATCH_BUFFER_END,      CMD_MI,        0x36,                                  4)   \
        X(BATCH_BUFFER_END,                  CMD_MI,        0x0a,                                  1)   \
        X(SEMAPHORE_WAIT,                    CMD_MI,        0x1c,                                  5)   \
        X(PREDICATE,                         CMD_MI,        0x0c,                                  1)   \
        X(STORE_REGISTER_MEM,                CMD_MI,        0x24,                                  4)   \
        X(STORE_DATA_IMM,                    CMD_MI,        0x20,                                  5)   \
        X(LOAD_REGISTER_IMM,                 CMD_MI,        0x22,                                  3)   \
        X(LOAD_REGISTER_MEM,                 CMD_MI,        0x29,                                  4)   \
        X(LOAD_REGISTER_REG,                 CMD_MI,        0x2a,                                  3)   \
        X(FLUSH_DW,                          CMD_MI,        0x26,                                  5)   \
        X(ARB_CHECK,                         CMD_MI,        0x05,                                  1)   \
        X(ARB_ON_OFF,                        CMD_MI,        0x08,                                  1)   \
        X(URB_ATOMIC_ALLOC,                  CMD_MI,        0x09,                                  1)   \
        X(MEM_COPY,                          CMD_XY,        0x5a,                                 10)   \
        X(MEM_SET,                           CMD_XY,        0x5b,                                  7)   \
        X(PIPE_CONTROL,                      CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x02, 0x00),          6)   \
        X(PIPELINE_SELECT,                   CMD_GFXPIPE,   OP_GFXPIPE(0x01, 0x01, 0x04),          1)   \
        X(COMPUTE_WALKER,                    CMD_GFXPIPE,   OP_GFXPIPE(0x02, 0x02, 0x08),         39)   \
        X(GPGPU_WALKER,                      CMD_GFXPIPE,   OP_GFXPIPE(0x02, 0x01, 0x05),         15)   \
        X(STATE_BASE_ADDRESS,                CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x01),         22)   \
        X(STATE_COMPUTE_MODE,                CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x05),          2)   \
        X(STATE_SIP,                         CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x02),          3)   \
        X(STATE_PREFETCH,                    CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x00, 0x03),          4)   \
        X(STATE_SYSTEM_MEM_FENCE_ADDRESS,    CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x09),          3)   \
        X(CFE_STATE,                         CMD_GFXPIPE,   OP_GFXPIPE(0x02, 0x02, 0x00),          6)   \
        X(_3DSTATE_BINDING_TABLE_POOL_ALLOC, CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x19),          4)

enum {
#define E(name, type, opcode, num_dwords) name = opcode,
        LIST_COMMANDS(E)
#undef E
};
