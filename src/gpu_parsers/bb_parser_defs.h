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
#define CMD_EXEC         (5)

#define OP_LEN_MI      (9)
#define OP_LEN_XY      (10)
#define OP_LEN_GFXPIPE (16)
#define OP_LEN_MFX_VC  (16)
#define OP_LEN_VEBOX   (16)
#define OP_LEN_EXEC    (6)

/* GFXPIPE Commands: Pipeline Type(28:27) Opcode(26:24) Sub Opcode(23:16) */
#define OP_GFXPIPE(sub_type, opcode, sub_opcode) \
        ((3 << 13) | ((sub_type) << 11) | ((opcode) << 8) | (sub_opcode))
#define OP_3D    ((3 << 13) | (0xF << 11) | (0xF << 8) | (0xFF))

/* The top three bits (31:29) are the command type */
#define CMD_TYPE(dword) (((dword) >> 29) & 7)

#define CMD_TYPE_LEN(cmd_type)                 \
( ((cmd_type) == CMD_MI)      ? OP_LEN_MI      \
: ((cmd_type) == CMD_GFXPIPE) ? OP_LEN_GFXPIPE \
: ((cmd_type) == CMD_XY)      ? OP_LEN_XY      \
: ((cmd_type) == CMD_EXEC)    ? OP_LEN_EXEC    \
: 0)

#define CMD_TYPE_OPCODE_MASK(cmd_type)         \
( ((cmd_type) == CMD_MI)      ? -1             \
: ((cmd_type) == CMD_GFXPIPE) ? OP_3D          \
: ((cmd_type) == CMD_XY)      ? 0x7f           \
: ((cmd_type) == CMD_EXEC)    ? 0x7            \
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

#ifdef XE_DRIVER

#define PLATFORM_HAS_MI_MATH (1)
#define PLATFORM_HAS_3DSTATE_CONSTANT_ALL (1)
#define PLATFORM_HAS_3DSTATE_VERTEX_BUFFERS (1)
#define PLATFORM_HAS_3DSTATE_VERTEX_ELEMENTS (1)
#define PLATFORM_HAS_3DPRIMITIVE (1)
#define PLATFORM_HAS_3DSTATE_BTD (1)

#define LIST_COMMANDS(X)                                                                                \
/*        NAME,                              TYPE,        OPCODE,                         NUM_DWORDS */ \
        X(NOOP,                                CMD_MI,        0x00,                                  1)   \
        X(BATCH_BUFFER_START,                  CMD_MI,        0x31,                                  3)   \
        X(PRT_BATCH_BUFFER_START,              CMD_MI,        0x39,                                  3)   \
        X(CONDITIONAL_BATCH_BUFFER_END,        CMD_MI,        0x36,                                  4)   \
        X(BATCH_BUFFER_END,                    CMD_MI,        0x0a,                                  1)   \
        X(SEMAPHORE_WAIT,                      CMD_MI,        0x1c,                                  5)   \
        X(PREDICATE,                           CMD_MI,        0x0c,                                  1)   \
        X(STORE_REGISTER_MEM,                  CMD_MI,        0x24,                                  4)   \
        X(STORE_DATA_IMM,                      CMD_MI,        0x20,                                  5)   \
        X(LOAD_REGISTER_IMM,                   CMD_MI,        0x22,                                  2)   \
        X(LOAD_REGISTER_MEM,                   CMD_MI,        0x29,                                  4)   \
        X(LOAD_REGISTER_REG,                   CMD_MI,        0x2a,                                  3)   \
        X(FLUSH_DW,                            CMD_MI,        0x26,                                  5)   \
        X(ARB_CHECK,                           CMD_MI,        0x05,                                  1)   \
        X(ARB_ON_OFF,                          CMD_MI,        0x08,                                  1)   \
        X(URB_ATOMIC_ALLOC,                    CMD_MI,        0x09,                                  1)   \
        X(MATH,                                CMD_MI,        0x1a,                                  1)   \
        X(SET_PREDICATE,                       CMD_MI,        0x01,                                  1)   \
        X(MEM_COPY,                            CMD_XY,        0x5a,                                 10)   \
        X(MEM_SET,                             CMD_XY,        0x5b,                                  7)   \
        X(RESOURCE_BARRIER,                    CMD_EXEC,      0x3,                                   5)   \
        X(_3DSTATE_CPS_POINTERS,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x22),          2)   \
        X(PIPE_CONTROL,                        CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x02, 0x00),          6)   \
        X(PIPELINE_SELECT,                     CMD_GFXPIPE,   OP_GFXPIPE(0x01, 0x01, 0x04),          1)   \
        X(COMPUTE_WALKER,                      CMD_GFXPIPE,   OP_GFXPIPE(0x02, 0x02, 0x08),         40)   \
        X(GPGPU_WALKER,                        CMD_GFXPIPE,   OP_GFXPIPE(0x02, 0x01, 0x05),         15)   \
        X(STATE_BASE_ADDRESS,                  CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x01),         22)   \
        X(STATE_COMPUTE_MODE,                  CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x05),          3)   \
        X(STATE_SIP,                           CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x02),          3)   \
        X(STATE_PREFETCH,                      CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x00, 0x03),          4)   \
        X(STATE_SYSTEM_MEM_FENCE_ADDRESS,      CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x09),          3)   \
        X(STATE_CONTEXT_DATA_BASE_ADDRESS,     CMD_GFXPIPE,   OP_GFXPIPE(0X00, 0X01, 0X0b),          3)   \
        X(CFE_STATE,                           CMD_GFXPIPE,   OP_GFXPIPE(0x02, 0x02, 0x00),          6)   \
        X(STATE_BYTE_STRIDE,                   CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x00, 0x05),          2)   \
        X(_3DSTATE_BINDING_TABLE_POOL_ALLOC,   CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x19),          4)   \
        X(_3DSTATE_CONSTANT_ALL,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x6d),          1)   \
        X(_3DSTATE_BINDING_TABLE_POINTERS_VS,  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x26),          2)   \
        X(_3DSTATE_3D_MODE,                    CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x1e),          5)   \
        X(_3DSTATE_VERTEX_BUFFERS,             CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x08),          1)   \
        X(_3DSTATE_DRAWING_RECTANGLE_FAST,     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x00),          4)   \
        X(_3DSTATE_SAMPLE_PATTERN,             CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x1c),          9)   \
        X(_3DSTATE_VERTEX_ELEMENTS,            CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x09),          1)   \
        X(_3DSTATE_AA_LINE_PARAMS,             CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x0a),          3)   \
        X(_3DSTATE_VF_STATISTICS,              CMD_GFXPIPE,   OP_GFXPIPE(0x01, 0x00, 0x0b),          1)   \
        X(_3DSTATE_VF_SGVS,                    CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x4a),          2)   \
        X(_3DSTATE_WM_CHROMAKEY,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x4c),          2)   \
        X(_3DSTATE_WM_HZ_OP,                   CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x52),          6)   \
        X(_3DSTATE_VF_SGVS_2,                  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x56),          3)   \
        X(_3DSTATE_POLY_STIPPLE_OFFSET,        CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x06),          2)   \
        X(_3DSTATE_VF_INSTANCING,              CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x49),          3)   \
        X(_3DSTATE_VF_TOPOLOGY,                CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x4b),          2)   \
        X(_3DSTATE_MESH_CONTROL,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x77),          3)   \
        X(_3DSTATE_URB_VS,                     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x30),          2)   \
        X(_3DSTATE_URB_HS,                     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x31),          2)   \
        X(_3DSTATE_URB_DS,                     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x32),          2)   \
        X(_3DSTATE_URB_GS,                     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x33),          2)   \
        X(_3DSTATE_TASK_CONTROL,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x7c),          3)   \
        X(_3DSTATE_PUSH_CONSTANT_ALLOC_VS,     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x12),          2)   \
        X(_3DSTATE_PUSH_CONSTANT_ALLOC_HS,     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x13),          2)   \
        X(_3DSTATE_PUSH_CONSTANT_ALLOC_DS,     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x14),          2)   \
        X(_3DSTATE_PUSH_CONSTANT_ALLOC_GS,     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x15),          2)   \
        X(_3DSTATE_PUSH_CONSTANT_ALLOC_PS,     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x16),          2)   \
        X(_3DSTATE_BLEND_STATE_POINTERS,       CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x24),          2)   \
        X(_3DSTATE_BINDING_TABLE_POINTERS_HS,  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x27),          2)   \
        X(_3DSTATE_BINDING_TABLE_POINTERS_DS,  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x28),          2)   \
        X(_3DSTATE_BINDING_TABLE_POINTERS_GS,  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x29),          2)   \
        X(_3DSTATE_BINDING_TABLE_POINTERS_PS,  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x2a),          2)   \
        X(_3DSTATE_SAMPLER_STATE_POINTERS_PS,  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x2f),          2)   \
        X(_3DSTATE_MULTISAMPLE,                CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x0d),          2)   \
        X(_3DSTATE_SAMPLE_MASK,                CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x18),          2)   \
        X(_3DSTATE_VIEWPORT_STATE_POINTERS_CC, CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x23),          2)   \
        X(_3DSTATE_CC_STATE_POINTERS,          CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x0e),          2)   \
        X(_3DSTATE_WM_DEPTH_STENCIL,           CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x4e),          4)   \
        X(_3DSTATE_DEPTH_BOUNDS,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x71),          4)   \
        X(_3DSTATE_VS,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x10),          9)   \
        X(_3DSTATE_DS,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x1d),         11)   \
        X(_3DSTATE_HS,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x1b),          8)   \
        X(_3DSTATE_PS,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x20),         12)   \
        X(_3DSTATE_TE,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x1c),          5)   \
        X(_3DSTATE_GS,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x11),         10)   \
        X(_3DSTATE_SF,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x13),          4)   \
        X(_3DSTATE_WM,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x14),          2)   \
        X(_3DSTATE_BTD,                        CMD_GFXPIPE,   OP_GFXPIPE(0x00, 0x01, 0x06),          1)   \
        X(_3DSTATE_PS_EXTRA,                   CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x4f),          2)   \
        X(_3DSTATE_STREAMOUT,                  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x1e),          5)   \
        X(_3DSTATE_CLIP,                       CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x12),          4)   \
        X(_3DSTATE_RASTER,                     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x50),          5)   \
        X(_3DSTATE_SBE,                        CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x1f),          6)   \
        X(_3DSTATE_SBE_SWIZ,                   CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x51),         11)   \
        X(_3DPRIMITIVE,                        CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x03, 0x00),          7)   \
        X(_3DSTATE_PRIMITIVE_REPLICATION,      CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x6c),          6)   \
        X(_3DSTATE_DEPTH_BUFFER,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x05),          8)   \
        X(_3DSTATE_STENCIL_BUFFER,             CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x06),          8)   \
        X(_3DSTATE_HIER_DEPTH_BUFFER,          CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x07),          5)   \
        X(_3DSTATE_VIEWPORT_STATE_POINTERS_SF_CLIP, CMD_GFXPIPE, OP_GFXPIPE(0x03, 0x00, 0x21),       2)   \
        X(_3DSTATE_VFG,                        CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x57),          4)   \
        X(_3DSTATE_SAMPLER_STATE_POINTERS_VS,  CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x2b),          2)   \
        X(_3DSTATE_INDEX_BUFFER,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x0a),          5)   \
        X(_3DSTATE_SCISSOR_STATE_POINTERS,     CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x0f),          2)   \
        X(_3DSTATE_POLY_STIPPLE_PATTERN,       CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x07),         33)   \
        X(_3DSTATE_LINE_STIPPLE,               CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x01, 0x08),          3)   \
        X(_3DSTATE_VF,                         CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x0c),          2)   \
        X(_3DSTATE_PS_BLEND,                   CMD_GFXPIPE,   OP_GFXPIPE(0x03, 0x00, 0x4d),          2)
        
#define COMPUTE_WALKER_KSP_DWORD 20
#else

#define PLATFORM_HAS_MI_MATH (1)
#define PLATFORM_HAS_3DSTATE_CONSTANT_ALL (0)
#define PLATFORM_HAS_3DSTATE_VERTEX_BUFFERS (0)
#define PLATFORM_HAS_3DSTATE_VERTEX_ELEMENTS (0)
#define PLATFORM_HAS_3DPRIMITIVE (0)
#define PLATFORM_HAS_3DSTATE_BTD (0)

/* Note about MI_MATH: the actual length in DWORDS of the command is encoded in the last 3 bits of the
 * DWORD. It's encoded as 1 in this table, but care should be taken in parsing code to account for this. */

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
        X(MATH,                              CMD_MI,        0x1a,                                  1)   \
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
#define COMPUTE_WALKER_KSP_DWORD 19
#endif

enum {
#define E(name, type, opcode, num_dwords) name = opcode,
        LIST_COMMANDS(E)
#undef E
};
