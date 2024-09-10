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
#define CMD_TYPE(cmd) (((cmd) >> 29) & 7)
#define CMD_MI 0
#define CMD_2D 2
#define GFXPIPE 3

#define OP_LEN_MI 9
#define OP_LEN_2D 10
#define OP_LEN_GFXPIPE 16
#define OP_LEN_MFX_VC 16
#define OP_LEN_VEBOX 16

/* MI Commands */
#define MI_BATCH_BUFFER_START 0x31
#define MI_BATCH_BUFFER_START_DWORDS 3
#define MI_BATCH_BUFFER_START_2ND_LEVEL(x) ((x) >> 22 & 1U)

#define MI_PRT_BATCH_BUFFER_START 0x39
#define MI_PRT_BATCH_BUFFER_START_DWORDS 3

#define MI_CONDITIONAL_BATCH_BUFFER_END 0x36
#define MI_CONDITIONAL_BATCH_BUFFER_END_DWORDS 4

#define MI_BATCH_BUFFER_END 0x0a
#define MI_BATCH_BUFFER_END_DWORDS 1

#define MI_SEMAPHORE_WAIT 0x1c
#define MI_SEMAPHORE_WAIT_DWORDS 5

#define MI_PREDICATE 0x0c
#define MI_PREDICATE_DWORDS 1

#define MI_STORE_REGISTER_MEM 0x24
#define MI_STORE_REGISTER_MEM_DWORDS 4

#define MI_STORE_DATA_IMM 0x20
#define MI_STORE_DATA_IMM_DWORDS 5

#define MI_LOAD_REGISTER_IMM 0x22
#define MI_LOAD_REGISTER_IMM_DWORDS 3

#define MI_LOAD_REGISTER_MEM 0x29
#define MI_LOAD_REGISTER_MEM_DWORDS 4

#define MI_LOAD_REGISTER_REG 0x2a
#define MI_LOAD_REGISTER_REG_DWORDS 3

#define MI_FLUSH_DW 0x26
#define MI_FLUSH_DW_DWORDS 5

#define MI_ARB_CHECK 0x05
#define MI_ARB_CHECK_DWORDS 1

#define MI_ARB_ON_OFF 0x08
#define MI_ARB_ON_OFF_DWORDS 1

#define MI_URB_ATOMIC_ALLOC 0x09
#define MI_URB_ATOMIC_ALLOC_DWORDS 1

#define MI_NOOP 0x00
#define MI_NOOP_DWORDS 1

/* 2D/XY Commands */

#define MEM_COPY 0x5a
#define MEM_COPY_DWORDS 10
#define MEM_SET 0x5b
#define MEM_SET_DWORDS 7

/* GFXPIPE Commands: Pipeline Type(28:27) Opcode(26:24) Sub Opcode(23:16) */
#define OP_GFXPIPE(sub_type, opcode, sub_opcode) \
        ((3 << 13) | ((sub_type) << 11) | ((opcode) << 8) | (sub_opcode))
#define OP_3D ((3 << 13) | (0xF << 11) | (0xF << 8) | (0xFF))

#define PIPE_CONTROL OP_GFXPIPE(0x3, 0x2, 0x0)
#define PIPE_CONTROL_DWORDS 6

#define PIPELINE_SELECT OP_GFXPIPE(0x1, 0x1, 0x04)
#define PIPELINE_SELECT_DWORDS 1

#define COMPUTE_WALKER OP_GFXPIPE(0x2, 0x2, 0x8)
#define COMPUTE_WALKER_DWORDS 39

#define GPGPU_WALKER OP_GFXPIPE(0x2, 0x1, 0x05)
#define GPGPU_WALKER_DWORDS 15

#define STATE_BASE_ADDRESS OP_GFXPIPE(0x0, 0x1, 0x01)
#define STATE_BASE_ADDRESS_DWORDS 22

#define STATE_SIP OP_GFXPIPE(0x0, 0x1, 0x02)
#define STATE_SIP_DWORDS 3

#define STATE_SYSTEM_MEM_FENCE_ADDRESS OP_GFXPIPE(0x0, 0x1, 0x9)
#define STATE_SYSTEM_MEM_FENCE_ADDRESS_DWORDS 3

#define CFE_STATE OP_GFXPIPE(0x2, 0x2, 0x0)
#define CFE_STATE_DWORDS 5

#define CMD_TYPE_LEN(cmd_type)             \
( ((cmd_type) == CMD_MI)  ? OP_LEN_MI      \
: ((cmd_type) == GFXPIPE) ? OP_LEN_GFXPIPE \
: ((cmd_type) == CMD_2D)  ? OP_LEN_2D      \
: 0)
