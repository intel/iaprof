#pragma once

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "collectors/bpf_i915/bpf_i915_collector.h"

/* STATE_BASE_ADDRESS::InstructionBaseAddress + ((INTERFACE_DESCRIPTOR_DATA */
/* *)(STATE_BASE_ADDRESS::DynamicBaseAddress + InterfaceDescriptorDataStartAddress))->KernelStartPointer */

use_tree(uint64_t, char);


/******************************************************************************
* Status
* *********
* Return types for the parser.
******************************************************************************/
enum bb_parser_status {
        BB_PARSER_STATUS_OK,
        BB_PARSER_STATUS_BUFF_OVERFLOW,
        BB_PARSER_STATUS_NOTFOUND,
};

uint64_t bb_parser_find_addr(struct buffer_binding *bind, uint64_t addr);

/******************************************************************************
* Parser Context
* *********
* This structure stores all the information the parser wants to find, and
* intermediate data and register values that it needs to continue parsing.
******************************************************************************/
struct bb_parser {
        uint64_t pc[3];
        uint64_t batch_len[3];
        uint8_t pc_depth;
        unsigned char in_cmd;
        uint64_t cur_cmd;
        uint8_t cur_num_dwords;

        struct vm_profile *vm;
        struct buffer_binding *bind;
        struct buffer_object *bo;

        /* Bookkeeping. Number of dwords that we've parsed. */
        uint64_t num_dwords;

        /* Instruction Base Address */
        uint64_t iba;
        
        /* Dynamics Base Address */
        uint64_t dba;

        /* SIP, or System Instruction Pointer.
	   This is an offset from the iba,
	   or Instruction Base Address. */
        uint64_t sip;

        /* Kernel Start Pointer. Gets overwritten
           if multiple are found. */
        uint64_t ksp;

        /* Batch Buffer Start Pointer */
        uint64_t bbsp;
        uint8_t bb2l;

        uint32_t load_register_offset, load_register_dword;

        /* For handling MI_PREDICATE */
        struct {
                uint64_t src0;
                uint64_t src1;
                uint64_t data;
                uint64_t result;
        } predicate;
        uint32_t enable_predication;

        /* General-purpose registers */
        union {
                uint64_t gpr64[16];
                uint32_t gpr32[16 * 2];
        };
        
        /* Infinite loop detection */
        tree(uint64_t, char) visited_addresses;
};

/******************************************************************************
* Registers
* *********
* Helpers for dealing with registers.
******************************************************************************/
/* General-purpose registers */
#define GPR_OFFSET 0x2600
#define GPR_REG(i) (GPR_OFFSET + (i)*8)

/* Predicate constants */
#define PREDICATE_SRC0 0x2400
#define PREDICATE_SRC1 0x2408
#define PREDICATE_RESULT 0x2418

/* Register constants */
static uint32_t null_reg;
static uint32_t unknown_reg = 0xdeaddead;

/* Get a pointer to the uint32_t that needs to be read/written when accessing
   a register value. */
static uint32_t *reg_ptr(struct bb_parser *parser, uint32_t offset, bool write)
{
        if (offset >= GPR_REG(0) && offset < GPR_REG(16)) {
                return &parser->gpr32[(offset - GPR_OFFSET) / 4];
        } else {
                bool off = (offset & 0x7ull) != 0;
                switch (offset & ~0x7ull) {
                case PREDICATE_SRC0:
                        return ((uint32_t *)&parser->predicate.src0) +
                               (off ? 1 : 0);
                case PREDICATE_SRC1:
                        return ((uint32_t *)&parser->predicate.src1) +
                               (off ? 1 : 0);
                case PREDICATE_RESULT:
                        return ((uint32_t *)&parser->predicate.result) +
                               (off ? 1 : 0);
                default:
                        return write ? &null_reg : &unknown_reg;
                }
        }
        return NULL;
}

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

uint32_t op_len(uint32_t *bb)
{
        switch (CMD_TYPE(*bb)) {
        case CMD_MI:
#if 0
                if (bb_debug) {
                        printf("cmd_type=CMD_MI\n");
                }
#endif
                return OP_LEN_MI;
        case GFXPIPE:
#if 0
                if (bb_debug) {
                        printf("cmd_type=GFXPIPE\n");
                }
#endif
                return OP_LEN_GFXPIPE;
        case CMD_2D:
#if 0
                if (bb_debug) {
                        printf("cmd_type=CMD_2D\n");
                }
#endif
                return OP_LEN_2D;
        default:
#if 0
                if (bb_debug) {
                        printf("cmd_type=UNKNOWN (0x%x)\n", CMD_TYPE(*bb));
                }
#endif
                break;
        }
        return 0;
}

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

char find_jump_buffer(struct bb_parser *parser, uint64_t bbsp)
{
        struct buffer_binding *bind;

        bind = get_containing_binding(parser->vm, bbsp);
        if (bind != NULL) {
                if (bb_debug) {
                        printf("Found a matching batch buffer ");
                        printf("to jump to. vm_id=%u gpu_addr=0x%lx\n",
                                bind->vm_id,
                                bind->gpu_addr);
                }
                if (parser->bo != NULL) {
                        release_buffer(parser->bo);
                }
                parser->bind = bind;
                parser->bo = acquire_buffer(parser->bind->file, parser->bind->handle);
                return 1;
        }

        return 0;
}

/******************************************************************************
* MI Command Implementations
* *********
* Commands in the MI_* group.
******************************************************************************/

#if 0
static bool
INST(MI_LOAD_REGISTER_IMM)(struct gen_mi_context *ctx,
                           struct GENX(MI_LOAD_REGISTER_IMM) *v)
{
   for (uint32_t i = 0; i < (v->__variable_length + 1); i++) {
      uint32_t offset, dword;

      if (i == 0) {
         offset = v->RegisterOffset;
         dword = v->DataDWord;
      } else {
         offset = v->__variable[i - 1].RegisterOffset;
         dword = v->__variable[i - 1].DataDWord;
      }

      uint32_t *ptr = reg_ptr(ctx, offset, true);
      if (ptr)
         *ptr = dword;
   }

   return false;
}
#endif

enum bb_parser_status mi_load_register_imm(struct bb_parser *parser,
                                           uint32_t *ptr)
{
        if (parser->in_cmd == 1) {
                /* Bits 22:2 of the third dword contains the register offset */
                parser->load_register_offset = (*ptr) & 0x3ffffe00;
                if (bb_debug) {
                        printf("load_register_offset=0x%x\n", *ptr);
                }
        } else if (parser->in_cmd == 2) {
                /* The entirety of the second dword contains the data dword */
                parser->load_register_dword = *ptr;
                if (bb_debug) {
                        printf("load_register_dword=0x%x\n", *ptr);
                }
        }
        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status mi_load_register_mem(struct bb_parser *parser,
                                           uint32_t *ptr)
{
        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status mi_load_register_reg(struct bb_parser *parser,
                                           uint32_t *ptr)
{
        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status mi_predicate(struct bb_parser *parser, uint32_t *ptr)
{
        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status state_base_address(struct bb_parser *parser, uint32_t *ptr)
{
        uint64_t tmp;
        
        if (parser->in_cmd == 10) {
                /* The eleventh dword in STATE_BASE_ADDRESS stores
                        * 20 of the iba bits. */
                parser->iba = (*ptr & 0xFFFFF000);
        } else if (parser->in_cmd == 11) {
                /* The twelfth dword in STATE_BASE_ADDRESS
                        * stores the majority of the iba */
                tmp = *ptr;
                parser->iba |= tmp << 32;
                if (bb_debug) {
                        printf("Found an IBA: 0x%lx\n",
                                parser->iba);
                }
        }
        
        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status compute_walker(struct bb_parser *parser,
                                     uint32_t *ptr, int pid,
                                     int stackid, char *procname)
{
        struct buffer_binding *shader_bind;
        uint64_t tmp;
        uint64_t tmp_iba;

        if (parser->in_cmd == 18) {
                tmp_iba = iba;
                if (parser->iba) {
                        tmp_iba = parser->iba;
                }
                if (!tmp_iba) {
                        fprintf(stderr, "Want shader address, but IBA is not set yet!\n");
                        return BB_PARSER_STATUS_OK;
                }
                tmp = ((*ptr & 0xffffffc0) + tmp_iba);
                parser->ksp = tmp;
        } else if (parser->in_cmd == 19) {
                tmp = *ptr;
                parser->ksp |= ((tmp & 0xffff) << 32);
                shader_bind = get_containing_binding(parser->vm, parser->ksp);
                if (shader_bind != NULL) {
                        shader_bind->type = BUFFER_TYPE_SHADER;
                        shader_bind->pid = pid;
                        if (shader_bind->execbuf_stack_str) {
                                free(shader_bind->execbuf_stack_str);
                                shader_bind->execbuf_stack_str = NULL;
                        }
                        store_stack(pid, stackid, &(shader_bind->execbuf_stack_str));
                        memcpy(shader_bind->name, procname, TASK_COMM_LEN);
                        debug_printf("Marked buffer as a shader: vm_id=%u gpu_addr=0x%lx\n",
                                     parser->vm->vm_id, shader_bind->gpu_addr);
                } else {
                        debug_printf("Did not find the shader for gpu_addr=0x%lx\n", parser->ksp);
                }
        }
        return BB_PARSER_STATUS_OK;
}

void compute_walker_simple(uint32_t *ptr, uint64_t *ksp, unsigned char in_cmd, uint64_t pc, uint64_t addr)
{
        uint64_t tmp;
        uint64_t tmp_iba;

        if (in_cmd == 18) {
                tmp_iba = iba;
                if (!tmp_iba) {
                        fprintf(stderr, "compute_walker_simple: Want shader address, but IBA is not set yet!\n");
                        return;
                }
                tmp = ((*ptr & 0xffffffc0) + tmp_iba);
                *ksp = tmp;
                printf("iba: 0x%lx\n", iba);
                printf("ksp: 0x%lx\n", *ksp);
                printf("Found ksp: 0x%lx\n", *ksp & 0xffffffff0000);
                if ((*ksp & 0xffffffff0000) == addr) {
                        printf("KSP matches addr=0x%lx at pc=0x%lx!\n", addr, pc);
                }
        }
        return;
}

void gpgpu_walker_simple(uint32_t *ptr, uint64_t *ksp, unsigned char in_cmd, uint64_t iba, uint64_t addr)
{
#if 0
        uint64_t tmp;
        uint64_t tmp_iba;

        if (in_cmd == 18) {
                tmp_iba = iba;
                if (iba) {
                        tmp_iba = iba;
                }
                if (!tmp_iba) {
                        fprintf(stderr, "Want shader address, but IBA is not set yet!\n");
                        return;
                }
                tmp = ((*ptr & 0xffffffc0) + tmp_iba);
                *ksp = tmp;
                printf("iba is: 0x%lx\n", iba);
        } else if (in_cmd == 19) {
                tmp = *ptr;
                *ksp |= ((tmp & 0xffff) << 32);
                printf("Found ksp: 0x%lx\n", *ksp);
                if ((*ksp & 0xffffffff) == addr) {
                        printf("KSP matches addr 0x%lx!\n", addr);
                }
        }
#endif
        return;
}

enum bb_parser_status mi_batch_buffer_start(struct bb_parser *parser,
                                            uint32_t *ptr)
{
        uint64_t tmp;
        tree_it(uint64_t, char) it;

        if (parser->in_cmd == 0) {
                parser->enable_predication = *ptr & 0x8000;
                if (bb_debug) {
                        printf("enable_predication=%u\n",
                               parser->enable_predication);
                }
        } else if (parser->in_cmd == 1) {
                parser->bb2l = MI_BATCH_BUFFER_START_2ND_LEVEL(*ptr);
                if (bb_debug) {
                        printf("bb2l=%u\n", parser->bb2l);
                }
                parser->bbsp = 0;
                parser->bbsp |= *ptr;
        } else if (parser->in_cmd == 2) {
                
                /* Collect the BBSP (Batch Buffer Start Pointer) */
                tmp = *ptr;
                parser->bbsp |= tmp << 32;
                if (bb_debug) {
                        printf("bbsp=0x%lx\n", parser->bbsp);
                }
                
                /* Try to detect recursion and stop */
                if (parser->bbsp == (parser->pc[parser->pc_depth] - 8)) {
                        if (bb_debug) {
                                printf("Recursion!\n");
                        }
                        return BB_PARSER_STATUS_NOTFOUND;
                }
                it = tree_lookup(parser->visited_addresses, parser->bbsp);
                if (tree_it_good(it)) {
                        if (bb_debug) {
                                printf("Recursion!\n");
                        }
                        return BB_PARSER_STATUS_NOTFOUND;
                }
                tree_insert(parser->visited_addresses, parser->bbsp, 1);


                if (parser->bb2l && (parser->pc_depth == 1)) {
                        /* Advance the program counter by the number of dwords in
                           an MI_BATCH_BUFFER_START command, minus one (since we're
                           going to increment this by one in the parser loop) */
                        parser->pc[parser->pc_depth] +=
                                (4 * (MI_BATCH_BUFFER_START_DWORDS - 1));
                        parser->pc_depth++;
                }
                parser->pc[parser->pc_depth] = parser->bbsp - 4;

                if (!find_jump_buffer(parser, parser->bbsp)) {
                        if (bb_debug) {
                                fprintf(stderr,
                                        "WARNING: Couldn't find a buffer ");
                                fprintf(stderr,
                                        " that encompasses the BBSP 0x%lx\n",
                                        parser->bbsp);
                        }
                        return BB_PARSER_STATUS_NOTFOUND;
                }

                if (!(parser->bo)) {
                        /* We know we're supposed to jump *somewhere*,
			 * but can't. */
                        if (bb_debug) {
                                fprintf(stderr, "WARNING: A batch buffer was");
                                fprintf(stderr,
                                        " supposed to chain somewhere,");
                                fprintf(stderr,
                                        " but we don't have a copy of it. (gpu_addr=0x%lx)\n",
                                        parser->bind->gpu_addr);
                        }
                        return BB_PARSER_STATUS_NOTFOUND;
                }
                parser->enable_predication = 0;
        }

        return BB_PARSER_STATUS_OK;
}

char mi_batch_buffer_end(struct bb_parser *parser)
{
        if (parser->pc_depth == 0) {
                return 1;
        }
        parser->pc_depth--;
        return 0;
}

void bb_parser_init(struct bb_parser *parser)
{
        memset(parser, 0, sizeof(struct bb_parser));
        parser->visited_addresses = tree_make(uint64_t, char);
}


enum bb_parser_status bb_parser_parse(struct bb_parser *parser,
                                      struct vm_profile *acquired_vm,
                                      struct buffer_binding *bind,
                                      uint32_t offset, uint64_t size,
                                      int pid, int stackid, char *procname)
{
        uint32_t *dword_ptr, op;
        uint64_t off, tmp, noops;
        enum bb_parser_status retval;
        
        /* Loop over 32-bit dwords. */
        parser->pc_depth = 1;
        parser->pc[parser->pc_depth] = bind->gpu_addr + offset;
        parser->batch_len[parser->pc_depth] = size;
        parser->vm = acquired_vm;
        parser->bind = bind;
        parser->in_cmd = 0;
        parser->cur_cmd = 0;
        parser->num_dwords = 0;
        noops = 0;

        parser->bo = acquire_buffer(parser->bind->file, parser->bind->handle);
        if (parser->bo == NULL) {
                fprintf(stderr,
                        "WARNING: can't parse vm_id=%u gpu_addr=0x%lx because we don't have a copy of it\n",
                        parser->bind->vm_id, parser->bind->gpu_addr);
                retval = BB_PARSER_STATUS_NOTFOUND;
                goto out;
        }

        while (parser->pc_depth > 0) {
                off = parser->pc[parser->pc_depth] -
                      parser->bind->gpu_addr;
                dword_ptr = (uint32_t *)(parser->bo->buff + off);

                /* First check if we're overflowing the buffer */
                if (off >= parser->bo->buff_sz) {
                        if (bb_debug) {
                                printf("Stop because of buffer size. off=0x%lx sz=0x%lx\n",
                                       off, parser->bo->buff_sz);
                        }
                        retval = BB_PARSER_STATUS_BUFF_OVERFLOW;
                        goto out;
                }

                if (bb_debug) {
                        printf("size=0x%lx dword=0x%x offset=0x%lx\n", size,
                               *dword_ptr, off);
                        printf("in_cmd=%u cur_cmd=%lu cur_num_dwords=%u\n",
                               parser->in_cmd, parser->cur_cmd,
                               parser->cur_num_dwords);
                }

                /* Keep track of how many dwords we've parsed */
                parser->num_dwords++;

                if (!parser->cur_cmd) {
                        op = (*dword_ptr) >> (32 - op_len(dword_ptr));
                        if (CMD_TYPE(*dword_ptr) == CMD_2D) {
                                op = op & 0x7F;
                        } else if (CMD_TYPE(*dword_ptr) == GFXPIPE) {
                                op = op & OP_3D;
                        }

                        /* Decode which op this is */
                        switch (op) {
                        case MI_BATCH_BUFFER_START:
                                if (bb_debug) {
                                        printf("op=MI_BATCH_BUFFER_START\n");
                                }
                                parser->cur_cmd = MI_BATCH_BUFFER_START;
                                parser->cur_num_dwords =
                                        MI_BATCH_BUFFER_START_DWORDS;
                                break;
                        case MI_PRT_BATCH_BUFFER_START:
                                if (bb_debug) {
                                        printf("op=MI_PRT_BATCH_BUFFER_START\n");
                                }
                                parser->cur_cmd = MI_PRT_BATCH_BUFFER_START;
                                parser->cur_num_dwords =
                                        MI_PRT_BATCH_BUFFER_START_DWORDS;
                                break;
                        case MI_NOOP:
                                noops++;

                                if (bb_debug) {
                                        printf("op=MI_NOOP %lu\n", noops);
                                }

                                if (noops == 32) {
                                        if (bb_debug) {
                                                printf("Too many NOOPs!\n");
                                        }
                                        retval = BB_PARSER_STATUS_OK;
                                        goto out;
                                }

                                parser->cur_cmd = MI_NOOP;
                                parser->cur_num_dwords = MI_NOOP_DWORDS;
                                break;
                        case MI_FLUSH_DW:
                                if (bb_debug) {
                                        printf("op=MI_FLUSH_DW\n");
                                }
                                parser->cur_cmd = MI_FLUSH_DW;
                                parser->cur_num_dwords = MI_FLUSH_DW_DWORDS;
                                break;
                        case STATE_BASE_ADDRESS:
                                if (bb_debug) {
                                        printf("op=STATE_BASE_ADDRESS\n");
                                }
                                parser->cur_cmd = STATE_BASE_ADDRESS;
                                parser->cur_num_dwords =
                                        STATE_BASE_ADDRESS_DWORDS;
                                break;
                        case STATE_SIP:
                                if (bb_debug) {
                                        printf("op=STATE_SIP\n");
                                }
                                parser->cur_cmd = STATE_SIP;
                                parser->cur_num_dwords = STATE_SIP_DWORDS;
                                break;
                        case STATE_SYSTEM_MEM_FENCE_ADDRESS:
                                if (bb_debug) {
                                        printf("op=STATE_SYSTEM_MEM_FENCE_ADDRESS\n");
                                }
                                parser->cur_cmd =
                                        STATE_SYSTEM_MEM_FENCE_ADDRESS;
                                parser->cur_num_dwords =
                                        STATE_SYSTEM_MEM_FENCE_ADDRESS_DWORDS;
                                break;
                        case COMPUTE_WALKER:
                                if (bb_debug) {
                                        printf("op=COMPUTE_WALKER\n");
                                }
                                parser->cur_cmd = COMPUTE_WALKER;
                                parser->cur_num_dwords = COMPUTE_WALKER_DWORDS;
                                break;
                        case CFE_STATE:
                                if (bb_debug) {
                                        printf("op=CFE_STATE\n");
                                }
                                parser->cur_cmd = CFE_STATE;
                                parser->cur_num_dwords = CFE_STATE_DWORDS;
                                break;
                        case GPGPU_WALKER:
                                if (bb_debug) {
                                        printf("op=GPGPU_WALKER\n");
                                }
                                parser->cur_cmd = GPGPU_WALKER;
                                parser->cur_num_dwords = GPGPU_WALKER_DWORDS;
                                break;
                        case MI_BATCH_BUFFER_END:
                                if (bb_debug) {
                                        printf("op=MI_BATCH_BUFFER_END\n");
                                }
                                parser->cur_cmd = MI_BATCH_BUFFER_END;
                                parser->cur_num_dwords =
                                        MI_BATCH_BUFFER_END_DWORDS;
                                break;
                        case MI_CONDITIONAL_BATCH_BUFFER_END:
                                if (bb_debug) {
                                        printf("op=MI_CONDITIONAL_BATCH_BUFFER_END\n");
                                }
                                parser->cur_cmd =
                                        MI_CONDITIONAL_BATCH_BUFFER_END;
                                parser->cur_num_dwords =
                                        MI_CONDITIONAL_BATCH_BUFFER_END_DWORDS;
                                break;
                        case MI_PREDICATE:
                                if (bb_debug) {
                                        printf("op=MI_PREDICATE\n");
                                }
                                parser->cur_cmd = MI_PREDICATE;
                                parser->cur_num_dwords = MI_PREDICATE_DWORDS;
                                break;
                        case MI_STORE_REGISTER_MEM:
                                if (bb_debug) {
                                        printf("op=MI_STORE_REGISTER_MEM\n");
                                }
                                parser->cur_cmd = MI_STORE_REGISTER_MEM;
                                parser->cur_num_dwords =
                                        MI_STORE_REGISTER_MEM_DWORDS;
                                break;
                        case MI_STORE_DATA_IMM:
                                if (bb_debug) {
                                        printf("op=MI_STORE_DATA_IMM\n");
                                }
                                parser->cur_cmd = MI_STORE_DATA_IMM;
                                parser->cur_num_dwords =
                                        MI_STORE_DATA_IMM_DWORDS;
                                break;
                        case MI_ARB_CHECK:
                                if (bb_debug) {
                                        printf("op=MI_ARB_CHECK\n");
                                }
                                parser->cur_cmd = MI_ARB_CHECK;
                                parser->cur_num_dwords =
                                        MI_ARB_CHECK_DWORDS;
                                break;
                        case MI_ARB_ON_OFF:
                                if (bb_debug) {
                                        printf("op=MI_ARB_ON_OFF\n");
                                }
                                parser->cur_cmd = MI_ARB_ON_OFF;
                                parser->cur_num_dwords =
                                        MI_ARB_ON_OFF_DWORDS;
                                break;
                        case MI_URB_ATOMIC_ALLOC:
                                if (bb_debug) {
                                        printf("op=MI_URB_ATOMIC_ALLOC\n");
                                }
                                parser->cur_cmd = MI_URB_ATOMIC_ALLOC;
                                parser->cur_num_dwords =
                                        MI_URB_ATOMIC_ALLOC_DWORDS;
                                break;
                        case MI_LOAD_REGISTER_IMM:
                                if (bb_debug) {
                                        printf("op=MI_LOAD_REGISTER_IMM\n");
                                }
                                parser->cur_cmd = MI_LOAD_REGISTER_IMM;
                                parser->cur_num_dwords =
                                        MI_LOAD_REGISTER_IMM_DWORDS;
                                break;
                        case MI_LOAD_REGISTER_REG:
                                if (bb_debug) {
                                        printf("op=MI_LOAD_REGISTER_REG\n");
                                }
                                parser->cur_cmd = MI_LOAD_REGISTER_REG;
                                parser->cur_num_dwords =
                                        MI_LOAD_REGISTER_REG_DWORDS;
                                break;
                        case MI_LOAD_REGISTER_MEM:
                                if (bb_debug) {
                                        printf("op=MI_LOAD_REGISTER_MEM\n");
                                }
                                parser->cur_cmd = MI_LOAD_REGISTER_MEM;
                                parser->cur_num_dwords =
                                        MI_LOAD_REGISTER_MEM_DWORDS;
                                break;
                        case PIPE_CONTROL:
                                if (bb_debug) {
                                        printf("op=PIPE_CONTROL\n");
                                }
                                parser->cur_cmd = PIPE_CONTROL;
                                parser->cur_num_dwords = PIPE_CONTROL_DWORDS;
                                break;
                        case PIPELINE_SELECT:
                                if (bb_debug) {
                                        printf("op=PIPELINE_SELECT\n");
                                }
                                parser->cur_cmd = PIPELINE_SELECT;
                                parser->cur_num_dwords = PIPELINE_SELECT_DWORDS;
                                break;
                        case MI_SEMAPHORE_WAIT:
                                if (bb_debug) {
                                        printf("op=MI_SEMAPHORE_WAIT\n");
                                }
                                parser->cur_cmd = MI_SEMAPHORE_WAIT;
                                parser->cur_num_dwords =
                                        MI_SEMAPHORE_WAIT_DWORDS;
                                break;
                        case MEM_COPY:
                                if (bb_debug) {
                                        printf("op=MEM_COPY\n");
                                }
                                parser->cur_cmd = MEM_COPY;
                                parser->cur_num_dwords = MEM_COPY_DWORDS;
                                break;
                        default:
                                if (bb_debug) {
                                        printf("op=UNKNOWN (0x%x)\n", op);
                                }
                                break;
                        }
                }

                /* Consume this command's dwords */
                switch (parser->cur_cmd) {
                case MI_BATCH_BUFFER_START:
                        retval = mi_batch_buffer_start(parser, dword_ptr);
                        if (retval != BB_PARSER_STATUS_OK) {
                                goto out;
                        }
                        break;
                case MI_PRT_BATCH_BUFFER_START:
                        retval = mi_batch_buffer_start(parser, dword_ptr);
                        if (retval != BB_PARSER_STATUS_OK) {
                                goto out;
                        }
                        break;
                case MI_BATCH_BUFFER_END:
                        if (mi_batch_buffer_end(parser)) {
                                return BB_PARSER_STATUS_OK;
                        }
                        break;
                case MI_LOAD_REGISTER_IMM:
                        retval = mi_load_register_imm(parser, dword_ptr);
                        if (retval != BB_PARSER_STATUS_OK) {
                                goto out;
                        }
                        break;
                case MI_PREDICATE:
                        retval = mi_predicate(parser, dword_ptr);
                        if (retval != BB_PARSER_STATUS_OK) {
                                goto out;
                        }
                        break;
                case MI_SEMAPHORE_WAIT:
                        break;
                case STATE_BASE_ADDRESS:
                        retval = state_base_address(parser, dword_ptr);
                        if (retval != BB_PARSER_STATUS_OK) {
                                return retval;
                        }
                        break;
                case STATE_SIP:
                        if (parser->in_cmd == 1) {
                                parser->sip |= *dword_ptr;
                        } else if (parser->in_cmd == 2) {
                                tmp = *dword_ptr;
                                parser->sip |= tmp << 32;
                        }
                        break;
                case COMPUTE_WALKER:
                        retval = compute_walker(parser, dword_ptr, pid, stackid, procname);
                        if (retval != BB_PARSER_STATUS_OK) {
                                goto out;
                        }
                        break;
                }

                if (parser->cur_cmd) {
                        /* If we're in a command already, advance to the next dword within it */

                        if (parser->in_cmd == parser->cur_num_dwords - 1) {
                                /* We've consumed all of this command's dwords,
				 * so go back to looking for new commands. */
                                parser->in_cmd = 0;
                                parser->cur_cmd = 0;
                                parser->cur_num_dwords = 0;
                        } else {
                                /* Keep looking for dwords that this command needs */
                                parser->in_cmd++;
                        }
                }

                /* Next dword in the buffer */
                parser->pc[parser->pc_depth] += 4;
                if (bb_debug) {
                        printf("Advancing the PC to 0x%lx\n",
                               parser->pc[parser->pc_depth]);
                }
        }

out:;
        if (parser->bo != NULL) {
                release_buffer(parser->bo);
        }

        if (bb_debug) {
                printf("Finished batchbuffer parsing.\n");
        }
        return retval;
}

uint64_t bb_parser_find_addr(struct buffer_binding *bind, uint64_t addr)
{
        uint8_t cur_num_dwords;
        uint32_t *dword_ptr, op;
        uint64_t pc, off, cur_cmd, ksp;
        unsigned char in_cmd;
        struct buffer_object *bo;
        enum bb_parser_status retval;
        
        if (bb_debug) {
                printf("Looking for addr=0x%lx\n", addr);
        }
        
        bo = acquire_buffer(bind->file, bind->handle);
        if (bo == NULL) {
                fprintf(stderr,
                        "WARNING: can't parse vm_id=%u gpu_addr=0x%lx because we don't have a copy of it\n",
                        bind->vm_id, bind->gpu_addr);
                retval = BB_PARSER_STATUS_NOTFOUND;
                goto out;
        }

        /* Loop over 32-bit dwords. */
        pc = bind->gpu_addr;
        in_cmd = 0;
        cur_cmd = 0;
        while (1) {
                off = pc - bind->gpu_addr;
                dword_ptr = (uint32_t *)(bo->buff + off);

                /* First check if we're overflowing the buffer */
                if (off >= bo->buff_sz) {
                        if (bb_debug) {
                                printf("Stop because of buffer size. off=0x%lx sz=0x%lx\n",
                                       off, bo->buff_sz);
                        }
                        retval = BB_PARSER_STATUS_BUFF_OVERFLOW;
                        goto out;
                }

                if (!cur_cmd) {
                        op = (*dword_ptr) >> (32 - op_len(dword_ptr));
                        if (CMD_TYPE(*dword_ptr) == CMD_2D) {
                                op = op & 0x7F;
                        } else if (CMD_TYPE(*dword_ptr) == GFXPIPE) {
                                op = op & OP_3D;
                        }

                        /* Decode which op this is */
                        switch (op) {
                        case COMPUTE_WALKER:
                                if (bb_debug) {
                                        printf("op=COMPUTE_WALKER\n");
                                }
                                cur_cmd = COMPUTE_WALKER;
                                cur_num_dwords = COMPUTE_WALKER_DWORDS;
                                break;
                        case GPGPU_WALKER:
                                if (bb_debug) {
                                        printf("op=GPGPU_WALKER\n");
                                }
                                cur_cmd = GPGPU_WALKER;
                                cur_num_dwords = GPGPU_WALKER_DWORDS;
                                break;
                        case MI_SEMAPHORE_WAIT:
                                if (bb_debug) {
                                        printf("op=MI_SEMAPHORE_WAIT\n");
                                }
                                cur_cmd = MI_SEMAPHORE_WAIT;
                                cur_num_dwords = MI_SEMAPHORE_WAIT_DWORDS;
                                break;
                        default:
                                break;
                        }
                }

                /* Consume this command's dwords */
                switch (cur_cmd) {
                case COMPUTE_WALKER:
                        if (bb_debug) {
                                printf("size=0x%lx dword=0x%x offset=0x%lx\n", bo->buff_sz,
                                *dword_ptr, off);
                                printf("in_cmd=%u cur_cmd=%lu cur_num_dwords=%u\n",
                                in_cmd, cur_cmd, cur_num_dwords);
                        }
                        compute_walker_simple(dword_ptr, &ksp, in_cmd, pc, addr);
                        break;
                case GPGPU_WALKER:
                        if (bb_debug) {
                                printf("size=0x%lx dword=0x%x offset=0x%lx\n", bo->buff_sz,
                                *dword_ptr, off);
                                printf("in_cmd=%u cur_cmd=%lu cur_num_dwords=%u\n",
                                in_cmd, cur_cmd, cur_num_dwords);
                        }
                        gpgpu_walker_simple(dword_ptr, &ksp, in_cmd, pc, addr);
                        break;
                }

                if (cur_cmd) {
                        /* If we're in a command already, advance to the next dword within it */

                        if (in_cmd == cur_num_dwords - 1) {
                                /* We've consumed all of this command's dwords,
				 * so go back to looking for new commands. */
                                in_cmd = 0;
                                cur_cmd = 0;
                                cur_num_dwords = 0;
                        } else {
                                /* Keep looking for dwords that this command needs */
                                in_cmd++;
                        }
                }

                /* Next dword in the buffer */
                pc += 4;
        }

out:;
        if (bo != NULL) {
                release_buffer(bo);
        }

        if (bb_debug) {
                printf("Finished batchbuffer parsing.\n");
        }
        return retval;
}
