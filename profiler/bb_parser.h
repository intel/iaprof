#pragma once

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "event_collector.h"

/* STATE_BASE_ADDRESS::InstructionBaseAddress + ((INTERFACE_DESCRIPTOR_DATA */
/* *)(STATE_BASE_ADDRESS::DynamicBaseAddress + InterfaceDescriptorDataStartAddress))->KernelStartPointer */

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

/******************************************************************************
* Parser Context
* *********
* This structure stores all the information the parser wants to find, and
* intermediate data and register values that it needs to continue parsing.
******************************************************************************/
struct bb_parser {
	uint64_t pc[3];
        uint64_t batch_len[3];
	char pc_depth;
	unsigned char in_cmd;
	uint64_t cur_cmd;
	unsigned char cur_num_dwords;

	struct buffer_profile *gem;
        int gem_index;

        /* Bookkeeping. Number of dwords that we've parsed. */
        uint64_t num_dwords;
        
        /* Should we update the buffer for this? */
        char *update_copy;

	/* Instruction Base Address */
	uint64_t iba;

	/* SIP, or System Instruction Pointer.
	   This is an offset from the iba,
	   or Instruction Base Address. */
	uint64_t sip;

	/* Batch Buffer Start Pointer */
	uint64_t bbsp;
	char bb2l;

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
};


/******************************************************************************
* Registers
* *********
* Helpers for dealing with registers.
******************************************************************************/
/* General-purpose registers */
#define GPR_OFFSET 0x2600
#define GPR_REG(i) (GPR_OFFSET + (i) * 8)

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
        if (offset >= GPR_REG(0) &&
                offset < GPR_REG(16)) {
                return &parser->gpr32[(offset - GPR_OFFSET) / 4];
        } else {
                bool off = (offset & 0x7ull) != 0;
                switch (offset & ~0x7ull) {
                case PREDICATE_SRC0:
                        return ((uint32_t *) &parser->predicate.src0) + (off ? 1 : 0);
                case PREDICATE_SRC1:
                        return ((uint32_t *) &parser->predicate.src1) + (off ? 1 : 0);
                case PREDICATE_RESULT:
                        return ((uint32_t *) &parser->predicate.result) + (off ? 1 : 0);
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
#define CMD_3D_MEDIA 3

#define OP_LEN_MI 9
#define OP_LEN_2D 10
#define OP_LEN_3D_MEDIA 16
#define OP_LEN_MFX_VC 16
#define OP_LEN_VEBOX 16

uint32_t op_len(uint32_t *bb)
{
	switch (CMD_TYPE(*bb)) {
	case CMD_MI:
		if (bb_debug) {
			printf("cmd_type=CMD_MI\n");
		}
		return OP_LEN_MI;
	case CMD_3D_MEDIA:
		if (bb_debug) {
			printf("cmd_type=CMD_3D_MEDIA\n");
		}
		return OP_LEN_3D_MEDIA;
	case CMD_2D:
		if (bb_debug) {
			printf("cmd_type=CMD_2D\n");
		}
		return OP_LEN_2D;
	default:
		if (bb_debug) {
			printf("cmd_type=UNKNOWN (0x%x)\n", CMD_TYPE(*bb));
		}
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

#define MI_LOAD_REGISTER_IMM 0x22
#define MI_LOAD_REGISTER_IMM_DWORDS 3

#define MI_LOAD_REGISTER_MEM 0x29
#define MI_LOAD_REGISTER_MEM_DWORDS 4

#define MI_LOAD_REGISTER_REG 0x2a
#define MI_LOAD_REGISTER_REG_DWORDS 3

#define MI_FLUSH_DW 0x26
#define MI_FLUSH_DW_DWORDS 5

#define MI_NOOP 0x00
#define MI_NOOP_DWORDS 1

/* 2D/XY Commands */

#define MEM_COPY 0x5a
#define MEM_COPY_DWORDS 10

/* 3D/Media Commands: Pipeline Type(28:27) Opcode(26:24) Sub Opcode(23:16) */
#define OP_3D_MEDIA(sub_type, opcode, sub_opcode) \
	((3 << 13) | ((sub_type) << 11) | ((opcode) << 8) | (sub_opcode))
#define OP_3D ((3 << 13) | (0xF << 11) | (0xF << 8) | (0xFF))

#define PIPE_CONTROL OP_3D_MEDIA(0x3, 0x2, 0x0)
#define PIPE_CONTROL_DWORDS 6

#define COMPUTE_WALKER OP_3D_MEDIA(0x2, 0x2, 0x8)
#define COMPUTE_WALKER_DWORDS 39

#define STATE_BASE_ADDRESS OP_3D_MEDIA(0x0, 0x1, 0x01)
#define STATE_BASE_ADDRESS_DWORDS 22

#define STATE_SIP OP_3D_MEDIA(0x0, 0x1, 0x02)
#define STATE_SIP_DWORDS 3

#define STATE_SYSTEM_MEM_FENCE_ADDRESS OP_3D_MEDIA(0x0, 0x1, 0x9)
#define STATE_SYSTEM_MEM_FENCE_ADDRESS_DWORDS 3

struct bb_parser *bb_parser_init()
{
	struct bb_parser *parser;
        int n;

	parser = calloc(1, sizeof(struct bb_parser));
        parser->update_copy = calloc(buffer_profile_used, sizeof(char));
        for (n = 0; n < buffer_profile_used; n++) {
                parser->update_copy[n] = 1;
        }

	return parser;
}

void find_jump_buffer(struct bb_parser *parser, uint64_t bbsp)
{
	struct buffer_profile *gem;
	uint64_t n, start, end;

	for (n = 0; n < buffer_profile_used; n++) {
		gem = &buffer_profile_arr[n];
		start = gem->vm_bind_info.gpu_addr;
		end = start + gem->vm_bind_info.size;
		if ((bbsp >= start) && (bbsp < end)) {
			if (bb_debug) {
				printf("Found a matching batch buffer ");
				printf("to jump to. handle=%u gpu_addr=0x%llx\n",
				       gem->vm_bind_info.handle,
				       gem->vm_bind_info.gpu_addr);
			}
                        parser->gem = gem;
                        parser->gem_index = n;
			return;
		}
	}
	return;
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

enum bb_parser_status mi_load_register_imm(struct bb_parser *parser, uint32_t *ptr)
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

enum bb_parser_status mi_load_register_mem(struct bb_parser *parser, uint32_t *ptr)
{
        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status mi_load_register_reg(struct bb_parser *parser, uint32_t *ptr)
{
        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status mi_predicate(struct bb_parser *parser, uint32_t *ptr)
{
        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status mi_batch_buffer_start(struct bb_parser *parser,
					    uint32_t *ptr)
{
	uint64_t tmp, bbsp_offset;

        if (parser->in_cmd == 0) {
                parser->enable_predication = *ptr & 0x8000;
                if (bb_debug) {
                        printf("enable_predication=%u\n", parser->enable_predication);
                }
	} else if (parser->in_cmd == 1) {
		parser->bb2l = MI_BATCH_BUFFER_START_2ND_LEVEL(*ptr);
		if (bb_debug) {
			printf("bb2l=%u\n", parser->bb2l);
		}
		parser->bbsp = 0;
		parser->bbsp |= *ptr;
	} else if (parser->in_cmd == 2) {
		tmp = *ptr;
		parser->bbsp |= tmp << 32;
		if (bb_debug) {
			printf("bbsp=0x%lx\n", parser->bbsp);
		}

		if (parser->bb2l && (parser->pc_depth == 1)) {
                        /* Advance the program counter by the number of dwords in
                           an MI_BATCH_BUFFER_START command, minus one (since we're
                           going to increment this by one in the parser loop) */
			parser->pc[parser->pc_depth] +=
				(4 * (MI_BATCH_BUFFER_START_DWORDS - 1));
			parser->pc_depth++;
		}
		parser->pc[parser->pc_depth] = parser->bbsp - 4;

		find_jump_buffer(parser, parser->bbsp);
		if (!parser->gem) {
			if (bb_debug) {
				fprintf(stderr,
					"WARNING: Couldn't find a buffer ");
				fprintf(stderr,
					" that encompasses the BBSP 0x%lx\n",
					parser->bbsp);
			}
			return BB_PARSER_STATUS_NOTFOUND;
		}

/*                 if (parser->update_copy[parser->gem_index]) { */
/*         		update_buffer_copy(parser->gem); */
/*                         parser->update_copy[parser->gem_index] = 0; */
/*                 } */

		if (!(parser->gem->buff)) {
			/* We know we're supposed to jump *somewhere*, 
			 * but can't. */
			if (bb_debug) {
				fprintf(stderr, "WARNING: A batch buffer was");
				fprintf(stderr,
					" supposed to chain somewhere,");
				fprintf(stderr,
					" but we don't have a copy of it.\n");
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

enum bb_parser_status bb_parser_parse(struct bb_parser *parser,
				      struct buffer_profile *gem,
				      uint32_t offset, uint64_t size)
{
	uint32_t *dword_ptr, op;
	uint64_t off, tmp, root_off;
        enum bb_parser_status retval;
        
        gem->parsed = 1;

	/* Loop over 32-bit dwords. */
	parser->pc_depth = 1;
	parser->pc[parser->pc_depth] = gem->vm_bind_info.gpu_addr + offset;
        parser->batch_len[parser->pc_depth] = size;
	parser->gem = gem;
	parser->in_cmd = 0;
	parser->cur_cmd = 0;
        parser->num_dwords = 0;
	while (parser->pc_depth > 0) {
		off = parser->pc[parser->pc_depth] -
		      parser->gem->vm_bind_info.gpu_addr;
		dword_ptr = (uint32_t *)(parser->gem->buff + off);

                /* First check if we're overflowing the buffer */
                if (off > parser->gem->buff_sz) {
                        if (bb_debug) {
                                printf("Stop because of buffer size. off=0x%lx sz=0x%lx\n",
                                       off, parser->gem->buff_sz);
                        }
                        return BB_PARSER_STATUS_BUFF_OVERFLOW;
                }

                /* XXX: The experimental mi_runner tool, an uncommitted PR to mesa,
                   does not actually check the batch_len at all; it relies on seeing
                   the proper MI_BATCH_BUFFER_END commands to stop the parsing.
                   Should we do the same...? */
		if (parser->batch_len[parser->pc_depth]) {
                        root_off = parser->pc[parser->pc_depth] -
                                   gem->vm_bind_info.gpu_addr - offset;
                        if(root_off >= parser->batch_len[parser->pc_depth]) {
                                /* Make sure we stop once we get to the end of the
                                   first-level batchbuffer commands (which in the i915
                                   kernel, is batch_len bytes long) */
        			if (bb_debug) {
        				printf("Stop because of batch_len. off=0x%lx sz=0x%lx.\n",
        				       root_off, parser->batch_len[parser->pc_depth]);
        			}
        			return BB_PARSER_STATUS_OK;
                        }
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
                        if(CMD_TYPE(*dword_ptr) == CMD_2D) {
                                op = op & 0x7F;
                        } else if(CMD_TYPE(*dword_ptr) == CMD_3D_MEDIA) {
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
				if (bb_debug) {
					printf("op=MI_NOOP\n");
				}
				parser->cur_cmd = MI_NOOP;
				parser->cur_num_dwords =
					MI_NOOP_DWORDS;
				break;
			case MI_FLUSH_DW:
				if (bb_debug) {
					printf("op=MI_FLUSH_DW\n");
				}
				parser->cur_cmd = MI_FLUSH_DW;
				parser->cur_num_dwords =
					MI_FLUSH_DW_DWORDS;
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
				parser->cur_cmd = STATE_SYSTEM_MEM_FENCE_ADDRESS;
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
				parser->cur_num_dwords = MI_STORE_REGISTER_MEM_DWORDS;
				break;
			case MI_LOAD_REGISTER_IMM:
				if (bb_debug) {
					printf("op=MI_LOAD_REGISTER_IMM\n");
				}
				parser->cur_cmd = MI_LOAD_REGISTER_IMM;
				parser->cur_num_dwords = MI_LOAD_REGISTER_IMM_DWORDS;
				break;
			case MI_LOAD_REGISTER_REG:
				if (bb_debug) {
					printf("op=MI_LOAD_REGISTER_REG\n");
				}
				parser->cur_cmd = MI_LOAD_REGISTER_REG;
				parser->cur_num_dwords = MI_LOAD_REGISTER_REG_DWORDS;
				break;
			case MI_LOAD_REGISTER_MEM:
				if (bb_debug) {
					printf("op=MI_LOAD_REGISTER_MEM\n");
				}
				parser->cur_cmd = MI_LOAD_REGISTER_MEM;
				parser->cur_num_dwords = MI_LOAD_REGISTER_MEM_DWORDS;
				break;
			case PIPE_CONTROL:
				if (bb_debug) {
					printf("op=PIPE_CONTROL\n");
				}
				parser->cur_cmd = PIPE_CONTROL;
				parser->cur_num_dwords = PIPE_CONTROL_DWORDS;
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
				parser->cur_num_dwords =
					MEM_COPY_DWORDS;
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
                        if(retval != BB_PARSER_STATUS_OK) {
                                return retval;
                        }
			break;
		case MI_PRT_BATCH_BUFFER_START:
			retval = mi_batch_buffer_start(parser, dword_ptr);
                        if(retval != BB_PARSER_STATUS_OK) {
                                return retval;
                        }
			break;
		case MI_BATCH_BUFFER_END:
			if (mi_batch_buffer_end(parser)) {
				return BB_PARSER_STATUS_OK;
			}
			break;
		case MI_LOAD_REGISTER_IMM:
			retval = mi_load_register_imm(parser, dword_ptr);
                        if(retval != BB_PARSER_STATUS_OK) {
                                return retval;
                        }
			break;
                case MI_PREDICATE:
                        retval = mi_predicate(parser, dword_ptr);
                        if (retval != BB_PARSER_STATUS_OK) {
                                return retval;
                        }
                        break;
		case MI_SEMAPHORE_WAIT:
			/* TODO: do *something* to handle the semaphor.
                         * Sleeping is a non-starter. */
			break;
		case STATE_BASE_ADDRESS:
			if (parser->in_cmd == 10) {
				/* The eleventh dword in STATE_BASE_ADDRESS stores
                                 * 20 of the iba bits. */
				parser->iba |= (*dword_ptr & 0xFFFFF000);
			} else if (parser->in_cmd == 11) {
				/* The twelfth dword in STATE_BASE_ADDRESS 
                                 * stores the majority of the iba */
				tmp = *dword_ptr;
				parser->iba |= tmp << 32;
				if (bb_debug) {
					printf("Found an IBA: 0x%lx\n",
					       parser->iba);
				}
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

	if (bb_debug) {
		printf("Finished batchbuffer parsing.\n");
	}
	return BB_PARSER_STATUS_OK;
}
