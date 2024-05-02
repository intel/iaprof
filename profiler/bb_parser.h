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
	BB_PARSER_STATUS_BUFFER_OVERFLOW,
	BB_PARSER_STATUS_NOTFOUND,
};

/******************************************************************************
* Commands
* *********
* These are constants that represent batch buffer commands
******************************************************************************/
#define CMD_TYPE(cmd) (((cmd) >> 29) & 7)
#define CMD_MI 0
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
		if (debug) {
			printf("cmd_type=CMD_MI\n");
		}
		return OP_LEN_MI;
	case CMD_3D_MEDIA:
		if (debug) {
			printf("cmd_type=CMD_3D_MEDIA\n");
		}
		return OP_LEN_3D_MEDIA;
	default:
		if (debug) {
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

#define MI_CONDITIONAL_BATCH_BUFFER_END 0x36
#define MI_CONDITIONAL_BATCH_BUFFER_END_DWORDS 4

#define MI_BATCH_BUFFER_END 0x0a
#define MI_BATCH_BUFFER_END_DWORDS 1

#define MI_SEMAPHORE_WAIT 0x1c
#define MI_SEMAPHORE_WAIT_DWORDS 5

#define MI_PREDICATE 0x0c
#define MI_PREDICATE_DWORDS 1

/* 3D/Media Command: Pipeline Type(28:27) Opcode(26:24) Sub Opcode(23:16) */
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

/******************************************************************************
* bb_parser
* *********
* This structure stores all the information the parser wants to find.
* The end goal here is to parse out all references to GPU kernel pointers.
******************************************************************************/
struct bb_parser {
	uint64_t pc[3];
	char pc_depth;
	unsigned char in_cmd;
	struct buffer_profile *gem;
	uint64_t cur_cmd;
	unsigned char cur_num_dwords;

	/* Instruction Base Address */
	uint64_t iba;

	/* SIP, or System Instruction Pointer.
	   This is an offset from the iba,
	   or Instruction Base Address. */
	uint64_t sip;

	/* Batch Buffer Start Pointer */
	uint64_t bbsp;
	char bb2l;
};

struct bb_parser *bb_parser_init()
{
	struct bb_parser *parser;

	parser = calloc(1, sizeof(struct bb_parser));
	return parser;
}

struct buffer_profile *find_jump_buffer(uint64_t bbsp)
{
	struct buffer_profile *gem;
	uint64_t n, start, end;

	for (n = 0; n < buffer_profile_used; n++) {
		gem = &buffer_profile_arr[n];
		start = gem->vm_bind_info.gpu_addr;
		end = start + gem->vm_bind_info.size;
		if ((bbsp >= start) && (bbsp < end)) {
			if (debug) {
				printf("Found a matching batch buffer ");
				printf("to jump to. handle=%u gpu_addr=0x%llx\n",
				       gem->vm_bind_info.handle,
				       gem->vm_bind_info.gpu_addr);
			}
			return gem;
		}
	}
	return NULL;
}

enum bb_parser_status mi_batch_buffer_start(struct bb_parser *parser,
					    uint32_t *ptr)
{
	uint64_t tmp, bbsp_offset;

	/* XXX: Handle MI_PREDICATE */

	if (parser->in_cmd == 1) {
		parser->bb2l = MI_BATCH_BUFFER_START_2ND_LEVEL(*ptr);
		if (debug) {
			printf("bb2l=%u\n", parser->bb2l);
		}
		parser->bbsp = 0;
		parser->bbsp |= *ptr;
	} else if (parser->in_cmd == 2) {
		tmp = *ptr;
		parser->bbsp |= tmp << 32;
		if (debug) {
			printf("bbsp=0x%lx\n", parser->bbsp);
		}

		if (parser->bb2l && (parser->pc_depth == 1)) {
			parser->pc[parser->pc_depth] +=
				4 * MI_BATCH_BUFFER_START_DWORDS - 4;
			parser->pc_depth++;
		}
		parser->pc[parser->pc_depth] = parser->bbsp - 4;

		parser->gem = find_jump_buffer(parser->bbsp);

		if (!parser->gem) {
			if (debug) {
				fprintf(stderr,
					"WARNING: Couldn't find a buffer ");
				fprintf(stderr,
					" that encompasses the BBSP 0x%lx\n",
					parser->bbsp);
			}
			return BB_PARSER_STATUS_NOTFOUND;
		}

		update_buffer_copy(parser->gem);

		if (!(parser->gem->buff)) {
			/* We know we're supposed to jump *somewhere*, 
			 * but can't. */
			if (debug) {
				fprintf(stderr, "WARNING: A batch buffer was");
				fprintf(stderr,
					" supposed to chain somewhere,");
				fprintf(stderr,
					" but we don't have a copy of it.\n");
			}
			return BB_PARSER_STATUS_NOTFOUND;
		}
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
	uint64_t off, tmp;

	/* Loop over 32-bit dwords. */
	parser->pc_depth = 0;
	parser->pc[parser->pc_depth] = gem->vm_bind_info.gpu_addr + offset;
	parser->gem = gem;
	parser->in_cmd = 0;
	parser->cur_cmd = 0;
	while (1) {
		off = parser->pc[parser->pc_depth] -
		      parser->gem->vm_bind_info.gpu_addr;
		dword_ptr = (uint32_t *)(parser->gem->buff + off);

		if ((parser->pc_depth == 0) && (off > size)) {
			/* Buffer overflow! We'll just have to bail out. */
			if (debug) {
				printf("Buffer overflow! off=0x%lx sz=0x%lx.\n",
				       off, parser->gem->buff_sz);
			}
			return BB_PARSER_STATUS_BUFFER_OVERFLOW;
		}

		if (debug) {
			printf("size=0x%lx dword=0x%x offset=0x%lx\n", size,
			       *dword_ptr, off);
			printf("in_cmd=%u cur_cmd=%lu cur_num_dwords=%u\n",
			       parser->in_cmd, parser->cur_cmd,
			       parser->cur_num_dwords);
		}

		if (!parser->cur_cmd) {
			op = (*dword_ptr) >> (32 - op_len(dword_ptr));

			/* Decode which op this is */
			switch (op) {
			case MI_BATCH_BUFFER_START:
				if (debug) {
					printf("op=MI_BATCH_BUFFER_START\n");
				}
				parser->cur_cmd = MI_BATCH_BUFFER_START;
				parser->cur_num_dwords =
					MI_BATCH_BUFFER_START_DWORDS;
				break;
			case STATE_BASE_ADDRESS:
				if (debug) {
					printf("op=STATE_BASE_ADDRESS\n");
				}
				parser->cur_cmd = STATE_BASE_ADDRESS;
				parser->cur_num_dwords =
					STATE_BASE_ADDRESS_DWORDS;
				break;
			case STATE_SIP:
				if (debug) {
					printf("op=STATE_SIP\n");
				}
				parser->cur_cmd = STATE_SIP;
				parser->cur_num_dwords = STATE_SIP_DWORDS;
				break;
			case COMPUTE_WALKER:
				if (debug) {
					printf("op=COMPUTE_WALKER\n");
				}
				parser->cur_cmd = COMPUTE_WALKER;
				parser->cur_num_dwords = COMPUTE_WALKER_DWORDS;
				break;
			case MI_BATCH_BUFFER_END:
				if (debug) {
					printf("op=MI_BATCH_BUFFER_END\n");
				}
				parser->cur_cmd = MI_BATCH_BUFFER_END;
				parser->cur_num_dwords =
					MI_BATCH_BUFFER_END_DWORDS;
				break;
			case MI_CONDITIONAL_BATCH_BUFFER_END:
				if (debug) {
					printf("op=MI_CONDITIONAL_BATCH_BUFFER_END\n");
				}
				parser->cur_cmd =
					MI_CONDITIONAL_BATCH_BUFFER_END;
				parser->cur_num_dwords =
					MI_CONDITIONAL_BATCH_BUFFER_END_DWORDS;
				break;
			case MI_PREDICATE:
				if (debug) {
					printf("op=MI_PREDICATE\n");
				}
				parser->cur_cmd = MI_PREDICATE;
				parser->cur_num_dwords = MI_PREDICATE_DWORDS;
				break;
			case PIPE_CONTROL:
				if (debug) {
					printf("op=PIPE_CONTROL\n");
				}
				parser->cur_cmd = PIPE_CONTROL;
				parser->cur_num_dwords = PIPE_CONTROL_DWORDS;
				break;
			case MI_SEMAPHORE_WAIT:
				if (debug) {
					printf("op=MI_SEMAPHORE_WAIT\n");
				}
				parser->cur_cmd = MI_SEMAPHORE_WAIT;
				parser->cur_num_dwords =
					MI_SEMAPHORE_WAIT_DWORDS;
				break;
			default:
				if (debug) {
					printf("op=UNKNOWN (0x%x)\n", op);
				}
				break;
			}
		}

		/* Consume this command's dwords */
		switch (parser->cur_cmd) {
		case MI_BATCH_BUFFER_START:
			mi_batch_buffer_start(parser, dword_ptr);
			break;
		case MI_BATCH_BUFFER_END:
			if (mi_batch_buffer_end(parser)) {
				return BB_PARSER_STATUS_OK;
			}
			break;
		case MI_SEMAPHORE_WAIT:
			/* TODO: do *something* to handle the semaphor.
                         * Sleeping is a non-starter. */
			break;
		case STATE_BASE_ADDRESS:
			if (parser->in_cmd == 10) {
				/* The tenth dword in STATE_BASE_ADDRESS stores
                                 * 20 of the iba bits. */
				parser->iba |= (*dword_ptr & 0xFFFFF000);
			} else if (parser->in_cmd == 11) {
				/* The eleventh dword in STATE_BASE_ADDRESS 
                                 * stores the majority of the iba */
				tmp = *dword_ptr;
				parser->iba |= tmp << 32;
				if (debug) {
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
		if (debug) {
			printf("Advancing the PC to 0x%lx\n",
			       parser->pc[parser->pc_depth]);
		}
	}

	if (debug) {
		printf("Finished batchbuffer parsing.\n");
	}
	return BB_PARSER_STATUS_OK;
}
