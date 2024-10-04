#pragma once

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "gpu_parsers/bb_parser_defs.h"
#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "utils/utils.h"

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

uint32_t cmd_lengths[] = {
        #define L(name, type, opcode, num_dwords) [name] = num_dwords,
        LIST_COMMANDS(L)
        #undef L
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
******************************************************************************/

char find_jump_buffer(struct bb_parser *parser, uint64_t bbsp)
{
        struct buffer_binding *bind;

        bind = get_containing_binding(parser->vm, bbsp);
        if (bind != NULL) {
                if (bb_debug) {
                        debug_printf("Found a matching batch buffer ");
                        debug_printf("to jump to. vm_id=%u gpu_addr=0x%lx\n",
                                bind->vm_id,
                                bind->gpu_addr);
                }
                if (parser->bo != NULL) {
                        release_buffer(parser->bo);
                }
                parser->bind = bind;
                parser->bo = acquire_buffer(parser->bind->file, parser->bind->handle);
                parser->bind->type = BUFFER_TYPE_BATCHBUFFER;

/*                 fprintf(stderr, "!!! BB %u 0x%lx 0x%lx %u\n", */
/*                         parser->bind->vm_id, parser->bind->gpu_addr, parser->bind->file, parser->bind->handle); */

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
                        debug_printf("load_register_offset=0x%x\n", *ptr);
                }
        } else if (parser->in_cmd == 2) {
                /* The entirety of the second dword contains the data dword */
                parser->load_register_dword = *ptr;
                if (bb_debug) {
                        debug_printf("load_register_dword=0x%x\n", *ptr);
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
                        debug_printf("Found an IBA: 0x%lx\n",
                                parser->iba);
                }
        }

        return BB_PARSER_STATUS_OK;
}

enum bb_parser_status compute_walker(struct bb_parser *parser,
                                     uint32_t *ptr, int pid, int tid,
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
                        store_stack(pid, tid, stackid);
                        shader_bind->execbuf_stackid = stackid;
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
                debug_printf("iba: 0x%lx\n", iba);
                debug_printf("ksp: 0x%lx\n", *ksp);
                debug_printf("Found ksp: 0x%lx\n", *ksp & 0xffffffff0000);
                if ((*ksp & 0xffffffff0000) == addr) {
                        debug_printf("KSP matches addr=0x%lx at pc=0x%lx!\n", addr, pc);
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
                debug_printf("iba is: 0x%lx\n", iba);
        } else if (in_cmd == 19) {
                tmp = *ptr;
                *ksp |= ((tmp & 0xffff) << 32);
                debug_printf("Found ksp: 0x%lx\n", *ksp);
                if ((*ksp & 0xffffffff) == addr) {
                        debug_printf("KSP matches addr 0x%lx!\n", addr);
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
                        debug_printf("enable_predication=%u\n",
                               parser->enable_predication);
                }
        } else if (parser->in_cmd == 1) {
                parser->bb2l = MI_BATCH_BUFFER_START_2ND_LEVEL(*ptr);
                if (bb_debug) {
                        debug_printf("bb2l=%u\n", parser->bb2l);
                }
                parser->bbsp = 0;
                parser->bbsp |= *ptr;
        } else if (parser->in_cmd == 2) {

                /* Collect the BBSP (Batch Buffer Start Pointer) */
                tmp = *ptr;
                parser->bbsp |= tmp << 32;
                if (bb_debug) {
                        debug_printf("bbsp=0x%lx\n", parser->bbsp);
                }

                /* Try to detect recursion and stop */
                if (parser->bbsp == (parser->pc[parser->pc_depth] - 8)) {
                        if (bb_debug) {
                                debug_printf("Recursion!\n");
                        }
                        return BB_PARSER_STATUS_NOTFOUND;
                }
                it = tree_lookup(parser->visited_addresses, parser->bbsp);
                if (tree_it_good(it)) {
                        if (bb_debug) {
                                debug_printf("Recursion!\n");
                        }
                        return BB_PARSER_STATUS_NOTFOUND;
                }
                tree_insert(parser->visited_addresses, parser->bbsp, 1);


                if (parser->bb2l && (parser->pc_depth == 1)) {
                        /* Advance the program counter by the number of dwords in
                           an MI_BATCH_BUFFER_START command, minus one (since we're
                           going to increment this by one in the parser loop) */
                        parser->pc[parser->pc_depth] +=
                                (4 * (cmd_lengths[BATCH_BUFFER_START] - 1));
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
                                        " but we don't have a copy of it. (vm_id=%u gpu_addr=0x%lx)\n",
                                        parser->bind->vm_id, parser->bind->gpu_addr);
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
                                      int pid, int tid, int stackid, char *procname)
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

        parser->bind->type = BUFFER_TYPE_BATCHBUFFER;

/*         fprintf(stderr, "!!! BB %u 0x%lx 0x%lx %u\n", */
/*                 parser->bind->vm_id, parser->bind->gpu_addr, parser->bind->file, parser->bind->handle); */

        while (parser->pc_depth > 0) {
                off = parser->pc[parser->pc_depth] -
                      parser->bind->gpu_addr;
                dword_ptr = (uint32_t *)(parser->bo->buff + off);

                /* First check if we're overflowing the buffer */
                if (off >= parser->bo->buff_sz) {
                        if (bb_debug) {
                                debug_printf("Stop because of buffer size. off=0x%lx sz=0x%lx\n",
                                       off, parser->bo->buff_sz);
                        }
                        retval = BB_PARSER_STATUS_BUFF_OVERFLOW;
                        goto out;
                }

                if (bb_debug) {
                        debug_printf("size=0x%lx dword=0x%x offset=0x%lx\n", size,
                               *dword_ptr, off);
                        debug_printf("in_cmd=%u cur_cmd=%lu cur_num_dwords=%u\n",
                               parser->in_cmd, parser->cur_cmd,
                               parser->cur_num_dwords);
                }

                /* Keep track of how many dwords we've parsed */
                parser->num_dwords++;

                if (!parser->cur_cmd) {
                        op = GET_OPCODE(*dword_ptr);

                        /* Decode which op this is */
                        switch (op) {
                                #define X(name, type, opcode, num_dwords)                  \
                                case name:                                                 \
                                        noops += name == NOOP;                             \
                                        if (bb_debug) {                                    \
                                                debug_printf("op=" #name "\n");            \
                                        }                                                  \
                                        if (noops == 32) {                                 \
                                                if (bb_debug) {                            \
                                                        debug_printf("Too many NOOPs!\n"); \
                                                }                                          \
                                                retval = BB_PARSER_STATUS_OK;              \
                                                goto out;                                  \
                                        }                                                  \
                                        parser->cur_cmd = name;                            \
                                        parser->cur_num_dwords = num_dwords;               \
                                        break;
                                LIST_COMMANDS(X);
                                #undef X

                                default:
                                        if (bb_debug) {
                                                debug_printf("op=UNKNOWN (0x%x)\n", op);
                                        }
                                        break;
                        }
                }

                /* Consume this command's dwords */
                switch (parser->cur_cmd) {
                        case BATCH_BUFFER_START:
                                retval = mi_batch_buffer_start(parser, dword_ptr);
                                if (retval != BB_PARSER_STATUS_OK) {
                                        goto out;
                                }
                                break;
                        case PRT_BATCH_BUFFER_START:
                                retval = mi_batch_buffer_start(parser, dword_ptr);
                                if (retval != BB_PARSER_STATUS_OK) {
                                        goto out;
                                }
                                break;
                        case BATCH_BUFFER_END:
                                if (mi_batch_buffer_end(parser)) {
                                        retval = BB_PARSER_STATUS_OK;
                                        goto out;
                                }
                                break;
                        case LOAD_REGISTER_IMM:
                                retval = mi_load_register_imm(parser, dword_ptr);
                                if (retval != BB_PARSER_STATUS_OK) {
                                        goto out;
                                }
                                break;
                        case PREDICATE:
                                retval = mi_predicate(parser, dword_ptr);
                                if (retval != BB_PARSER_STATUS_OK) {
                                        goto out;
                                }
                                break;
                        case SEMAPHORE_WAIT:
                                break;
                        case STATE_BASE_ADDRESS:
                                retval = state_base_address(parser, dword_ptr);
                                if (retval != BB_PARSER_STATUS_OK) {
                                        goto out;
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
                                retval = compute_walker(parser, dword_ptr, pid, tid, stackid, procname);
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
                        debug_printf("Advancing the PC to 0x%lx\n",
                               parser->pc[parser->pc_depth]);
                }
        }

out:;
        tree_free(parser->visited_addresses);

        if (parser->bo != NULL) {
                release_buffer(parser->bo);
        }

        if (bb_debug) {
                debug_printf("Finished batchbuffer parsing.\n");
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
                debug_printf("Looking for addr=0x%lx\n", addr);
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
                                debug_printf("Stop because of buffer size. off=0x%lx sz=0x%lx\n",
                                       off, bo->buff_sz);
                        }
                        retval = BB_PARSER_STATUS_BUFF_OVERFLOW;
                        goto out;
                }

                if (!cur_cmd) {
                        op = GET_OPCODE(*dword_ptr);

                        /* Decode which op this is */
                        switch (op) {
                                case COMPUTE_WALKER:
                                        if (bb_debug) {
                                                debug_printf("op=COMPUTE_WALKER\n");
                                        }
                                        cur_cmd = COMPUTE_WALKER;
                                        cur_num_dwords = cmd_lengths[COMPUTE_WALKER];
                                        break;
                                case GPGPU_WALKER:
                                        if (bb_debug) {
                                                debug_printf("op=GPGPU_WALKER\n");
                                        }
                                        cur_cmd = GPGPU_WALKER;
                                        cur_num_dwords = cmd_lengths[GPGPU_WALKER];
                                        break;
                                case SEMAPHORE_WAIT:
                                        if (bb_debug) {
                                                debug_printf("op=SEMAPHORE_WAIT\n");
                                        }
                                        cur_cmd = SEMAPHORE_WAIT;
                                        cur_num_dwords = cmd_lengths[SEMAPHORE_WAIT];
                                        break;
                                default:
                                        break;
                        }
                }

                /* Consume this command's dwords */
                switch (cur_cmd) {
                        case COMPUTE_WALKER:
                                if (bb_debug) {
                                        debug_printf("size=0x%lx dword=0x%x offset=0x%lx\n", bo->buff_sz,
                                        *dword_ptr, off);
                                        debug_printf("in_cmd=%u cur_cmd=%lu cur_num_dwords=%u\n",
                                        in_cmd, cur_cmd, cur_num_dwords);
                                }
                                compute_walker_simple(dword_ptr, &ksp, in_cmd, pc, addr);
                                break;
                        case GPGPU_WALKER:
                                if (bb_debug) {
                                        debug_printf("size=0x%lx dword=0x%x offset=0x%lx\n", bo->buff_sz,
                                        *dword_ptr, off);
                                        debug_printf("in_cmd=%u cur_cmd=%lu cur_num_dwords=%u\n",
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
                debug_printf("Finished batchbuffer parsing.\n");
        }
        return retval;
}
