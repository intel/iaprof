#pragma once

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/* STATE_BASE_ADDRESS::InstructionBaseAddress + ((INTERFACE_DESCRIPTOR_DATA */
/* *)(STATE_BASE_ADDRESS::DynamicBaseAddress + InterfaceDescriptorDataStartAddress))->KernelStartPointer */

/******************************************************************************
* Commands
* *********
* These are constants that represent batch buffer commands
******************************************************************************/
#define CMD_TYPE(cmd)  (((cmd) >> 29) & 7)
#define CMD_MI 0
#define CMD_3D_MEDIA 3

#define OP_LEN_MI           9
#define OP_LEN_2D           10
#define OP_LEN_3D_MEDIA     16
#define OP_LEN_MFX_VC       16
#define OP_LEN_VEBOX      16

/* MI Commands */
#define MI_BATCH_BUFFER_START 0x31
#define MI_BATCH_BUFFER_START_DWORDS 3
#define MI_BATCH_BUFFER_START_2ND_LEVEL(x) ((x) >> 22 & 1U)

#define MI_BATCH_BUFFER_END 0x0a
#define MI_BATCH_BUFFER_END_DWORDS 1

#define MI_SEMAPHORE_WAIT 0x1c
#define MI_SEMAPHORE_WAIT_DWORDS 5

/* 3D/Media Command: Pipeline Type(28:27) Opcode(26:24) Sub Opcode(23:16) */
#define OP_3D_MEDIA(sub_type, opcode, sub_opcode) \
  ((3 << 13) | ((sub_type) << 11) | ((opcode) << 8) | (sub_opcode))
#define OP_3D \
  ((3 << 13) | (0xF << 11) | (0xF << 8) | (0xFF))
  
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

struct bb_parser *bb_parser_init() {
  struct bb_parser *parser;
  
  parser = calloc(1, sizeof(struct bb_parser));
  return parser;
}

void bb_parser_parse(struct bb_parser *parser, unsigned char *bb, uint32_t offset, uint64_t size) {
  char found;
  uint32_t *ptr, cur_cmd, op, op_len;
  uint64_t i, n, tmp, start, end, bbsp_offset;
  unsigned char in_cmd, num_cmd_dwords;
  struct buffer_profile *gem;
  
  /* Loop over the uint32_t batch buffer commands.
     `in_cmd` records the number of dwords that we're "in" a command.
     `cmd` records the command that we're "in."
     `num_cmd_dwords` records the number of dwords that the command holds. */
  ptr = (uint32_t *) (bb + offset);
  in_cmd = 0;
  for(i = offset / sizeof(uint32_t); i < (size + offset) / sizeof(uint32_t); i++) {
    
    if(verbose) {
      printf("dword=0x%x offset=0x%lx\n", *ptr, i * sizeof(uint32_t));
      printf("in_cmd=%u cur_cmd=%u num_cmd_dwords=%u\n", in_cmd, cur_cmd, num_cmd_dwords);
    }
    
    if(!in_cmd) {
      /* Get the op */
      if(CMD_TYPE(*ptr) == CMD_MI) {
        if(verbose) {
          printf("cmd_type=CMD_MI\n");
        }
        op_len = OP_LEN_MI;
      } else if(CMD_TYPE(*ptr) == CMD_3D_MEDIA) {
        if(verbose) {
          printf("cmd_type=CMD_3D_MEDIA\n");
        }
        op_len = OP_LEN_3D_MEDIA;
      } else {
        if(verbose) {
          printf("cmd_type=UNKNOWN (0x%x)\n", CMD_TYPE(*ptr));
        }
        ptr++;
        continue;
      }
      op = (*ptr) >> (32 - op_len);
      
      switch(op) {
        case MI_BATCH_BUFFER_START:
          if(verbose) {
            printf("op=MI_BATCH_BUFFER_START\n");
          }
          in_cmd = 1;
          cur_cmd = MI_BATCH_BUFFER_START;
          num_cmd_dwords = MI_BATCH_BUFFER_START_DWORDS;
          break;
        case STATE_BASE_ADDRESS:
          if(verbose) {
            printf("op=STATE_BASE_ADDRESS\n");
          }
          in_cmd = 1;
          cur_cmd = STATE_BASE_ADDRESS;
          num_cmd_dwords = STATE_BASE_ADDRESS_DWORDS;
          break;
        case STATE_SIP:
          if(verbose) {
            printf("op=STATE_SIP\n");
          }
          in_cmd = 1;
          cur_cmd = STATE_SIP;
          num_cmd_dwords = STATE_SIP_DWORDS;
          break;
        case COMPUTE_WALKER:
          if(verbose) {
            printf("op=COMPUTE_WALKER\n");
          }
          in_cmd = 1;
          cur_cmd = COMPUTE_WALKER;
          num_cmd_dwords = COMPUTE_WALKER_DWORDS;
          break;
        case MI_BATCH_BUFFER_END:
          if(verbose) {
            printf("op=MI_BATCH_BUFFER_END\n");
          }
          in_cmd = 1;
          cur_cmd = MI_BATCH_BUFFER_END;
          num_cmd_dwords = MI_BATCH_BUFFER_END_DWORDS;
          break;
        case PIPE_CONTROL:
          if(verbose) {
            printf("op=PIPE_CONTROL\n");
          }
          in_cmd = 1;
          cur_cmd = PIPE_CONTROL;
          num_cmd_dwords = PIPE_CONTROL_DWORDS;
          break;
        case MI_SEMAPHORE_WAIT:
          if(verbose) {
            printf("op=MI_SEMAPHORE_WAIT\n");
          }
          in_cmd = 1;
          cur_cmd = MI_SEMAPHORE_WAIT;
          num_cmd_dwords = MI_SEMAPHORE_WAIT_DWORDS;
          break;
        default:
          if(verbose) {
            printf("op=UNKNOWN (0x%x)\n", op);
          }
          break;
      }
    }
    
    if(in_cmd) {
      /* Consume this command's dwords */
      switch(cur_cmd) {
        case MI_BATCH_BUFFER_START:
          if(in_cmd == 1) {
            parser->bb2l = MI_BATCH_BUFFER_START_2ND_LEVEL(*ptr);
            if(verbose) {
              printf("bb2l=%u\n", parser->bb2l);
            }
          } else if(in_cmd == 2) {
            parser->bbsp = 0;
            parser->bbsp |= *ptr;
          } else if(in_cmd == 3) {
            tmp = *ptr;
            parser->bbsp |= tmp << 32;
            if(verbose) {
              printf("bbsp=0x%lx\n", parser->bbsp);
            }
            
            /* At this point, we've got an address that we need to jump to,
               so go ahead and do it */
            found = 0;
            for(n = 0; n < buffer_profile_used; n++) {
              gem = &buffer_profile_arr[n];
              start = gem->vm_bind_info.gpu_addr;
              end = start + gem->vm_bind_info.size;
              if((parser->bbsp >= start) && (parser->bbsp < end)) {
                
                if(verbose) {
                  printf("Found a matching batch buffer to jump to. handle=%u gpu_addr=0x%llx\n", gem->vm_bind_info.handle, gem->vm_bind_info.gpu_addr);
                }
                found = 1;
                
                if(gem->buff == NULL) {
                  /* We know we're supposed to jump *somewhere*, but can't. */
                  printf("WARNING: A batch buffer was supposed to chain somewhere, but we ");
                  printf("don't have a copy of it.\n");
                  return;
                }
                
                bbsp_offset = parser->bbsp - gem->vm_bind_info.gpu_addr;
                if(verbose) {
                  printf("Parsing a batch buffer at start=0x%llx offset=0x%lx size=%llu\n", gem->mapping_info.cpu_addr, bbsp_offset, gem->mapping_info.size - bbsp_offset);
                  printf("The next dword: 0x%x\n", *(ptr + 1));
                }
                bb_parser_parse(parser, gem->buff, bbsp_offset, gem->mapping_info.size - bbsp_offset);
                
                if(!(parser->bb2l)) {
                  /* If the "2nd level" bit in the MI_BATCH_BUFFER_START command
                     wasn't set, it acts as a goto - don't continue parsing after the jump 
                     returns here. */
                  return;
                }
              }
            }
            if(!found) {
              printf("WARNING: Didn't find a match for GPU address 0x%lx\n", parser->bbsp);
              return;
            }
          }
          break;
        case MI_SEMAPHORE_WAIT:
          if(in_cmd == 5) {
            if(verbose) {
              printf("Sleeping for 1 second.\n");
            }
            sleep(2);
          }
          break;
        case STATE_BASE_ADDRESS:
          if(in_cmd == 10) {
            if(verbose) {
              printf("Found an Instruction Base Address.\n");
            }
            /* The tenth dword in STATE_BASE_ADDRESS
              stores 20 of the iba bits. */
            parser->iba |= (*ptr & 0xFFFFF000);
          } else if(in_cmd == 11) {
            /* The eleventh dword in STATE_BASE_ADDRESS
              stores the majority of the iba */
            tmp = *ptr;
            parser->iba |= tmp << 32;
          }
          break;
        case STATE_SIP:
          if(in_cmd == 1) {
            parser->sip |= *ptr;
          } else if(in_cmd == 2) {
            tmp = *ptr;
            parser->sip |= tmp << 32;
          }
          break;
      }
      
      if(in_cmd == num_cmd_dwords) {
        /* We've consumed all of this command's
           dwords, so go back to looking for new
           commands. */
        in_cmd = 0;
      } else {
        /* Keep looking for dwords that this command
           needs */
        in_cmd++;
      }
      
    }
    
    if(cur_cmd == MI_BATCH_BUFFER_END) break;
    
    ptr++;
  }
}
