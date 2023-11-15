#pragma once

#include <stdio.h>
#include <stdint.h>

/* We can use these to determine the type of command,
   and how long the command should be */
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
#define MI_BATCH_BUFFER_START_DWORDS 2

/* 3D/Media Command: Pipeline Type(28:27) Opcode(26:24) Sub Opcode(23:16) */
#define OP_3D_MEDIA(sub_type, opcode, sub_opcode) \
  ((3 << 13) | ((sub_type) << 11) | ((opcode) << 8) | (sub_opcode))
#define OP_3D \
  ((3 << 13) | (0xF << 11) | (0xF << 8) | (0xFF))

#define STATE_BASE_ADDRESS OP_3D_MEDIA(0x0, 0x1, 0x01)
#define STATE_BASE_ADDRESS_DWORDS 19

#define STATE_SIP OP_3D_MEDIA(0x0, 0x1, 0x02)
#define STATE_SIP_DWORDS 3

struct bb_parser {
  /* Instruction Base Address */
  uint64_t iba;
  
  /* SIP, or System Instruction Pointer.
     This is an offset from the iba,
     or Instruction Base Address. */
  uint64_t sip;
};

struct bb_parser *bb_parser_init() {
  struct bb_parser *parser;
  
  parser = calloc(1, sizeof(struct bb_parser));
  return parser;
}

void bb_parser_parse(struct bb_parser *parser, unsigned char *bb, uint64_t size) {
  uint32_t *ptr, cur_cmd, op, op_len;
  uint64_t i, tmp;
  unsigned char in_cmd, num_cmd_dwords;
  
  /* Loop over the uint32_t batch buffer commands.
     `in_cmd` records the number of dwords that we're "in" a command.
     `cmd` records the command that we're "in."
     `num_cmd_dwords` records the number of dwords that the command holds. */
  ptr = bb;
  in_cmd = 0;
  for(i = 0; i < size / sizeof(uint32_t); i++) {
    
    if(in_cmd) {
      /* Consume this command's dwords */
      switch(cur_cmd) {
        case STATE_BASE_ADDRESS:
          if(in_cmd == 10) {
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
      
      if(in_cmd == num_cmd_dwords - 1) {
        /* We've consumed all of this command's
           dwords, so go back to look for new
           commands. */
        in_cmd = 0;
      } else {
        /* Keep looking for dwords that this command
           needs */
        in_cmd++;
      }
      
    } else {
      
      /* Get the op */
      if(CMD_TYPE(*ptr) == CMD_MI) {
        op_len = OP_LEN_MI;
      } else if(CMD_TYPE(*ptr) == CMD_3D_MEDIA) {
        op_len = OP_LEN_3D_MEDIA;
      } else {
        ptr++;
        continue;
      }
      op = (*ptr) >> (32 - op_len);
      
      switch(op) {
        case MI_BATCH_BUFFER_START:
          in_cmd = 1;
          cur_cmd = MI_BATCH_BUFFER_START;
          num_cmd_dwords = MI_BATCH_BUFFER_START_DWORDS;
          break;
        case STATE_BASE_ADDRESS:
          in_cmd = 1;
          cur_cmd = STATE_BASE_ADDRESS;
          num_cmd_dwords = STATE_BASE_ADDRESS_DWORDS;
          break;
        case STATE_SIP:
          in_cmd = 1;
          cur_cmd = STATE_SIP;
          num_cmd_dwords = STATE_SIP_DWORDS;
          break;
      }
    }
    ptr++;
  }
}
