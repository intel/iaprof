#include <stdio.h>
#include <dlfcn.h>
#include "shader_decoder.h"
#include <iga/iga.h>

char *iga_status_to_str(iga_status_t status) {
  switch(status) {
    case IGA_SUCCESS:
      return "IGA_SUCCESS";
    case IGA_INVALID_ARG:
      return "IGA_INVALID_ARG";
    case IGA_INVALID_OBJECT:
      return "IGA_INVALID_OBJECT";
    case IGA_OUT_OF_MEM:
      return "IGA_OUT_OF_MEM";
    case IGA_ERROR:
      return "IGA_ERROR";
    case IGA_DECODE_ERROR:
      return "IGA_DECODE_ERROR";
    case IGA_ENCODE_ERROR:
      return "IGA_ENCODE_ERROR";
    case IGA_PARSE_ERROR:
      return "IGA_PARSE_ERROR";
    case IGA_VERSION_ERROR:
      return "IGA_VERSION_ERROR";
    case IGA_INVALID_STATE:
      return "IGA_INVALID_STATE";
    case IGA_UNSUPPORTED_PLATFORM:
      return "IGA_UNSUPPORTED_PLATFORM";
    case IGA_DIFF_FAILURE:
      return "IGA_DIFF_FAILURE";
  }
  return "UNKNOWN";
}

iga_context_t *iga_init() {
  iga_context_t *ctx;
  iga_status_t status;
  iga_context_options_t opts;
  
  opts.cb = sizeof(iga_context_options_t);
  opts.gen = IGA_XE_HPC;
  
  ctx = malloc(sizeof(iga_context_t));
  
  status = iga_context_create(&opts, ctx);
  if(status != IGA_SUCCESS) {
    fprintf(stderr, "Failed to create an IGA context! Error: %s\n", iga_status_to_str(status));
    fprintf(stderr, "Aborting.\n");
    exit(1);
  }
  return ctx;
}

char *iga_disassemble_single(iga_context_t *ctx, unsigned char *data) {
  char *text, *tok, *first_tok;
  iga_status_t status;
  int field;
  
  iga_disassemble_options_t opts = {
    sizeof(iga_disassemble_options_t),
    IGA_FORMATTING_OPTS_DEFAULT,
    0,
    0,
    IGA_DECODING_OPTS_DEFAULT,
  };
  
  status = iga_disassemble_instruction(*ctx, &opts, data, NULL, NULL, &text);
  if(status != IGA_SUCCESS) {
    fprintf(stderr, "IGA failed to disassemble an instruction! Error: %s\n", iga_status_to_str(status));
    return NULL;
  }
  if(!text) {
    fprintf(stderr, "IGA failed to disassemble an instruction by returning a NULL pointer!\n");
    return NULL;
  }
  
  /* Post-process the text by grabbing the second field (space-separated).
     TODO: This might be better if we used the JSON output from
     IGA, then parsed that instead. */
     
  tok = strtok(text, " ");
  if(!tok) {
    /* There were no spaces in the string at all, so return the whole thing */
    return strdup(text);
  }
  first_tok = tok;
  tok = strtok(NULL, " ");
  if(!tok) {
    /* There was only one space in the whole string, so return the rest of the string */
    return strdup(first_tok);
  }
  return strdup(tok);
}

void iga_disassemble_shader(iga_context_t *ctx, unsigned char *data, size_t data_sz) {
  const char *buff;
  iga_status_t status;
  const iga_diagnostic_t *diag, *tmp;
  uint32_t diag_len, i, offset, first_error_offset;
  uint64_t n, assumed_end;
  uint8_t *ptr, num_zero_bytes;
  char *text;
  
  /* First, we need to discover the actual size of the kernel.
     We do this by naively iterating over it, stopping at the first
     full 16 bytes of zeroes. */
  assumed_end = 0;
  num_zero_bytes = 0;
  ptr = data;
  for(n = 0; n < data_sz; n++) {
    if(*ptr == 0) {
      num_zero_bytes++;
      if(num_zero_bytes == 16) {
        assumed_end = n;
        break;
      }
    } else {
      num_zero_bytes = 0;
    }
    ptr++;
  }
  printf("assumed_end=%lu\n", assumed_end);
  
  iga_disassemble_options_t opts = {
    sizeof(iga_disassemble_options_t),
    IGA_FORMATTING_OPTS_DEFAULT | IGA_FORMATTING_OPT_PRINT_PC | IGA_FORMATTING_OPT_NUMERIC_LABELS,
    0,
    0,
    IGA_DECODING_OPTS_DEFAULT,
  };
  
  status = iga_disassemble(*ctx, &opts, data, assumed_end, NULL, NULL, &text);
  if((status != IGA_SUCCESS) && (status != IGA_DECODE_ERROR)) {
    fprintf(stderr, "IGA failed to disassemble a kernel! Error: %s\n", iga_status_to_str(status));
  } else {
    printf("Successfully disassembled a kernel!\n");
  }
  
  first_error_offset = 0xFFFFFFFF;
  status = iga_get_errors(*ctx, &diag, &diag_len);
  if(status != IGA_SUCCESS) {
    fprintf(stderr, "IGA failed to get errors! Error: %s\n", iga_status_to_str(status));
  } else {
    tmp = diag;
    for(i = 0; i < diag_len; i++) {
      status = iga_diagnostic_get_offset(tmp, &offset);
      if(status != IGA_SUCCESS) continue;
      status = iga_diagnostic_get_message(tmp, &buff);
      if(status != IGA_SUCCESS) continue;
      
      /* Actually just break on the first error */
      first_error_offset = offset;
      break;
      
      /* What we would otherwise do if we knew where this buffer ended... */
      fprintf(stderr, "ERROR (0x%x): %s\n", offset, buff);
      tmp++;
    }
  }
  
  status = iga_get_warnings(*ctx, &diag, &diag_len);
  if(status != IGA_SUCCESS) {
    fprintf(stderr, "IGA failed to get warnings! Error: %s\n", iga_status_to_str(status));
  } else {
    tmp = diag;
    for(i = 0; i < diag_len; i++) {
      status = iga_diagnostic_get_offset(tmp, &offset);
      if(status != IGA_SUCCESS) continue;
      status = iga_diagnostic_get_message(tmp, &buff);
      if(status != IGA_SUCCESS) continue;
      
      if(offset < first_error_offset) {
        fprintf(stderr, "WARNING (0x%x): %s\n", offset, buff);
      }
      tmp++;
    }
  }
  
  printf("%s\n", text);
  fflush(stdout);
}
