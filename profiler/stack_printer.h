#pragma once

#include <stdint.h>
#include "trace_helpers.h"

#define MAX_STACK_DEPTH 127

static struct syms_cache *syms_cache = NULL;
static unsigned long ip[MAX_STACK_DEPTH * sizeof(unsigned long)];

int init_syms_cache() {
  if(syms_cache == NULL) {
    syms_cache = syms_cache__new(0);
    if(!syms_cache) {
      fprintf(stderr, "ERROR: Failed to initialize syms_cache.\n");
      return -1;
    }
  }
  return 0;
}

void print_stack(uint32_t pid, int stackid) {
  const struct syms *syms;
  const struct sym *sym;
  int sfd, i;
  
  sfd = bpf_map__fd(bpf_info.obj->maps.stackmap);
  if(sfd <= 0) {
    fprintf(stderr, "Failed to get stackmap.\n");
    return;
  }
  
  if(init_syms_cache() != 0) {
    return;
  }
  syms = syms_cache__get_syms(syms_cache, pid);
  
  if (bpf_map_lookup_elem(sfd, &stackid, ip) != 0) {
    printf("[unknown]");
    return;
  }
  
  for(i = 0; i < MAX_STACK_DEPTH && ip[i]; i++) {
    sym = syms__map_addr(syms, ip[i]);
    if(sym) {
      printf("%s;", sym->name);
    } else {
      printf("unknown;");
    }
  }

  return;
}
