#pragma once

#include <asm/types.h>
#include "bpf/gem_collector.h"
#include "utils/hash_table.h"
#include "utils/utils.h"

use_hash_table(uint64_t, uint64_t);

struct offset_profile {
  unsigned int active;
  unsigned int other;
  unsigned int control;
  unsigned int pipestall;
  unsigned int send;
  unsigned int dist_acc;
  unsigned int sbid;
  unsigned int sync;
  unsigned int inst_fetch;
};
  
struct shader_profile {
  /* The EU stalls. Key is the offset into the binary,
     value is a pointer to the struct of EU stall counts */
  hash_table(uint64_t, uint64_t) counts;
};

struct gem_profile {
  struct gem_info kinfo;
  
  uint64_t buff_sz;
  unsigned char *buff;
  
  unsigned char is_shader;
  struct shader_profile shader_profile;
} __attribute__((packed));

#define GEM_ARR_TYPE struct gem_profile
extern pthread_rwlock_t gem_lock;
extern GEM_ARR_TYPE *gem_arr;
extern size_t gem_arr_sz, gem_arr_used;

extern char verbose;
