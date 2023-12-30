#pragma once

#include <asm/types.h>
#include "bpf/gem_collector.h"

struct gem_profile {
  struct kernel_info kinfo;
  unsigned char *buff;
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

#define GEM_ARR_TYPE struct gem_profile
extern pthread_rwlock_t gem_lock;
extern GEM_ARR_TYPE *gem_arr;
extern size_t gem_arr_sz, gem_arr_used;

extern char verbose;
