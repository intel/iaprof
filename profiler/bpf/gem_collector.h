#ifndef GEM_COLLECTOR_H
#define GEM_COLLECTOR_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 512*1024

#define I915_EXEC_BATCH_FIRST (1<<18)

struct gem_info {
  __u32 pid;
  __u32 handle;
  __u32 batch_start_offset;
  __u64 batch_len;
  __u64 addr;
  __u64 gpu_addr;
  __u64 size;
  __u64 offset;
  __u64 file;
  char name[TASK_COMM_LEN];
  char is_bb;
};

#endif
