#ifndef KERNEL_WRITES_H
#define KERNEL_WRITES_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 512*1024
#define I915_EXEC_BATCH_FIRST (1<<18)

struct kernel_info {
  __u32 pid;
  __u32 handle;
  __u64 data;
  __u64 data_sz;
  __u64 offset;
  char name[TASK_COMM_LEN];
  char is_bb;
};

#endif
