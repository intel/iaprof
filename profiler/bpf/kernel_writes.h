#ifndef KERNEL_WRITES_H
#define KERNEL_WRITES_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 512*1024*1024

struct kernel_info {
  __u32 pid;
  void *data;
  size_t data_sz;
  char name[TASK_COMM_LEN];
};

#endif
