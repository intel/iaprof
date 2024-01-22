#ifndef GEM_COLLECTOR_H
#define GEM_COLLECTOR_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 512*1024

/* GEN binary copying maximums */
#define MAX_BINARY_SIZE 1024
#define MAX_BINARIES_IN_FLIGHT 16

#define I915_EXEC_BATCH_FIRST (1<<18)

struct binary_info {
  __u64 start, end;
  unsigned char buff[MAX_BINARY_SIZE];
};

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
