#ifndef GEM_COLLECTOR_H
#define GEM_COLLECTOR_H

#define MAX_STACK_DEPTH 127
#define TASK_COMM_LEN 16
#define MAX_ENTRIES 1024*1024
#define RINGBUF_SIZE 4096*4096*16

/* GEN binary copying maximums */
#define MAX_BINARY_SIZE 1024*1024

#define I915_EXEC_BATCH_FIRST (1<<18)

/* Collected from an mmap */
struct mapping_info {
  __u64 file;
  __u32 handle;
  __u64 cpu_addr;
  __u64 size;
  __u64 offset;
  
  __u32 pid, tid, cpu;
  __u64 time;
  int stackid;
};

/* Collected from an munmap, possibly
   after execbuffer */
struct binary_info {
  __u64 file;
  __u32 handle;
  __u64 cpu_addr;
  __u64 size;
  unsigned char buff[MAX_BINARY_SIZE];
  
  __u32 pid, tid, cpu;
  __u64 time;
};

/* Collected from a vm_bind */
struct vm_bind_info {
  __u64 file;
  __u32 handle;
  __u32 vm_id;
  __u64 gpu_addr;
  __u64 size;
  __u64 offset;
  
  __u32 pid, tid, cpu;
  __u64 time;
  int stackid;
  
  char pad[8];
};

/* Collected from a vm_unbind */
struct vm_unbind_info {
  __u64 file;
  __u32 handle;
  __u32 vm_id;
  __u64 gpu_addr;
  __u64 size;
  __u64 offset;
  
  __u32 pid, tid, cpu;
  __u64 time;
};

/* Collected from the start of an execbuffer */
struct execbuf_start_info {
  __u32 ctx_id, vm_id;
  
  char name[TASK_COMM_LEN];
  __u32 cpu, pid, tid;
  __u64 time;
  int stackid;
};

/* Collected from the end of an execbuffer */
struct execbuf_end_info {
  __u32 cpu, pid, tid;
  __u64 time;
};

#endif
