#ifndef GEM_COLLECTOR_H
#define GEM_COLLECTOR_H

#define MAX_STACK_DEPTH 127
#define TASK_COMM_LEN 16
#define MAX_ENTRIES 1024 * 1024
#define RINGBUF_SIZE 512 * 1024 * 1024 /* 512 MB */

/* GEN binary copying maximums */
#define MAX_BINARY_SIZE 1024 * 1024

#ifndef I915_EXEC_BATCH_FIRST
#define I915_EXEC_BATCH_FIRST (1 << 18)
#endif

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
struct unmap_info {
        __u64 file;
        __u32 handle;
        __u64 cpu_addr;
        __u64 size;
        unsigned char buff[MAX_BINARY_SIZE];

        __u32 pid, tid, cpu;
        __u64 time;
};

/* Collected from a vm_create */
struct vm_create_info {
        __u32 pid, tid, cpu;
        __u64 time;
        int stackid;
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

        char pad[7];
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
        __u64 file;

        __u64 batch_len;
        __u32 batch_start_offset, batch_index, buffer_count;

        /* The GPU address and a copy of the batchbuffer data */
        __u64 bb_offset;
        unsigned char buff[MAX_BINARY_SIZE];
        __u64 buff_sz;

        char name[TASK_COMM_LEN];
        __u32 cpu, pid, tid;
        __u64 time;
        int stackid;

        char pad[8];
};

/* Collected at execbuffer time, represents a batchbuffer */
struct batchbuffer_info {
        __u32 pid, tid, cpu;
        __u64 time;
        __u64 gpu_addr, buff_sz;
        __u32 vm_id;
        unsigned char buff[MAX_BINARY_SIZE];
};

/* Collected from the end of an execbuffer */
struct execbuf_end_info {
        __u32 cpu, pid, tid;
        __u64 time;
};

/* Collected from the end of a call to i915_gem_userptr_ioctl */
struct userptr_info {
        __u64 file;
        __u32 handle;
        __u64 cpu_addr;
        __u64 size;
        unsigned char buff[MAX_BINARY_SIZE];

        __u32 pid, tid, cpu;
        __u64 time;
        char pad[8];
};

/* Collected from the tracepoints i915_request_* */
enum i915_request_type {
        REQUEST_SUBMIT,
        REQUEST_IN,
        REQUEST_OUT,
        REQUEST_RETIRE
};

struct request_info {
        enum i915_request_type type;
        __u32 seqno;
        __u32 gem_ctx;
        __u16 class, instance;
        __u64 time;
        char pad[16];
};

#endif
