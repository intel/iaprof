#ifndef GEM_COLLECTOR_H
#define GEM_COLLECTOR_H

#define MAX_STACK_DEPTH 512
#define TASK_COMM_LEN 16
#define MAX_ENTRIES 1024 * 1024
#define RINGBUF_SIZE 512 * 1024 * 1024 /* 512 MB */
#define MAX_BUFFER_COPIES 256
#define PAGE_SIZE 4096
#define PAGE_MASK ~(0xfff)

/* GEN binary copying maximums */
#define MAX_BINARY_SIZE     (2048 * 1024)
#define MAX_BB_DWORDS       (1024)
#define MAX_BB_DWORDS_IDX   (MAX_BB_DWORDS - 1)
#define MAX_BB_BYTES        (MAX_BB_DWORDS * sizeof(uint32_t))
#define MAX_BB_COMMANDS     (4 * MAX_BB_DWORDS)

#ifndef I915_EXEC_BATCH_FIRST
#define I915_EXEC_BATCH_FIRST (1 << 18)
#endif

struct file_handle_pair {
        __u64 file;
        __u32 handle;
};

struct stack {
        __u64 addrs[MAX_STACK_DEPTH];
};

enum {
    BPF_EVENT_TYPE_UNKNOWN,
    BPF_EVENT_TYPE_VM_CREATE,
    BPF_EVENT_TYPE_VM_BIND,
    BPF_EVENT_TYPE_VM_UNBIND,
    BPF_EVENT_TYPE_DEBUG_AREA,
    BPF_EVENT_TYPE_EXECBUF,
};

struct execbuf_info {
        __u8         type;

        __u32        vm_id;
        __u64        file;

        __u64        iba;
        __u64        sip;
        __u64        ksp;
        struct stack ustack;
        struct stack kstack;

        __u64        time;
        __u32        pid;
        __u32        tid;
        __u32        cpu;
        char         name[TASK_COMM_LEN];
};

/* Collected from an mmap */
struct mapping_info {
        __u8 type;

        __u64 file;
        __u32 handle;
        __u64 cpu_addr;
        __u64 size;
        __u64 offset;

        __u32 pid, tid, cpu;
        __u64 time;
};

/* Collected from an munmap, possibly
   after execbuffer */
struct unmap_info {
        __u8 type;

        __u64 file;
        __u32 handle;
        __u64 cpu_addr;
        __u64 size;

        __u32 pid, tid, cpu;
        __u64 time;
};

/* Collected from a vm_create */
struct vm_create_info {
        __u8 type;

        __u32 pid, tid, cpu;
        __u64 time;
        __u32 vm_id;
        __u64 file;
};

/* Collected from a vm_bind */
struct vm_bind_info {
        __u8 type;

        __u8 userptr;
        __u64 file;
        __u32 handle;
        __u32 vm_id;
        __u64 gpu_addr;
        __u64 size;
        __u64 offset;

        __u32 pid;
};

/* Collected from a vm_unbind */
struct vm_unbind_info {
        __u8 type;

        __u64 file;
        __u32 handle;
        __u32 vm_id;
        __u64 gpu_addr;
        __u64 size;
        __u64 offset;

        __u32 pid, tid, cpu;
        __u64 time;
};

/* Tells userspace that this vm/addr is a debug area. */
struct debug_area_info {
        __u8 type;

        __u32 pid, vm_id;
        __u64 file;
        __u64 gpu_addr;
        int stackid;
        char name[TASK_COMM_LEN];
};

#endif
