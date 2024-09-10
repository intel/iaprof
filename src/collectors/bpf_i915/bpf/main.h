#ifndef GEM_COLLECTOR_H
#define GEM_COLLECTOR_H

#define MAX_STACK_DEPTH 127
#define TASK_COMM_LEN 16
#define MAX_ENTRIES 1024 * 1024
#define RINGBUF_SIZE 512 * 1024 * 1024 /* 512 MB */
#define MAX_BUFFER_COPIES 256

/* GEN binary copying maximums */
#define MAX_BINARY_SIZE (512 * 1024)

#ifndef I915_EXEC_BATCH_FIRST
#define I915_EXEC_BATCH_FIRST (1 << 18)
#endif

struct file_handle_pair {
        __u64 file;
        __u32 handle;
};

struct buffer_copy {
        uint64_t      size;
        unsigned char bytes[MAX_BINARY_SIZE];
};

enum {
    BPF_EVENT_TYPE_UNKNOWN,
    BPF_EVENT_TYPE_MAPPING,
    BPF_EVENT_TYPE_UNMAP,
    BPF_EVENT_TYPE_VM_CREATE,
    BPF_EVENT_TYPE_VM_BIND,
    BPF_EVENT_TYPE_VM_UNBIND,
    BPF_EVENT_TYPE_EXECBUF_START,
    BPF_EVENT_TYPE_EXECBUF_END,
    BPF_EVENT_TYPE_BATCHBUFFER,
    BPF_EVENT_TYPE_USERPTR,
    BPF_EVENT_TYPE_DEBUG_AREA,
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
        int stackid;
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
};

/* Collected from a vm_bind */
struct vm_bind_info {
        __u8 type;

        __u64 file;
        __u32 handle;
        __u32 vm_id;
        __u64 gpu_addr;
        __u64 size;
        __u64 offset;
        __u64 flags;

        __u32 pid, tid, cpu;
        __u64 time;
        int stackid;
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

/* Collected from the start of an execbuffer */
struct execbuf_start_info {
        __u8 type;

        __u32 ctx_id, vm_id;
        __u64 file;

        __u64 batch_len;
        __u32 batch_start_offset, batch_index, buffer_count;

        /* The GPU address */
        __u64 bb_offset;

        char name[TASK_COMM_LEN];
        __u32 cpu, pid, tid;
        __u64 time;
        int stackid;
};

/* Represents a copy of a batchbuffer */
struct batchbuffer_info {
        __u8 type;

        __u32 pid, tid, cpu;
        __u64 time;
        __u64 gpu_addr;
        __u32 vm_id;
};

/* Collected from the end of an execbuffer */
struct execbuf_end_info {
        __u8 type;

        __u32 ctx_id, vm_id;
        __u64 file;

        __u64 batch_len;
        __u32 batch_start_offset, batch_index, buffer_count;

        /* The GPU address */
        __u64 bb_offset;

        char name[TASK_COMM_LEN];
        __u32 cpu, pid, tid;
        __u64 time;
        int stackid;
};

/* Collected from the end of a call to i915_gem_userptr_ioctl */
struct userptr_info {
        __u8 type;

        __u64 file;
        __u32 handle;
        __u64 cpu_addr;

        __u32 pid, tid, cpu;
        __u64 time;
};

/* Tells userspace that this vm/addr is a debug area. */
struct debug_area_info {
        __u8 type;

        __u32 pid, vm_id;
        __u64 gpu_addr;
        int stackid;
        char name[TASK_COMM_LEN];
};

#endif
