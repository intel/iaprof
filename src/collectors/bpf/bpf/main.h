// Copyright 2025 Intel Corporation
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#ifndef GEM_COLLECTOR_H
#define GEM_COLLECTOR_H

#define MAX_STACK_DEPTH     (512)
#define TASK_COMM_LEN       (16)
#define MAX_MAPPINGS        (4 * 1024)
#define MAX_PAGE_ENTRIES    (1024 * 1024)
#define MAX_BINARY_SIZE     (1024 * 1024)
#define MAX_SYMBOL_SIZE     (1024)
#define MAX_FILENAME_SIZE   (4096)
#define RINGBUF_SIZE        (512 * 1024 * 1024) /* 512 MB */
#define PAGE_SIZE           (4096)
#define PAGE_MASK           (~0xfff)
#define UPPER_MASK          (~0xffff000000000000)

#define MAX_BB_DWORDS       (1024)
#define MAX_BB_DWORDS_IDX   (MAX_BB_DWORDS - 1)
#define MAX_BB_BYTES        (MAX_BB_DWORDS * sizeof(uint32_t))
#define MAX_BB_COMMANDS     (8192)
#define MAX_BB_DEFERRED     (64)
#define MAX_BB_KSP          (128)
#define MAX_BB_ATTEMPTS     (5)
#define MAX_BB_NSECS        (100000000)

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

static inline void copy_stack(struct stack *dst, struct stack *src) {
        int i;

        if (dst == NULL || src == NULL) { return; }

        for (i = 0; i < MAX_STACK_DEPTH; i += 1) {
                dst->addrs[i] = src->addrs[i];
        }
}

static inline void copy_comm_name(char *dst, char *src) {
        int i;

        if (dst == NULL || src == NULL) { return; }

        for (i = 0; i < TASK_COMM_LEN; i += 1) {
                dst[i] = src[i];
        }
}

enum {
    BPF_EVENT_TYPE_UNKNOWN,
    BPF_EVENT_TYPE_DEVICE_QUERY,
    BPF_EVENT_TYPE_EXECBUF,
    BPF_EVENT_TYPE_EXECBUF_END,
    BPF_EVENT_TYPE_IBA,
    BPF_EVENT_TYPE_KSP,
    BPF_EVENT_TYPE_SIP,
    BPF_EVENT_TYPE_UPROBE_IBA,
    BPF_EVENT_TYPE_UPROBE_KSP,
    BPF_EVENT_TYPE_UPROBE_ELF,
    BPF_EVENT_TYPE_UPROBE_KERNEL_INFO,
    BPF_EVENT_TYPE_UPROBE_KERNEL_BIN,
    BPF_EVENT_TYPE_UPROBE_FRAME_INFO,
};

struct device_query_info {
        __u8         type;
        __u32        pid;
};

struct execbuf_info {
        __u8         type;

        __u64        eb_id;

        __u32        vm_id;
        __u64        file;

        struct stack ustack;
        struct stack kstack;

        __u64        time;
        __u32        pid;
        __u32        tid;
        __u32        cpu;
        char         name[TASK_COMM_LEN];
};

struct execbuf_end_info {
        __u8  type;

        __u64 eb_id;
};

struct ksp_info {
        __u8  type;

        __u64 eb_id;
        __u64 addr;
};

struct sip_info {
        __u8  type;

        __u64 eb_id;
        __u64 addr;
};

struct uprobe_ksp_info {
        __u8         type;

        __u64        addr;
        __u64        size;

        struct stack ustack;

        __u64        time;
        __u32        pid;
        __u32        tid;
        __u32        cpu;
        char         name[TASK_COMM_LEN];
};

struct uprobe_elf_info {
        __u8          type;

        __u64         size;
        unsigned char data[MAX_BINARY_SIZE];
};

struct uprobe_kernel_info {
        __u8  type;

        __u64 addr;

        __u64 size;
        char  symbol[MAX_SYMBOL_SIZE];
        char  filename[MAX_FILENAME_SIZE];
        int   linenum;
};

struct uprobe_kernel_bin {
        __u8          type;

        __u64         addr;

        __u64         size;
        unsigned char data[MAX_BINARY_SIZE];
};

struct uprobe_frame_info {
        __u8  type;
};

#endif
