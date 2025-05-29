/*
Copyright 2025 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/***************************************
* Event Collector
***************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#include "commands/record.h"

#include "stores/gpu_kernel.h"

#include "printers/stack/stack_printer.h"
#include "printers/debug/debug_printer.h"
#include "printers/interval/interval_printer.h"

#include "bpf/main.h"
#include "bpf/main.skel.h"
#include "bpf_collector.h"
#include "collectors/debug/debug_collector.h"

#include "utils/utils.h"
#include "utils/hash_table.h"
#include "utils/demangle.h"

struct live_execbuf {
        uint64_t eb_id;
        uint64_t proc_name_id;
        uint64_t ustack_id;
        uint64_t kstack_id;
        uint32_t pid;
};

typedef struct live_execbuf live_execbuf_struct;

static uint64_t hash_eb_id(uint64_t eb_id) { return eb_id; }

use_hash_table(uint64_t, live_execbuf_struct);

static hash_table(uint64_t, live_execbuf_struct) live_execbufs;

/***************************************
* BPF Handlers
***************************************/

int handle_execbuf(void *data_arg)
{
        struct execbuf_info *info;
        struct live_execbuf *existing;
        struct live_execbuf  live;

        info = (struct execbuf_info *)data_arg;

        existing = hash_table_get_val(live_execbufs, info->eb_id);
        if (existing != NULL) {
                ERR("execbuf info eb_id already seen, eb_id = %llu", info->eb_id);
        }

        live.pid          = info->pid;
        live.proc_name_id = print_string(info->name);
        live.ustack_id    = print_string(store_ustack(info->pid, &info->ustack));
        live.kstack_id    = print_string(store_kstack(&info->kstack));

        hash_table_insert(live_execbufs, info->eb_id, live);

        if (eudebug_collector) {
                /* Register the PID with the eudebug collector */
                init_eudebug(devinfo.fd, info->pid);
        }

        return 0;
}

int handle_execbuf_end(void *data_arg)
{
        struct execbuf_end_info *info;
        struct live_execbuf     *live;

        info = (struct execbuf_end_info *)data_arg;

        live = hash_table_get_val(live_execbufs, info->eb_id);
        if (live == NULL) {
                ERR("execbuf_end for eb_info we've never seen, eb_id = %llu", info->eb_id);
                return 0;
        }

        hash_table_delete(live_execbufs, info->eb_id);

        return 0;
}


int handle_ksp(void *data_arg)
{
        struct ksp_info     *info;
        struct live_execbuf *exec;
        uint64_t             masked_addr;
        struct shader       *shader;

        info = (struct ksp_info *)data_arg;
        exec = hash_table_get_val(live_execbufs, info->eb_id);
        if (exec == NULL) {
                ERR("KSP for exec that is not live");
                return 0;
        }

        masked_addr = info->addr & 0xFFFFFFFFFF00;
        shader      = acquire_or_create_shader(masked_addr);
        if (shader->type == SHADER_TYPE_UNKNOWN) {
                shader->type = SHADER_TYPE_SHADER;
                debug_printf("  Marked buffer as a shader: gpu_addr=0x%lx\n", shader->gpu_addr);
        }

        shader->pid          = exec->pid;
        shader->proc_name_id = exec->proc_name_id;
        shader->ustack_id    = exec->ustack_id;
        shader->kstack_id    = exec->kstack_id;

        release_shader(shader);
        wakeup_eustall_deferred_attrib_thread();

        return 0;
}

int handle_sip(void *data_arg)
{
        struct sip_info     *info;
        struct live_execbuf *exec;
        struct shader       *shader;

        info = (struct sip_info *)data_arg;
        exec = hash_table_get_val(live_execbufs, info->eb_id);
        if (exec == NULL) {
                ERR("SIP for exec that is not live");
                return 0;
        }

        shader = acquire_or_create_shader(info->addr);
        if (shader->type == SHADER_TYPE_UNKNOWN) {
                shader->type = SHADER_TYPE_SYSTEM_ROUTINE;
                debug_printf("  Marked buffer as a SIP: gpu_addr=0x%lx\n", shader->gpu_addr);
        }

        shader->pid          = exec->pid;
        shader->proc_name_id = exec->proc_name_id;
        shader->ustack_id    = exec->ustack_id;
        shader->kstack_id    = exec->kstack_id;

        release_shader(shader);
        wakeup_eustall_deferred_attrib_thread();

        return 0;
}


int handle_uprobe_ksp(void *data_arg)
{
        struct uprobe_ksp_info *info;
        uint64_t                masked_addr;
        struct shader          *shader;

        info = (struct uprobe_ksp_info *)data_arg;

        if (eudebug_collector) {
                /* Register the PID with the eudebug collector */
                init_eudebug(devinfo.fd, info->pid);
        }

        masked_addr = info->addr & 0xFFFFFFFFFF00;
        shader      = acquire_or_create_shader(masked_addr);
        if (shader->type == SHADER_TYPE_UNKNOWN) {
                shader->type = SHADER_TYPE_SHADER;
                debug_printf("  Marked buffer as a shader: gpu_addr=0x%lx\n", shader->gpu_addr);
        }

        shader->size         = info->size;
        shader->pid          = info->pid;
        shader->ustack_id    = print_string(store_ustack(info->pid, &info->ustack));
        shader->kstack_id    = 0;
        shader->proc_name_id = print_string(info->name);

        release_shader(shader);
        wakeup_eustall_deferred_attrib_thread();

        return 0;
}

int handle_uprobe_elf(void *data_arg)
{
        struct uprobe_elf_info *info;

        info = (struct uprobe_elf_info *)data_arg;

        extract_elf_kernel_info(info->data, info->size);

        return 0;
}

int handle_uprobe_kernel_info(void *data_arg)
{
        struct uprobe_kernel_info *info;
        uint64_t                   masked_addr;
        uint64_t                   symbol_id;
        char                      *demangled;
        uint64_t                   filename_id;

        info = (struct uprobe_kernel_info *)data_arg;

        masked_addr = info->addr & 0xFFFFFFFFFF00;

        symbol_id = 0;
        if (info->symbol[0]) {
                demangled = demangle(info->symbol);

                if (demangled) {
                        symbol_id = print_string(demangled);
                        free(demangled);
                } else {
                        symbol_id = print_string(info->symbol);
                }
        }

        filename_id = 0;
        if (info->filename[0]) {
                filename_id = print_string(info->filename);
        }

        set_kernel_info(masked_addr, info->size, symbol_id, filename_id, info->linenum);

        return 0;
}

int handle_uprobe_frame_info(void *data_arg)
{
        print_frame();
        return 0;
}

int handle_uprobe_kernel_bin(void *data_arg)
{
        struct uprobe_kernel_bin *info;
        uint64_t                  masked_addr;

        info = (struct uprobe_kernel_bin *)data_arg;

        masked_addr = info->addr & 0xFFFFFFFFFF00;

        set_kernel_binary(masked_addr, info->data, info->size);

        return 0;
}


/* Runs each time a sample from the ringbuffer is collected. */
static int handle_sample(void *ctx, void *data_arg, size_t data_sz)
{
        uint8_t type;

        type = *((uint8_t*)data_arg);

        switch (type) {
                case BPF_EVENT_TYPE_EXECBUF:            return handle_execbuf(data_arg);
                case BPF_EVENT_TYPE_EXECBUF_END:        return handle_execbuf_end(data_arg);
                case BPF_EVENT_TYPE_KSP:                return handle_ksp(data_arg);
                case BPF_EVENT_TYPE_SIP:                return handle_sip(data_arg);
                case BPF_EVENT_TYPE_UPROBE_KSP:         return handle_uprobe_ksp(data_arg);
                case BPF_EVENT_TYPE_UPROBE_ELF:         return handle_uprobe_elf(data_arg);
                case BPF_EVENT_TYPE_UPROBE_KERNEL_INFO: return handle_uprobe_kernel_info(data_arg);
                case BPF_EVENT_TYPE_UPROBE_KERNEL_BIN:  return handle_uprobe_kernel_bin(data_arg);
                case BPF_EVENT_TYPE_UPROBE_FRAME_INFO:  return handle_uprobe_frame_info(data_arg);
        }

        ERR("Unknown data type when handling a sample: %u\n", type);
        return -1;
}

/***************************************
* BPF Setup
***************************************/

int deinit_bpf()
{
        uint64_t i;
        int retval;
        size_t ring_buffer_avail;
        struct ring *ring;

        ring = ring_buffer__ring(bpf_info.rb, 0);
        ring_buffer_avail = ring__avail_data_size(ring);
        debug_printf("Leftover ringbuffer size: %lu\n", ring_buffer_avail);

        for (i = 0; i < bpf_info.num_links; i++) {
                retval = bpf_link__destroy(bpf_info.links[i]);
                if (retval == -1) {
                        return retval;
                }
        }
        free(bpf_info.links);

        main_bpf__destroy(bpf_info.obj);

        return 0;
}

int init_bpf()
{
        int err, stack_limit;
        FILE *file;

        /* Check the value of kernel.perf_event_max_stack */
        stack_limit = 127;
        file = fopen("/proc/sys/kernel/perf_event_max_stack", "r");
        if (file) {
                /* If we're able to read it from /proc, set it to that
                   value. To be safe, just default to a typical value that
                   we've seen (127). */
                fscanf(file, "%d", &stack_limit);
                fclose(file);
        }

        bpf_info.stackmap_fd = bpf_map_create(BPF_MAP_TYPE_STACK_TRACE,
                                 "stackmap", 4, sizeof(uintptr_t) * stack_limit,
                                 1<<14, 0);

        bpf_info.obj = main_bpf__open_and_load();
        if (!bpf_info.obj) {
                ERR("Failed to get BPF object.\n"
                    "       Most likely, one of two things are true:\n"
                    "       1. You're not root.\n"
                    "       2. You don't have a kernel that supports BTF type information.\n");
                return -1;
        }

        err = main_bpf__attach(bpf_info.obj);
        if (err) {
                ERR("Failed to attach BPF programs.\n");
                return -1;
        }


        live_execbufs = hash_table_make(uint64_t, live_execbuf_struct, hash_eb_id);


        bpf_info.rb = ring_buffer__new(bpf_map__fd(bpf_info.obj->maps.rb),
                                       handle_sample, NULL, NULL);
        if (!(bpf_info.rb)) {
                ERR("Failed to create a new ring buffer. You're most likely not root.\n");
                return -1;
        }

        bpf_info.rb_fd = bpf_map__fd(bpf_info.obj->maps.rb);
        bpf_info.epoll_fd = ring_buffer__epoll_fd(bpf_info.rb);
        bpf_info.dropped_event = &(bpf_info.obj->bss->dropped_event);

        return 0;
}

/*******************
*      DEBUG       *
*******************/
void print_ringbuf_stats()
{
        uint64_t size, avail;

        avail = ring__avail_data_size(ring_buffer__ring(bpf_info.rb, 0));
        size = ring__size(ring_buffer__ring(bpf_info.rb, 0));
        debug_printf("GEM ringbuf usage: %lu / %lu\n", avail, size);
}
