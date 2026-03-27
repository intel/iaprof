/*
Copyright 2026 Intel Corporation

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

#pragma once

#include "common.hpp"

typedef bool _Bool;
#include "discover.skel.h"
#include "patcher.skel.h"
#include "libze_intel_gpu.skel.h"
#include "discover_types.h"
#include "probes_types.h"

struct BPF_Object_Base {
    void               *obj        = nullptr;
    struct ring_buffer *ringbuf    = nullptr;
    int                 ringbuf_fd = -1;

    bool open_and_load() {
        this->obj = this->_open_and_load();
        return this->obj != nullptr;
    }
    bool attach(ring_buffer_sample_fn rb_sample_fn = nullptr) {
        return this->_attach(rb_sample_fn);
    }

    virtual void *_open_and_load()                            = 0;
    virtual bool  _attach(ring_buffer_sample_fn rb_sample_fn) = 0;

    virtual ~BPF_Object_Base() { }
};

template <typename OBJ_T>
concept BPF_Object_Has_RingBuf = requires(OBJ_T obj) { obj.maps.rb; };

template <typename OBJ_T>
struct BPF_Obj_Info {
    using Object_Type = OBJ_T;

    Object_Type* (*open_and_load_fn)();
    int          (*attach_fn)(Object_Type*);

    bool has_rb = BPF_Object_Has_RingBuf<OBJ_T>;

    constexpr BPF_Obj_Info(Object_Type *(*open_and_load_fn)(), int (*attach_fn)(Object_Type*))
        : open_and_load_fn(open_and_load_fn), attach_fn(attach_fn) {}
};

#define BPF_OBJ_INFO(name) BPF_Obj_Info<struct name##_bpf>(name##_bpf__open_and_load, name##_bpf__attach)

template <auto OBJ_INFO>
struct BPF_Object : BPF_Object_Base {
    using Object_Type = typename decltype(OBJ_INFO)::Object_Type;

    Object_Type *get_obj() { return (Object_Type*)this->obj; }

    void *_open_and_load() {
        Object_Type *obj = OBJ_INFO.open_and_load_fn();

        if (obj == nullptr) {
            WARN("Failed to get BPF object.\n"
                 "    Most likely, one of two things are true:\n"
                 "    1. You're not root.\n"
                 "    2. You don't have a kernel that supports BTF type information.\n");
        }

        return obj;
    }

    bool _attach(ring_buffer_sample_fn rb_sample_fn) {
        int err = OBJ_INFO.attach_fn(this->get_obj());
        if (err) {
            WARN("Failed to attach BPF programs.\n");
            return false;
        }

        if constexpr (OBJ_INFO.has_rb) {
            this->ringbuf = ring_buffer__new(bpf_map__fd(this->get_obj()->maps.rb), rb_sample_fn, NULL, NULL);
            if (!this->ringbuf) {
                WARN("Failed to create a new ring buffer. You're most likely not root.\n");
                return false;
            }

            errno = 0;
            this->ringbuf_fd = bpf_map__fd(this->get_obj()->maps.rb);
        }

        return true;
    }
};

#define BPF_OBJECT(name) BPF_Object<BPF_OBJ_INFO(name)>

class BPF_Collector {
    bool                                                    initialized = false;
    std::mutex                                              init_mtx;
    BPF_OBJECT(discover)                                    discover;
    BPF_OBJECT(patcher)                                     patcher;
    std::map<std::string, std::unique_ptr<BPF_Object_Base>> probes;
    std::mutex                                              probes_mtx;
    std::thread                                             thr;
    int                                                     thread_stop_pipe[2] = { -1, -1 };
    int                                                     trace_pipe_fd = -1;

    ~BPF_Collector();

    bool init();

    static int discover_sample_fn(void *ctx, void *data, size_t size);
    static int discover_handle_libze_intel_gpu(discover_libze_intel_gpu *data);

    static int probes_sample_fn(void *ctx, void *data, size_t size);
    static int handle_probe_event_iba(probe_event_iba *iba_event);
    static int handle_probe_event_kernel_launch(probe_event_kernel_launch *kernel_launch_event);
    static int handle_probe_event_kernel_path(probe_event_kernel_path *kernel_path_event);

    static void bpf_thread(BPF_Collector &bpf_collector);

public:
    static BPF_Collector &get();
};
