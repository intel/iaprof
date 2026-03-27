// Copyright 2026 Intel Corporation
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

extern int LINUX_KERNEL_VERSION __kconfig;

#define ERR_PRINTK(...) bpf_printk("ERROR:   " __VA_ARGS__)
#ifdef DEBUG
#define DEBUG_PRINTK(...) bpf_printk("         " __VA_ARGS__)
#define WARN_PRINTK(...) bpf_printk("WARNING: " __VA_ARGS__)
#else
#define DEBUG_PRINTK(...) ;
#define WARN_PRINTK(...) ;
#endif

/* The path component of the section name is 4096 (PATH_MAX) spaces.
   We overwrite this memory prior to attachment with an actual path. */
#define USDT_SEC_PLACEHOLDER(suffix) \
SEC("usdt/                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                :" suffix)

