# AI Flame Graphs


## Introduction

> **Note:** This version targets Xe-family consumer and data center GPUs. If you
> were using `iaprof` on the Intel® Tiber™ AI Cloud with a PVC device, see the
> [`tiber`](https://github.com/intel/iaprof/tree/tiber) tag.

This tool collects profiles of Intel GPU performance based on hardware sampling and
generates visualizations from the results: AI flame graphs and subsecond-offset heatmaps.

It combines [EU stalls](https://www.intel.com/content/www/us/en/docs/gpa/user-guide/2022-4/gpu-metrics.html),
CPU stacks, and GPU kernel information to link CPU code to GPU performance metrics.
The resulting profile output can be consumed by external tools to generate
visualizations such as:
1. [Flame Graphs](https://www.brendangregg.com/blog/2024-10-29/ai-flame-graphs.html)
2. [FlameScope](https://www.brendangregg.com/blog/2018-11-08/flamescope-pattern-recognition.html)-style subsecond-offset heatmaps

The following Intel Xe-family hardware is supported on Linux:
- Intel® Arc™ B-series graphics cards (Battlemage)
- Intel® Core™ Ultra processors with Intel® Arc™ graphics (Lunar Lake)
- Other Intel® Xe2-based devices (untested)


## Prerequisites


### Linux Kernel

You will need Linux 6.15 or later, which includes [EU stall sampling support](https://patchwork.freedesktop.org/series/145443/) for the xe driver.

[BTF type information](https://docs.kernel.org/bpf/btf.html) is required for both
`vmlinux` and the xe driver. These are typically found at `/sys/kernel/btf/vmlinux`
and `/sys/kernel/btf/xe` once the driver is loaded. If `/sys/kernel/btf/xe` is
absent, your kernel may have been built without `CONFIG_DEBUG_INFO_BTF_MODULES=y`.


### Level Zero Runtime with USDT Probes

`iaprof` uses [USDT probes](https://lwn.net/Articles/753601/) in `libze_intel_gpu`
(the Intel GPU Level Zero runtime) to observe GPU kernel launches and collect kernel
debug information. Standard NEO releases do not yet include these probes; until they
are upstreamed, a patched build is required.

Patches against a supported NEO release are provided on the
[Releases](https://github.com/intel/iaprof/releases) page.

> **Note:** Documentation for the specific NEO version and patch instructions is coming soon.


### Frame Pointers

The profiled application and its dependencies — including the graphics stack — must
be compiled with frame pointers enabled in order to collect reliable CPU stacks.
Add these flags to C/C++ compile commands:

```
-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
```

Work is in progress to have frame pointer support integrated into official graphics
stack packages. In the meantime, you will need to rebuild relevant libraries from
source with the flags above.


## Building

Install build dependencies:
```
sudo apt install libelf-dev clang llvm python3-mako cmake libzstd-dev
```

A Rust toolchain is also required. The recommended way to install one is via
[rustup](https://rustup.rs) rather than the `cargo` package from apt, which is
often out of date:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repo and build:
```
git clone --recursive https://github.com/intel/iaprof
cd iaprof
make deps
./build.sh
```

NOTE: if the `make deps` step fails, ensure that `user.name` and `user.email` are
set in your git config.

The built binary is placed at `build/iaprof`.


## Running

Start the profiler (requires root):
```
sudo build/iaprof > profile.txt
```

Run your GPU workload. When done, interrupt `iaprof` with `ctrl-C`.

You can tune collection with the following options:
- `--interval=MS` — output interval in milliseconds (default: 10)
- `--eu-stall-subsample=N` — process one out of every N EU stall samples (default: 100)


## Workload-specific Requirements

> **Note:** This section is incomplete. More detailed per-framework guidance is coming once frame pointer support is available in official graphics stack packages.

### Python

Python added perf support (and frame pointer support through trampolines) in version
3.12. This is the minimum required version for profiling with this tool. The CPython
interpreter itself must also be compiled with frame pointers enabled.

Set this environment variable before running a Python workload to enable perf support:

```
export PYTHONPERFSUPPORT=1
```

### PyTorch

PyTorch workloads typically use a mix of SYCL, oneDNN, and oneMKL kernels. Frame
pointers must be enabled for the following components:

- PyTorch itself
- IPEX (Intel Extension for PyTorch)
- oneCCL and its PyTorch bindings (a dependency of IPEX)
- The SYCL runtime
- oneMKL
- oneDNN

> **Note:** Guidance on which of these components may already ship with frame pointers on supported distributions is coming soon.


## Visualizing

The `iaprof` output format is a tab-separated text stream that can be consumed by
external tools. [ProVis](https://github.com/kammerdienerb/proviz) is one such tool
that reads this format and generates flame graphs and subsecond-offset heatmaps. A
conversion script for producing standard
[stackcollapse](https://github.com/BrendanGregg/FlameGraph) output (compatible with
`flamegraph.pl` and other tools) is also planned.

> **Note:** The stackcollapse conversion script is not yet available.


## Troubleshooting / FAQ

### Can I use iaprof as a continuous profiler?

The overhead of `iaprof` is low, but the current version is not designed for
continuous profiling. It profiles a single active workload and does not handle
multiple transient workloads as would be seen in a multi-tenant environment.

### CPU stacks don't go all the way back to `_start`/`main`

Ensure all code is compiled with frame pointers as described above. If your CPU
stack ends in one frame of `libfoo.so`, that library is likely missing frame pointers.

### Some CPU stacks are incomplete even with frame pointers enabled

Stacks can be truncated if they exceed the kernel's collection limit. Raise it with:

```
sudo sysctl kernel.perf_event_max_stack=512
sudo sysctl kernel.perf_event_max_contexts_per_stack=64
```

If stacks are still truncated below that depth, it may be due to the kernel stopping
early on encountering a non-resident stack page. This can occur under memory pressure
or with NUMA balancing enabled.

### My workload runs slower with the profiler enabled

`iaprof` is designed to have low overhead, but some slowdown may still be
noticeable depending on the workload. If `iaprof` itself is consuming significant
CPU, the `--eu-stall-subsample` option can reduce its processing load.
