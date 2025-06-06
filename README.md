# AI Flame Graphs


## Introduction


This tool collects profiles of Intel AI accelerator and GPU performance based on hardware sampling,
and generates visualizations from these results: AI flame graphs and GPU flame graphs.

Specifically, it combines [EU stalls](https://www.intel.com/content/www/us/en/docs/gpa/user-guide/2022-4/gpu-metrics.html),
CPU stacks, and AI/GPU kernel information to provide a link between CPU code and
GPU performance metrics. Using the resulting profile, it can create advanced
visualizations which can greatly help AI/GPU performance analysis:
1. [Flame Graphs](https://www.brendangregg.com/blog/2024-10-29/ai-flame-graphs.html)
2. [FlameScope](https://www.brendangregg.com/blog/2018-11-08/flamescope-pattern-recognition.html)

The following hardware platforms are supported on Linux:
1. Intel® Data Center GPU Max Series (code named Ponte Vecchio)
2. Intel® Arc™ B-series graphics cards (code named Battlemage)
3. Other Intel® Xe2-based graphics cards, including Lunar Lake's iGPU (untested)


## Prerequisites


Specific requirements depend on your platform.
If you are on the Intel® Tiber™ AI Cloud[^1], please see [here](docs/README.pvc.md).
If you are on a Battlemage discrete graphics card, please see [here](docs/README.bmg.md).

Various software stack changes may be required, including:

### Custom Kernel Driver

A custom Linux kernel driver may be required depending on your platform.
Details for supported platforms are below.

### Frame Pointers

In general, a profiled application’s code and all of its dependencies must be
compiled with [frame pointers
enabled](https://www.brendangregg.com/blog/2024-03-17/the-return-of-the-frame-pointers.html)
in order to get reliable CPU stacks in the profiler’s output. Enabling this
typically requires adding these flags to the C/C++ compile commands:

```
-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
```

If you do not have control over the build process for a particular
library/project, look for packages that build it specifically with frame
pointers enabled (e.g. `libc-prof` on older Ubuntu). Otherwise please submit
requests/issues with the project maintainers to add frame pointer support in
their next release.

### BTF Type Information

You will need to have [BTF type
information](https://docs.kernel.org/bpf/btf.html) for at least `vmlinux`; for
most distributions, this is stored in `/sys/kernel/btf/vmlinux`. You may need
additional BTF files for your kernel driver, depending on your driver and
use-case. Please see the corresponding README in `docs/` for more details.

### Application and Runtime Configuration

Collection of enhanced GPU kernel information might require the modification of
applications and runtimes. For example, applications that use the Vulkan API
may need to be modified to provide shader names to the runtime.


## Building `iaprof`

*Note: customers of the Intel® Tiber™ AI Cloud[^1] may choose to use a prebuilt binary release.*

Install build dependencies:
```
sudo apt install libelf-dev g++-12 llvm clang python3-mako cmake libzstd-dev
```

Clone repo and build:
```
git clone --recursive https://github.com/intel/iaprof
cd iaprof
make deps
make
```
NOTE: if the `make deps` step fails, ensure that you have `user.name` and `user.email` set in your `git` config.

## Running `iaprof`

A helper script is provided to run `iaprof` and generate SVG flame graphs for you:
- Run the script, `aiflamegraph.sh` and wait for initialization (can take up to a minute in some cases) e.g.:
  
  ```
  sudo ./scripts/aiflamegraph.sh
  ```
- Run a GPU based workload, e.g. an example from the [oneAPI samples](https://github.com/oneapi-src/oneAPI-samples)
- Interrupt the `aiflamegraph.sh` script with `ctrl-C` at any time to stop profiling.
- Open the generated flame graph SVG file in a browser or other image viewer.


## Interpreting the Output

The output of this tool is a flame graph (see [Brendan Gregg's
page](https://www.brendangregg.com/flamegraphs.html)) SVG file. You can view
this file in any browser or some other preferred image viewer. It is interactive
and allows you to zoom in on stack frames of interest and search around for a
symbol or pattern.

The top frames in blue of each stack indicate the GPU instruction being executed
for a collected EU stall sample. The yellow/orange/red/pink frames below them
are the CPU stack frames that launched the sampled GPU kernel. Each frame’s
rectangle’s width represents how often it appeared in the stack below, giving an
indication of how “heavy” a particular stack was.

The example below shows a simple program for SYCL (a high-level C++ language for
accelerators) that tests three implementations of matrix multiply, running them
with the same input workload. The flame graph is dominated by the slowest
implementation, multiply\_basic(), which doesn't use any optimizations and
consumes at 72% of stall samples and is shown as the widest tower. On the right
are two thin towers for multiply\_local\_access() at 21% which replaces the
accessor with a local variable, and multiply\_local\_access\_and\_tiling() at 6%
which also adds matrix tiling. The towers are getting smaller as optimizations
are added.

![PyTorch Example](docs/example_sycl_matmul.png)

This is a useful visualization of the performance of your AI workload because it
allows you to correlate CPU code from several layers including Python
frameworks, runtime libraries, and the OS kernel to a meaningful measurement of
GPU execution.


# Troubleshooting / FAQ

### What about other hardware including NVIDIA?

This is a new project that currently only supports limited Intel hardware listed in the Introduction.

### Can I use iaprof as a continuous profiler?

Our aim is to have overhead less than 5% (CPU footprint), however, the current overhead is expected to be larger, and for i915 workloads much larger. This makes the current version unsuitable for continuous profiling, however, we aim to change that in the future. Additional work is also needed to support multiple transient workloads (such as with a multi-tenant environment) as would be seen by a continuous profiler, rather than the current version that profiles a single active workload. To be clear: If you turn this into a continuous profiler without first addressing these issues you will produce invalid and costly profiles, giving people a bad experience.

### **CPU stacks don’t go all the way back to \_start/main:**

Ensure that all code is compiled to include frame pointers as described above.
If your CPU stack ends in one frame of libfoo.so, it libfoo.so is likely not
compiled with frame pointers.
    
### **My code has frame pointers enabled and some CPU stacks are *still* incomplete:**  
  	
One reason that stacks can be incomplete is that they are simply deeper than the
maximum stack depth that the linux kernel will collect. This limit can be set as
follows:

```
sudo sysctl kernel.perf_event_max_stack=512
sudo sysctl kernel.perf_event_max_contexts_per_stack=64
```

If your stack ends prematurely, but is below the max stack depth, it could be
related to the kernel’s intolerance for page faults in the stack collection
code. The Linux kernel routine that collects FP stack traces will stop
prematurely if it encounters a non-resident stack page, resulting in an
incomplete stack. This is unlikely to be the case, but we’ve seen it happen with
NUMA balancing. Memory pressure could also be causing parts of the stack to get
swapped out.

### **My workload runs slowly when the profiler is enabled.**

This tool can introduce a moderate amount of overhead for many workloads.
Efforts are being made to reduce overhead in the future. For now, this is not an
“always on” profiling tool.

[^1]: *Intel, the Intel logo and Intel Tiber are trademarks of Intel Corporation or its subsidiaries.*
