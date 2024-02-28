Current State
=============

This is the current state of the PVC profiler as of February 28, 2024.
It's just meant as a "living document" to record what's going on with the project.

Design
======

The main design is split into several directories:
1. `common/`, which includes architecture-specific code, such as detecting PVC cards
   and anything that interacts directly with i915 or the DRM subsystem. This directory
   also includes `utils/`, which are simple utilities.
2. `profiler/`, which includes the entirety of the profiler portion. This is split into:
   
   `profiler/pvc_profile.[ch]`: This is the main userspace program, which essentially
   launches a thread which spins on the file descriptors for the EU stalls and the BPF
   ringbuffer, waits to receive a signal to die, and spits out the final printout.
   
   `profiler/gem_collector.[ch]`: These files interact directly with the BPF program.
   BPF attachment and ringbuffer reading are here, along with handlers that get run
   each time an event is seen on the ringbuffer.
   
   `profiler/eustall_collector.[ch]`: These files set up and read EU stalls. There's a
   handler function that gets run each time the perf-like file descriptor says that it
   has data to read.
   
   `profiler/shader_decoder.[ch]`: This handles GEN binary disassembly. It's basically
   just a simple wrapper around the Intel Graphics Assembler (IGA) API that translates
   GEN binaries into textual assembly instructions.
   
   `profiler/stack_printer.[ch]`: Does as it says; prints stacks. Uses the `trace_helpers`
   from the `common` directory, gotten from the BCC repo.
   
   `profiler/printer.h`: Prints out debug information about each event.
   
   `profiler/bb_parser.h`: Attempts to parse batch buffers. These are copied out when
   the profiler sees a call to `i915_gem_execbuffer2_ioctl`. It's disabled for now,
   since it doesn't work; it detects several useful commands for many workloads, but
   then gets a `MI_BATCH_BUFFER_START` call that causes it to jump to where more commands
   *should* reside, but those locations are all zeroes, halting it in its tracks.
   
3. `profiler/bpf/gem_collector.bpf.c`: This is the BPF program that does most of the
   heavy lifting on the i915 side. It attaches to everything that it can (largely consisting
   of `mmap`, `munmap`, `vm_bind`, and `execbuffer` calls), gathers relevant information
   from each (`cpu_addr`, `gpu_addr`, etc.), and sends it all to userspace via
   a single ringbuffer.
   
Issues
========

1. When running `scripts/test_benchdnn.sh`, we intermittently (sometimes it takes
   100 runs to reproduce) miss `vm_bind` calls in the BPF program itself; that is,
   even if we're running `bpftrace` at the same time and see that `vm_bind` call,
   our profiler *doesn't* see it, and we therefore drop every EU stall (since
   we don't know the GPU address of the buffer object that they relate to).
   
2. When running `scripts/test_benchdnn.sh`, we'll always see a few (1% or less) EU stalls
   that are happening at addresses that we have no notion of; for example, `0xfff0`.
   I currently have no theories as to why that could be.
   
3. We will, VERY intermittently, miss the `munmap` tracepoint that allows us to copy
   GEN binaries in the BPF program. This results in the final printouts being
   nonsensical or having a plethora of `illegal` instructions when decoding. This is
   likely related to #1.
   
4. When running `scripts/test_llama.sh`, we *always* miss several buffer objects
   that should have been bound into the VM, but aren't. We get quite a lot of
   EU stalls from `0x8100ff760000` to `0x8100ff770000`, but don't see a `vm_bind`
   for that block of size `0x10000`. bpftrace nor our profiler sees it.
   
   This can be mitigated by setting the environment variable `MakeEachAllocationResident=2`,
   which tells the Compute Runtime library to explicitly bind all buffer objects.
   
5. With `scripts/test_llama.sh`, we often get "illegal" instructions when disassembling the GEN
   binaries that we collected during the run.
   
6. We don't get CPU-side symbols for `scripts/test_llama.sh`.
