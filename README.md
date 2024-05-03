Intel Accelerator Profiler (iaprof)
=====================

Introduction
------------

This is a profiler which is composed of two parts:
1. A BPF program, and accompanying userspace one, that traces i915 memory allocation
   routines to keep track of buffers being allocated and copied to the GPU.
2. An EU (Execution Unit) stall sampler, which collects stalls and their reasons on
   Intel Ponte Vecchio cards.
   
It then associates the stalls with the buffers that caused them, systemwide, for the
purposes of further processing into a visualization.

Building
--------

Run `./build.sh -d` to build the project along with its dependencies. The resulting
executable will be called `iaprof`.

Usage
-----

With no commandline arguments, the profiler will simply print output which can be
fed directly into Brendan Gregg's `flamegraph.pl` (https://github.com/brendangregg/FlameGraph),
but if you want more insight into GPU-related events happening on your system, you can
pass `--debug` to print all events in a tabular format.
