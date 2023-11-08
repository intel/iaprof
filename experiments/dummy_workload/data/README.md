# miniBUDE Benchmark Data

This directory contains input data and reference output.
Each sub-directory is a self-contained test case.
The test case can be selected using the `--deck /path/to/bm` parameter for the `bude` executables.

## Benchmarks included

* `bm1` is a short benchmark (~100 ms/iteration on a 64-core ThunderX2 node) based on a small ligand (26 atoms)
* `bm2` is a long benchmark (~25 s/iteration on a 64-core ThunderX2 node) based on a big ligand (2672 atoms)

## Additional benchmarks

More benchmarks can be generated from BUDE protein/forcefield files.
See [the benchmark generation script](/makedeck) for more details.
