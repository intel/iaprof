# miniBUDE OpenCL

This is a GPU implementation of miniBUDE using OpenCL.

## Building

Select the compiler you want to use and pass it to Make:

```
make COMPILER=GNU
```

The supported compilers names are: `ARM`, `CLANG`, `CRAY`, `GNU`, `INTEL`.

### Target Architecture

By default, the native architecture is targetted, but this can be changed by setting the `ARCH` parameter to the name of the target processor.
For example, the following are both valid:

```
make COMPILER=GNU ARCH=thunderx2t99
make COMPILER=GNU ARCH=skylake-avx512
```

### Block Sizes

This implementation includes a tunable block size similar to OpenCL workgroups.
The default value is `64`, which is suitable for 512-bit vectors, e.g. in Skylake or A64FX, but higher values may sometimes be beneficial.
For 128-bit vectors, `16` is a good choice.

This parameter can be set using the `WGSIZE` parameter, as follows:

```
make COMPILER=GNU ARCH=thunderx2t99 WGSIZE=16
```

## Running

The `-n` and `-i` parameters are available, along with several OpenCL-specific options for device selection and run-time tuning.
Run `bude -h` for a list of all available flags.
