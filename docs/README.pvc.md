# Building

## i915 Kernel Driver BTF

You'll need BTF type information for the i915 driver, usually found
in `/sys/kernel/btf/i915`.

If you're on the Intel® Tiber™ AI Cloud, use the following steps
to create this file:

```
# Get BTF build-time dependencies
sudo apt update
sudo apt install cmake dwarves pahole clang

# Extract kernel so BTF info is accessible for the i915 driver build
sudo /usr/lib/modules/$(uname -r)/build/scripts/extract-vmlinux \
  /boot/vmlinuz-$(uname -r) | sudo tee /lib/modules/$(uname -r)/build/vmlinux > /dev/null

# Remove and install i915 driver to force DKMS re-installation
sudo apt remove intel-i915-dkms
sudo apt install -y intel-i915-dkms

# Reboot the system to load the new driver that should now have BTF info
sudo reboot
```

## Use Prebuilt `iaprof` Binary Releases
Install the latest `iaprof` packages from the [Releases](https://github.com/intel/iaprof/releases?q=iaprof&expanded=true) page.
Download either a debian package or a tarball and install with one of the following commands:

Debian:

```
sudo apt install ./iaprof-<version>.deb
```

Tar:

```
# This will extract into a directory structure under /opt
sudo tar --strip-components=1 -xvf ./iaprof-<version>.tar.gz -C /
```


## (Alternatively) Build `iaprof` from Source

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

# Running

## Kernel Driver

In order for the profiler to collect symbols for GPU kernels, the
i915 driver needs to have debugging mode enabled. The `aiflamegraph.sh` script
does this for you, but if you're running `iaprof` directly, you'll need to do
this.

If you’re using the i915 driver:

```
for f in /sys/class/drm/card*/prelim_enable_eu_debug;
  do echo 1 | sudo tee "$f";
done
```

## Intel® Graphics Compute Runtime for oneAPI Level Zero and OpenCL™ Driver

The userspace Compute Runtime library (NEO) must also be configured to send
debugging information to the kernel driver. These two environment variables must
be set at runtime to enable this functionality:

```
export NEOReadDebugKeys=1
export ZET_ENABLE_PROGRAM_DEBUGGING=1
```

Standard distributions of NEO omit debug information for its built-in GPU
kernels, which will cause those kernels to lack symbol, file, and line number
information in the profiler output. Patched versions are provided in the
[release packages](https://github.com/intel/iaprof/releases?q=iaprof&expanded=true)
and can be enabled by using:

```
source /opt/intel/iaprof-graphics-stack/setvars.sh
```


# Workload/Framework-specific Requirements


## Python

Python added perf support (and consequently, frame pointer support through
trampolines) in version 3.12. This is the minimum required version of Python
that can be profiled with this tool. Additionally, the CPython interpreter
itself must be compiled with frame pointers enabled.

When running a Python workload, this environment variable must be set in order
to enable its perf support at run time:

```
export PYTHONPERFSUPPORT=1
```

## PyTorch

PyTorch workloads often use a mix of SYCL, oneDNN, and oneMKL kernels. Thus, you will need to enable frame pointers for the following components:

* PyTorch itself  
* IPEX (Intel Extension for PyTorch)  
* oneCCL and its PyTorch bindings (a dependency of IPEX)  
* The SYCL runtime  
* oneMKL  
* oneDNN

## Running `iaprof`

If using the release packages, use the following to put `iaprof` executables in your `$PATH`:
```
source /opt/intel/iaprof/setvars.sh
```

### `aiflamegraph.sh`
This helper script is provided to run `iaprof` and generate SVG flame graphs for you:
- Run the provided script, `aiflamegraph.sh` and wait for initialization (can take up to a minute in some cases) e.g.:
  
  From release package:
  ```
  sudo aiflamegraph.sh
  ```
  From source:
  ```
  sudo ./scripts/aiflamegraph.sh
  ```
- Run a GPU based workload, e.g. an example from the [oneAPI samples](https://github.com/oneapi-src/oneAPI-samples)
- Interrupt the `aiflamegraph.sh` script with `ctrl-C` at any time to stop profiling.
- Open the generated flame graph SVG file in a browser or other image viewer.

### Directly with `iaprof`
- Start the profiler and wait for initialization (can take up to a minute in some cases):
  
  From release package:
  ```
  sudo iaprof record > profile.txt
  ```
  From source:
  ```
  sudo ./iaprof record > profile.txt
  ```
- Run a GPU based workload, e.g. an example from the [oneAPI samples](https://github.com/oneapi-src/oneAPI-samples)
- Interrupt `iaprof` with `ctrl-C` at any time to stop profiling.
- Generate a flame graph of your application's GPU stalls:
  
  From release package:
  ```
  iaprof flame < profile.txt > profile.stackcollapse
  flamegraph.pl < profile.stackcollapse > profile.svg
  ```
  From source:
  ```
  ./iaprof flame < profile.txt > profile.stackcollapse
  deps/flamegraph/flamegraph.pl < profile.stackcollapse > profile.svg
  ```
  
