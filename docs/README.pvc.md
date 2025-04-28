#######
# Build
#######


## i915 Kernel Driver BTF

You'll need BTF type information for the i915 driver, usually found
in `/sys/kernel/btf/i915`.

If you're on the Intel® Tiber™ AI Cloud, use the following steps
to create this file:

```
# Get BTF build-time dependencies
apt update
apt install cmake dwarves pahole clang

# Extract kernel so BTF info is accessible for the i915 driver build
/usr/lib/modules/$(uname -r)/build/scripts/extract-vmlinux \
  /boot/vmlinuz-$(uname -r) > /lib/modules/$(uname -r)/build/vmlinux

# Ensure the APT repository exists for the i915 driver on Ubuntu 22.04
cat > /etc/apt/sources.list.d/intel-gpu-jammy.list <<"EOF"
deb [arch=amd64 signed-by=/usr/share/keyrings/intel-graphics.gpg] https://repositories.intel.com/gpu/ubuntu jammy/lts/2350 unified
EOF

# Remove and install i915 driver to force DKMS re-installation
apt update
apt remove intel-i915-dkms
apt install -y intel-i915-dkms

# Reboot the system to load the new driver that should now have BTF info
reboot
```


#####
# Run
#####


## Kernel Driver

Your kernel driver (whether i915 or xe) 

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
information in the profiler output.


##########################################
# Workload/Framework-specific Requirements
##########################################


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
