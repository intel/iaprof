#!/bin/bash
# WARNING: ONLY `-O2` OPTIMIZATIONS ARE SUPPORTED
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

BPFTOOL=${BPFTOOL:-bpftool}
CLANG=${CLANG:-clang}
BPF_CFLAGS=${BPF_CFLAGS:--O2}
LLVM_STRIP=${LLVM_STRIP:-llvm-strip}

BPF_CFLAGS+=" -DDEBUG"

GENERATED_HEADERS="${DIR}/generated_headers"
mkdir -p ${GENERATED_HEADERS}

# Get this kernel's `vmlinux.h`
echo "  Gathering BTF information for this kernel..."
${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${GENERATED_HEADERS}/vmlinux.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    Your current kernel does not have BTF information."
  echo "    This is required for running eBPF programs."
  exit 1
fi

# Find i915 BTF information
FOUND_I915_BTF=""
KERNEL_VERSION=$(uname -r)
LOADED_I915_MODULE=$(modinfo i915 | grep filename | awk '{print $2}')
DKMS_I915_MODULE="/lib/modules/${KERNEL_VERSION}/updates/dkms/i915.ko"
SYS_I915_BTF="/sys/kernel/btf/i915"

if [ ! -z "${LOADED_I915_MODULE}" ] && [ -f "${LOADED_I915_MODULE}" ]; then
  FOUND_I915_BTF="${LOADED_I915_MODULE}"
fi
if [ -z "${FOUND_I915_BTF}" ] && [ -f "${DKMS_I915_MODULE}" ]; then
  FOUND_I915_BTF="${DKMS_I915_MODULE}"
fi
if [ -z "${FOUND_I915_BTF}" ] && [ -f "${SYS_I915_BTF}" ]; then
  FOUND_I915_BTF="${DKMS_I915_MODULE}"
fi
if [ -z "${FOUND_I915_BTF}" ]; then
  echo "    Can't find BTF information for i915. Aborting."
  exit 1
fi

# Also get i915's BTF information
${BPFTOOL} btf dump file ${FOUND_I915_BTF} format c --base-btf /sys/kernel/btf/vmlinux > ${GENERATED_HEADERS}/i915.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    Failed to run bpftool on ${FOUND_I915_BTF}! Aborting."
  exit 1
fi

${BPFTOOL} btf dump file /sys/kernel/btf/drm format c > ${GENERATED_HEADERS}/drm.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    I can't find the BTF information for drm! Aborting."
  exit 1
fi

# Compile the BPF object code
echo "  Compiling the BPF program..."
${CLANG} ${EXTRA_CFLAGS} ${BPF_CFLAGS} -target bpf -D__TARGET_ARCH_x86 -g \
  -Wno-pass-failed \
  -I${GENERATED_HEADERS} -I${DIR} -I${DIR}/../../.. -I${PREFIX}/include -c ${DIR}/main.bpf.c -o ${DIR}/main.bpf.o

# Strip the object file (for a smaller filesize)
echo "  Stripping the object file..."
${LLVM_STRIP} -g ${DIR}/main.bpf.o

# Compile the object file into the skeleton header
echo "  Generating the BPF skeleton header..."
${BPFTOOL} gen skeleton ${DIR}/main.bpf.o > ${DIR}/main.skel.h
