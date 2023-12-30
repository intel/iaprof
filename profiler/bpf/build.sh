#!/bin/bash
# WARNING: ONLY `-O2` OPTIMIZATIONS ARE SUPPORTED
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

BPFTOOL=${BPFTOOL:-bpftool}
CLANG=${CLANG:-clang}
BPF_CFLAGS=${BPF_CFLAGS:--O2}
LLVM_STRIP=${LLVM_STRIP:-llvm-strip}

# Get this kernel's `vmlinux.h`
echo "  Gathering BTF information for this kernel..."
${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${DIR}/vmlinux.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    Your current kernel does not have BTF information."
  echo "    This is required for running eBPF programs."
  exit 1
fi

# Also get i915's BTF information
${BPFTOOL} btf dump file /sys/kernel/btf/i915 format c > ${DIR}/i915.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    I can't find the BTF information for i915! Trying to"
  echo "    modprobe i915..."
  sudo modprobe i915
fi
${BPFTOOL} btf dump file /sys/kernel/btf/i915 format c > ${DIR}/i915.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    I can't find the BTF information for i915! Bailing out."
  exit 1
fi

${BPFTOOL} btf dump file /sys/kernel/btf/drm format c > ${DIR}/drm.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    I can't find the BTF information for drm! Aborting."
  exit 1
fi

# Compile the BPF object code
echo "  Compiling the BPF program..."
${CLANG} ${BPF_CFLAGS} -target bpf -D__TARGET_ARCH_x86 -g \
  -I${DIR} -I${PREFIX}/include -c ${DIR}/gem_collector.bpf.c -o ${DIR}/gem_collector.bpf.o

# Strip the object file (for a smaller filesize)
echo "  Stripping the object file..."
${LLVM_STRIP} -g ${DIR}/gem_collector.bpf.o

# Compile the object file into the skeleton header
echo "  Generating the BPF skeleton header..."
${BPFTOOL} gen skeleton ${DIR}/gem_collector.bpf.o > ${DIR}/gem_collector.skel.h
