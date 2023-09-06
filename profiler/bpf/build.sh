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
${BPFTOOL} btf dump file /sys/kernel/btf/i915 format c > ${DIR}/i915.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    Your current kernel does not have BTF information."
  echo "    This is required for running eBPF programs."
  echo "    For the purposes of compiling eBPF, though, we'll just use"
  echo "    a pre-generated vmlinux.h."
  cp ${DIR}/../vmlinux_505.h ${DIR}/vmlinux.h
fi

# Compile the BPF object code
echo "  Compiling the BPF program..."
${CLANG} ${BPF_CFLAGS} -target bpf -D__TARGET_ARCH_x86 -g \
  -I${DIR} -I${PREFIX}/include -I/usr/include/libdrm -c ${DIR}/kernel_writes.bpf.c -o ${DIR}/kernel_writes.bpf.o

# Strip the object file (for a smaller filesize)
echo "  Stripping the object file..."
${LLVM_STRIP} -g ${DIR}/kernel_writes.bpf.o

# Compile the object file into the skeleton header
echo "  Generating the BPF skeleton header..."
${BPFTOOL} gen skeleton ${DIR}/kernel_writes.bpf.o > ${DIR}/kernel_writes.skel.h
