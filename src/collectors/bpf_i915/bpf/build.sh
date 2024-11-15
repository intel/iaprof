#!/bin/bash
# WARNING: ONLY `-O2` OPTIMIZATIONS ARE SUPPORTED
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

BPFTOOL=${BPFTOOL:-bpftool}
CLANG=${CLANG:-clang}
BPF_CFLAGS=${BPF_CFLAGS:--O2}
LLVM_STRIP=${LLVM_STRIP:-llvm-strip}

BPF_CFLAGS+=" -DDEBUG"
if [ ! -z ${IAPROF_XE_DRIVER} ]; then
        BPF_CFLAGS+=" -DXE_DRIVER"
fi

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

if [ -z ${IAPROF_XE_DRIVER} ]; then

  # Also get i915's BTF information
  ${BPFTOOL} btf dump file /sys/kernel/btf/i915 format c > ${GENERATED_HEADERS}/i915.h
  RETVAL="$?"
  if [ $RETVAL -ne 0 ]; then
    echo "    I can't find the BTF information for i915! Trying to"
    echo "    modprobe i915..."
    sudo modprobe i915
  fi
  ${BPFTOOL} btf dump file /sys/kernel/btf/i915 format c > ${GENERATED_HEADERS}/i915.h
  RETVAL="$?"
  if [ $RETVAL -ne 0 ]; then
    echo "    I can't find the BTF information for i915! Bailing out."
    exit 1
  fi
  
else

  # Also get xe's BTF information
  ${BPFTOOL} btf dump file /sys/kernel/btf/xe format c > ${GENERATED_HEADERS}/xe.h
  RETVAL="$?"
  if [ $RETVAL -ne 0 ]; then
    echo "    I can't find the BTF information for xe! Trying to"
    echo "    modprobe xe..."
    sudo modprobe xe
  fi
  ${BPFTOOL} btf dump file /sys/kernel/btf/xe format c > ${GENERATED_HEADERS}/xe.h
  RETVAL="$?"
  if [ $RETVAL -ne 0 ]; then
    echo "    I can't find the BTF information for xe! Bailing out."
    exit 1
  fi
  
fi

${BPFTOOL} btf dump file /sys/kernel/btf/drm format c > ${GENERATED_HEADERS}/drm.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    I can't find the BTF information for drm! Aborting."
  exit 1
fi

# Compile the BPF object code
echo "  Compiling the BPF program..."
${CLANG} ${EXTRA_CFLAGS} ${BPF_CFLAGS} -target bpf -D__TARGET_ARCH_x86 -g -v \
  -Wno-pass-failed \
  -I${GENERATED_HEADERS} -I${DIR} -I${DIR}/../../.. -I${PREFIX}/include -c ${DIR}/main.bpf.c -o ${DIR}/main.bpf.o

# Strip the object file (for a smaller filesize)
echo "  Stripping the object file..."
${LLVM_STRIP} -g ${DIR}/main.bpf.o

# Compile the object file into the skeleton header
echo "  Generating the BPF skeleton header..."
${BPFTOOL} gen skeleton ${DIR}/main.bpf.o > ${DIR}/main.skel.h
