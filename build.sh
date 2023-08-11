#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

BENCH_DIR="${BASE_DIR}/benchmark"
KERN="${KERN:-${BASE_DIR}/reference/drivers.gpu.i915.drm-intel}"
KERN_HEADERS="${KERN_HEADERS:-${BASE_DIR}/reference/kernel_headers}"

CC=${CC:-gcc}
LDFLAGS=${LDFLAGS:-}

# if [ -f /usr/lib/x86_64-linux-gnu/libdrm.so ]; then
#   LDFLAGS="${LDFLAGS} -L/usr/lib/x86_64-linux-gnu"
# fi

# Produce the userspace headers from the kernel
cd ${KERN}
mkdir -p ${KERN_HEADERS}
make headers_install ARCH=x86_64 INSTALL_HDR_PATH=${KERN_HEADERS}

# Compile the profiler
gcc -g -c -I${KERN_HEADERS}/include ${BASE_DIR}/drm_helper.c -o drm_helper.o
gcc -g -c -I${KERN_HEADERS}/include ${BASE_DIR}/pvc_profile.c -o pvc_profile.o
gcc ${LDFLAGS} ${BASE_DIR}/pvc_profile.o ${BASE_DIR}/drm_helper.o -lpthread -o ${BASE_DIR}/pvc_profile

# Compile the benchmark
gcc -g -c -I${KERN_HEADERS}/include -I${BASE_DIR} ${BENCH_DIR}/gpgpu_fill.c -o gpgpu_fill.o
gcc ${LDFLAGS} ${BENCH_DIR}/gpgpu_fill.o ${BENCH_DIR}/drm_helper.o -ldrm -o ${BENCH_DIR}/gpgpu_fill
