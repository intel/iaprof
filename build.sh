#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

KERN="${KERN:-${BASE_DIR}/reference/drivers.gpu.i915.drm-intel}"
KERN_HEADERS="${KERN_HEADERS:-${BASE_DIR}/reference/kernel_headers}"

CC=${CC:-gcc}
LDFLAGS=${LDFLAGS:-}

# Produce the userspace headers from the kernel
cd ${KERN}
mkdir -p ${KERN_HEADERS}
make headers_install ARCH=x86_64 INSTALL_HDR_PATH=${KERN_HEADERS}

# Build common code
COMMON_DIR="${BASE_DIR}/common"
echo "Building ${COMMON_DIR}..."
gcc -g -c \
  -I${KERN_HEADERS}/include \
  ${COMMON_DIR}/drm_helper.c -o ${COMMON_DIR}/drm_helper.o
echo ""
  
# Create the bin directory
mkdir -p ${BASE_DIR}/bin

# Compile the profiler
PROFILER_DIR="${BASE_DIR}/profiler"
echo "Building ${PROFILER_DIR}..."
gcc -g -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} \
  ${PROFILER_DIR}/pvc_profile.c \
  -o ${PROFILER_DIR}/pvc_profile.o
gcc ${LDFLAGS} \
  ${PROFILER_DIR}/pvc_profile.o \
  ${COMMON_DIR}/drm_helper.o \
  -o ${BASE_DIR}/bin/pvc_profile \
  -lpthread
echo ""

# Compile the benchmark
BENCHMARK_DIR="${BASE_DIR}/benchmark"
echo "Building ${BENCHMARK_DIR}..."
gcc -g -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} \
  ${BENCHMARK_DIR}/gpgpu_fill.c \
  -o ${BENCHMARK_DIR}/gpgpu_fill.o
gcc ${LDFLAGS} \
  ${BENCHMARK_DIR}/gpgpu_fill.o \
  ${COMMON_DIR}/drm_helper.o \
  -o ${BASE_DIR}/bin/gpgpu_fill
echo ""
  
# Build the dummy workload
DUMMY_WORKLOAD_DIR="${BASE_DIR}/experiments/dummy_workload"
echo "Building ${DUMMY_WORKLOAD_DIR}..."
cd ${DUMMY_WORKLOAD_DIR}
make
[ ! -d "${DUMMY_WORKLOAD_DIR}/data" ] && echo "${DUMMY_WORKLOAD_DIR}/data does NOT exist! Did you use 'git lfs'?"
