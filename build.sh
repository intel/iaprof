#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

KERN="${KERN:-${BASE_DIR}/reference/drivers.gpu.i915.drm-intel}"
KERN_HEADERS="${KERN_HEADERS:-${BASE_DIR}/reference/kernel_headers}"

CLANG=${CLANG:-clang}
CC=${CC:-${CLANG}}
LDFLAGS=${LDFLAGS:-}

# Commandline arguments
DO_DEPS=false
while getopts d flag
do
  case "${flag}" in
    d) DO_DEPS=true;;
  esac
done


# Build the dependencies
DEPS_DIR="${BASE_DIR}/deps"
PREFIX="${DEPS_DIR}/install"

if [ "${DO_DEPS}" = true ]; then
  cd ${DEPS_DIR}
  git submodule init
  git submodule update
  source build.sh
else
  echo "WARNING: Not building dependencies. Pass '-d' to build them."
fi

# Produce the userspace headers from the kernel
cd ${KERN}
mkdir -p ${KERN_HEADERS}
make headers_install ARCH=x86_64 INSTALL_HDR_PATH=${KERN_HEADERS}

# Build common code
COMMON_DIR="${BASE_DIR}/common"
echo "Building ${COMMON_DIR}..."
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include \
  ${COMMON_DIR}/drm_helper.c -o ${COMMON_DIR}/drm_helper.o
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include \
  ${COMMON_DIR}/trace_helpers.c -o ${COMMON_DIR}/trace_helpers.o
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include \
  ${COMMON_DIR}/uprobe_helpers.c -o ${COMMON_DIR}/uprobe_helpers.o
echo ""
  
# Create the bin directory
mkdir -p ${BASE_DIR}/bin

PROFILER_DIR="${BASE_DIR}/profiler"
echo "Building ${PROFILER_DIR}..."
cd ${PROFILER_DIR}/bpf
source build.sh
cd ${PROFILER_DIR}

# pvc_profile.c
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/pvc_profile.c \
  -o ${PROFILER_DIR}/pvc_profile.o
  
# gem_collector.c
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/gem_collector.c \
  -o ${PROFILER_DIR}/gem_collector.o
  
# eustall_collector.c
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/eustall_collector.c \
  -o ${PROFILER_DIR}/eustall_collector.o
  
# shader_decoder.c
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/shader_decoder.c \
  -o ${PROFILER_DIR}/shader_decoder.o
  
# printer.c
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/printer.c \
  -o ${PROFILER_DIR}/printer.o
  
# stack_printer.c
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/stack_printer.c \
  -o ${PROFILER_DIR}/stack_printer.o
  
# utils.c
${CC} -gdwarf-4 -c \
  -I${KERN_HEADERS}/include -I${COMMON_DIR} -I${PREFIX}/include \
  ${COMMON_DIR}/utils/utils.c \
  -o ${COMMON_DIR}/utils/utils.o
  
${CC} ${LDFLAGS} \
  ${COMMON_DIR}/drm_helper.o \
  ${COMMON_DIR}/trace_helpers.o \
  ${COMMON_DIR}/uprobe_helpers.o \
  \
  ${PROFILER_DIR}/pvc_profile.o \
  ${PROFILER_DIR}/gem_collector.o \
  ${PROFILER_DIR}/eustall_collector.o \
  ${PROFILER_DIR}/shader_decoder.o \
  \
  ${PROFILER_DIR}/printer.o \
  ${PROFILER_DIR}/stack_printer.o \
  \
  ${COMMON_DIR}/utils/utils.o \
  \
  -gdwarf-4 \
  -o ${BASE_DIR}/bin/pvc_profile \
  -L${PREFIX}/lib -liga64 \
  -lpthread \
  ${PREFIX}/lib/libbpf.a \
  -lelf -lz
echo ""

# Compile the benchmark
# BENCHMARK_DIR="${BASE_DIR}/benchmark"
# echo "Building ${BENCHMARK_DIR}..."
# ${CC} -g -c \
#   -I${KERN_HEADERS}/include -I${COMMON_DIR} \
#   ${BENCHMARK_DIR}/gpgpu_fill.c \
#   -o ${BENCHMARK_DIR}/gpgpu_fill.o
# ${CC} ${LDFLAGS} \
#   ${BENCHMARK_DIR}/gpgpu_fill.o \
#   ${COMMON_DIR}/drm_helper.o \
#   -o ${BASE_DIR}/bin/gpgpu_fill
# echo ""
  
# Build the dummy workload
# DUMMY_WORKLOAD_DIR="${BASE_DIR}/experiments/dummy_workload"
# echo "Building ${DUMMY_WORKLOAD_DIR}..."
# cd ${DUMMY_WORKLOAD_DIR}
# make
# [ ! -d "${DUMMY_WORKLOAD_DIR}/data" ] && echo "${DUMMY_WORKLOAD_DIR}/data does NOT exist! Did you use 'git lfs'?"
