#!/bin/bash

set -eu

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# User choices
CLANG=${CLANG:-clang}
CLANGPP=${CLANGPP:-clang++}
LLVM_CONFIG=${LLVM_CONFIG:-llvm-config}
CC=${CC:-${CLANG}}
CXX=${CXX:-${CLANGPP}}
LDFLAGS=${LDFLAGS:-}
# OPT="-O3"
OPT="-O0"
CFLAGS="${CFLAGS:-} ${OPT} ${CSAN:-} -g -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -Wall -Werror -Wno-unused-function"
FUZZ="no"
if [[ "${FUZZ}" == "yes" ]]; then
  CFLAGS+="-fsanitize=fuzzer-no-link,address -fprofile-instr-generate -fcoverage-mapping"
  LDFLAGS+="-fsanitize=fuzzer,address -fprofile-instr-generate -fcoverage-mapping"
fi
CFLAGS+=" -DDEBUG"
LDFLAGS="${LSAN:-}"

BPFTOOL=${BPFTOOL:-bpftool}

export GPU_PLATFORM="pvc"
# export GPU_PLATFORM="xe2"

export GPU_DRIVER="i915"
# export GPU_DRIVER="xe"

export KERNEL_LAUNCH_COLLECTOR="driver"
# export KERNEL_LAUNCH_COLLECTOR="uprobe"

CONFIG_CFLAGS=""
CONFIG_CFLAGS+=" -DGPU_PLATFORM_pvc=1"
CONFIG_CFLAGS+=" -DGPU_PLATFORM_xe=2"
CONFIG_CFLAGS+=" -DGPU_PLATFORM=GPU_PLATFORM_${GPU_PLATFORM}"
CONFIG_CFLAGS+=" -DGPU_DRIVER_i915=1"
CONFIG_CFLAGS+=" -DGPU_DRIVER_xe=2"
CONFIG_CFLAGS+=" -DGPU_DRIVER=GPU_DRIVER_${GPU_DRIVER}"
CONFIG_CFLAGS+=" -DCOLLECTOR_driver=1"
CONFIG_CFLAGS+=" -DCOLLECTOR_uprobe=2"
CONFIG_CFLAGS+=" -DKERNEL_LAUNCH_COLLECTOR=COLLECTOR_${KERNEL_LAUNCH_COLLECTOR}"
export CONFIG_CFLAGS

CFLAGS+="${CONFIG_CFLAGS}"
LDFLAGS+=" $(${LLVM_CONFIG} --ldflags --libs demangle)"

DEPS_DIR="${BASE_DIR}/deps"
PREFIX="${DEPS_DIR}/install"
IGA_INCLUDE_DIR="${IGA_INCLUDE_DIR:-${DEPS_DIR}/install/include}"
LOCAL_DEPS=${LOCAL_DEPS:-"${PREFIX}/lib/libbpf.a ${PREFIX}/lib/libiga64.a"}

# Find the proper kernel headers and copy them into the deps/ directory.
# Add those to CFLAGS. Users can place headers in there as a workaround.
if [ -d "/lib/modules/$(uname -r)/build/include/uapi" ]; then
  KERNEL_HEADERS="${KERNEL_HEADERS:-/lib/modules/$(uname -r)/build/include/uapi/}"
  mkdir -p ${DEPS_DIR}/kernel_headers/uapi
  cp -r ${KERNEL_HEADERS}/* ${DEPS_DIR}/kernel_headers/uapi/
fi
CFLAGS+=" -I${DEPS_DIR}/kernel_headers"

# Get the git commit hash
cd ${BASE_DIR}
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
GIT_COMMIT_HASH=$(git rev-parse HEAD)

SRC_DIR="${BASE_DIR}/src"
COMMON_FLAGS="${CFLAGS} -I${SRC_DIR}"

# Commandline arguments
DO_DEPS=false
while getopts d flag
do
  case "${flag}" in
    d) DO_DEPS=true;;
  esac
done


if [ "${DO_DEPS}" = true ]; then
  # Build the dependencies
  cd ${DEPS_DIR}
  source build.sh
else
  echo "WARNING: Not building dependencies. Pass '-d' to build them."
fi

# Check to make sure the dependencies are there
IFS=' ' read -ra ITEMS <<< "$LOCAL_DEPS"
for dep in "${ITEMS[@]}"; do
#done
#for dep in ${LOCAL_DEPS[@]}; do
  if [ ! -f "${dep}" ]; then
    echo ""
    echo "ERROR: Dependency ${dep} does not exist. Either:"
    echo "  1. Pass '-d' to this script to build local dependencies, or"
    echo "  2. Check the above output for dependency build errors."
    exit 1
  fi
  LDFLAGS="${LDFLAGS} ${dep}"
done

# If not already in the PATH, use our locally-built bpftool
# by setting the PATH. If the user specifies BPFTOOL, that
# path will still be used regardless.
if ! command -v ${BPFTOOL} &> /dev/null; then
  export PATH="${PREFIX}/bin:${PATH}"
  echo "  No system bpftool found! Setting the PATH to use the bpftool we just built."
else
  if ! ${BPFTOOL} --version &> /dev/null; then
    echo " Your system bpftool appears to be broken! Setting the PATH to use our local bpftool."
    export PATH="${PREFIX}/bin:${PATH}"
  else
    echo "  Using system bpftool."
  fi
fi

####################
#  DRIVER HELPERS  #
####################
DRIVER_HELPERS_DIR="${SRC_DIR}/driver_helpers"
echo "Building ${DRIVER_HELPERS_DIR}..."
if [[ ${GPU_DRIVER} == "i915" ]]; then

        # If applicable, find the i915 prelim headers from the DKMS version
        # of i915. Copy them locally, fix them up, and include them where necessary.
        I915_DKMS_SRC_DIR=$(find /usr/src -maxdepth 1 -name "intel-i915-dkms*" | tail -n 1)
        if [ ! -z ${I915_DKMS_SRC_DIR} ]; then
          mkdir -p ${DRIVER_HELPERS_DIR}/drm
          cat "${I915_DKMS_SRC_DIR}/i915-include/uapi/drm/i915_drm_prelim.h" |
            sed 's/#include "i915_drm.h"/#include <drm\/i915_drm.h>/' |
            sed '/define __I915_PMU_OTHER/i#ifndef __I915_PMU_OTHER' |
            sed '/define __I915_PMU_OTHER/a#endif' > "${DRIVER_HELPERS_DIR}/drm/i915_drm_prelim.h"
          COMMON_FLAGS+=" -I${DRIVER_HELPERS_DIR}"
        else
          echo " WARNING: Couldn't find the intel-i915-dkms directory in /usr/src."
          echo " We use this to get a copy of i915_drm_prelim.h. Proceeding without."
        fi

        # Build the i915 helpers
        ${CC} ${COMMON_FLAGS} -c \
          ${DRIVER_HELPERS_DIR}/i915_helpers.c \
          -o ${DRIVER_HELPERS_DIR}/i915_helpers.o

        DRIVER_HELPER_FLAGS="${DRIVER_HELPERS_DIR}/i915_helpers.o"
elif [[ ${GPU_DRIVER} == "xe" ]]; then

        ${CC} ${COMMON_FLAGS} -c \
          ${DRIVER_HELPERS_DIR}/xe_helpers.c \
          -o ${DRIVER_HELPERS_DIR}/xe_helpers.o

        DRIVER_HELPER_FLAGS="${DRIVER_HELPERS_DIR}/xe_helpers.o"
fi

####################
#   DRM HELPERS    #
####################
DRM_HELPERS_DIR="${SRC_DIR}/drm_helpers"
echo "Building ${DRM_HELPERS_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  ${DRM_HELPERS_DIR}/drm_helpers.c \
  -o ${DRM_HELPERS_DIR}/drm_helpers.o

####################
#   BPF HELPERS    #
####################
BPF_HELPERS_DIR="${SRC_DIR}/bpf_helpers"
echo "Building ${BPF_HELPERS_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${IGA_INCLUDE_DIR} \
  ${BPF_HELPERS_DIR}/trace_helpers.c \
  -o ${BPF_HELPERS_DIR}/trace_helpers.o
${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${BPF_HELPERS_DIR}/uprobe_helpers.c \
  -o ${BPF_HELPERS_DIR}/uprobe_helpers.o

####################
#     STORES       #
####################
STORES_DIR="${SRC_DIR}/stores"
echo "Building ${STORES_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${IGA_INCLUDE_DIR} \
  ${STORES_DIR}/gpu_kernel.c \
  -o ${STORES_DIR}/gpu_kernel.o

####################
#   COLLECTORS     #
####################
COLLECTORS_DIR="${SRC_DIR}/collectors"
echo "Building ${COLLECTORS_DIR}..."

cd ${COLLECTORS_DIR}/bpf/bpf
source build.sh
cd ${BASE_DIR}

IAPROF_COLLECTORS=""

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -std=c2x \
  ${COLLECTORS_DIR}/bpf/bpf_collector.c \
  -o ${COLLECTORS_DIR}/bpf/bpf_collector.o
IAPROF_COLLECTORS+="${COLLECTORS_DIR}/bpf/bpf_collector.o "

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${COLLECTORS_DIR}/debug/debug_collector.c \
  -o ${COLLECTORS_DIR}/debug/debug_collector.o
IAPROF_COLLECTORS+="${COLLECTORS_DIR}/debug/debug_collector.o "

${CC} ${COMMON_FLAGS} -c \
      -I${PREFIX}/include \
      ${COLLECTORS_DIR}/eustall/eustall_collector.c \
      -o ${COLLECTORS_DIR}/eustall/eustall_collector.o
IAPROF_COLLECTORS+="${COLLECTORS_DIR}/eustall/eustall_collector.o "

####################
#    PRINTERS      #
####################
PRINTERS_DIR="${SRC_DIR}/printers"

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${PRINTERS_DIR}/debug/debug_printer.c \
  -o ${PRINTERS_DIR}/debug/debug_printer.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${PRINTERS_DIR}/stack/stack_printer.c \
  -o ${PRINTERS_DIR}/stack/stack_printer.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${PRINTERS_DIR}/interval/interval_printer.c \
  -o ${PRINTERS_DIR}/interval/interval_printer.o

####################
#     UTILS        #
####################
UTILS_DIR="${SRC_DIR}/utils"
echo "Building ${UTILS_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${UTILS_DIR}/utils.c \
  -o ${UTILS_DIR}/utils.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${UTILS_DIR}/array.c \
  -o ${UTILS_DIR}/array.o

${CXX} ${COMMON_FLAGS} $(${LLVM_CONFIG} --cppflags) -c \
  -I${PREFIX}/include \
  ${UTILS_DIR}/demangle.cpp \
  -o ${UTILS_DIR}/demangle.o

####################
#   GPU PARSERS    #
####################
GPU_PARSERS_DIR="${SRC_DIR}/gpu_parsers"
echo "Building ${GPU_PARSERS_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${IGA_INCLUDE_DIR} \
  ${GPU_PARSERS_DIR}/shader_decoder.c \
  -o ${GPU_PARSERS_DIR}/shader_decoder.o

####################
#     COMMANDS     #
####################
COMMANDS_DIR="${SRC_DIR}/commands"
echo "Building ${COMMANDS_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -DGIT_COMMIT_HASH="\"${GIT_COMMIT_HASH}\"" \
  ${COMMANDS_DIR}/record.c \
  -o ${COMMANDS_DIR}/record.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -DGIT_COMMIT_HASH="\"${GIT_COMMIT_HASH}\"" \
  ${COMMANDS_DIR}/flame.c \
  -o ${COMMANDS_DIR}/flame.o
  
${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -DGIT_COMMIT_HASH="\"${GIT_COMMIT_HASH}\"" \
  ${COMMANDS_DIR}/flamescope.c \
  -o ${COMMANDS_DIR}/flamescope.o

####################
#     IAPROF       #
####################

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${SRC_DIR}/iaprof.c \
  -o ${SRC_DIR}/iaprof.o || exit $?

${CXX} ${LDFLAGS}  \
  ${SRC_DIR}/iaprof.o \
  ${DRM_HELPERS_DIR}/drm_helpers.o \
  ${DRIVER_HELPER_FLAGS} \
  \
  ${BPF_HELPERS_DIR}/trace_helpers.o \
  ${BPF_HELPERS_DIR}/uprobe_helpers.o \
  \
  ${STORES_DIR}/gpu_kernel.o \
  \
  ${IAPROF_COLLECTORS} \
  \
  ${PRINTERS_DIR}/stack/stack_printer.o \
  ${PRINTERS_DIR}/debug/debug_printer.o \
  ${PRINTERS_DIR}/interval/interval_printer.o \
  \
  ${UTILS_DIR}/utils.o \
  ${UTILS_DIR}/array.o \
  ${UTILS_DIR}/demangle.o \
  \
  ${GPU_PARSERS_DIR}/shader_decoder.o \
  \
  ${COMMANDS_DIR}/record.o \
  ${COMMANDS_DIR}/flame.o \
  ${COMMANDS_DIR}/flamescope.o \
  \
  \
  ${COMMON_FLAGS} \
  -o ${BASE_DIR}/iaprof \
  -L${PREFIX}/lib \
  -lpthread \
  ${PREFIX}/lib/libbpf.a \
  -lz \
  -lzstd \
  -lstdc++ \
  ${PREFIX}/lib/libdw.a \
  ${PREFIX}/lib/libelf.a \
  ${PREFIX}/lib/libiga64.a || exit $?
echo ""
