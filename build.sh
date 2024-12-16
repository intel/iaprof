#!/bin/bash

set -eu

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CLANG=${CLANG:-clang}
CLANGPP=${CLANGPP:-clang++}
LLVM_CONFIG=${LLVM_CONFIG:-llvm-config}
CC=${CC:-${CLANG}}
CXX=${CXX:-${CLANGPP}}
LDFLAGS=${LDFLAGS:-}
# CSAN="-fsanitize=address"
# LSAN="-fsanitize=address -static-libsan"
OPT="-O3"
CFLAGS="${CFLAGS:-} ${OPT} ${CSAN:-} -gdwarf-4 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -Wall -Werror -Wno-unused-function"
CFLAGS+=" -DDEBUG"
# EXTRA_CFLAGS="-DSLOW_MODE"
LDFLAGS="${LSAN:-}"
LDFLAGS+=" $(${LLVM_CONFIG} --ldflags --libs demangle)"

DEPS_DIR="${BASE_DIR}/deps"
PREFIX="${DEPS_DIR}/install"
IGA_INCLUDE_DIR="${IGA_INCLUDE_DIR:-${DEPS_DIR}/install/include}"
LOCAL_DEPS=${LOCAL_DEPS:-"${PREFIX}/lib/libbpf.a ${PREFIX}/lib/libiga64.a"}


# Get the git commit hash
cd ${BASE_DIR}
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
GIT_COMMIT_HASH=$(git rev-parse HEAD)

SRC_DIR="${BASE_DIR}/src"
COMMON_FLAGS="${CFLAGS} -I${SRC_DIR} ${EXTRA_CFLAGS:-}"

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


####################
#   I915 HELPERS    #
####################
I915_HELPERS_DIR="${SRC_DIR}/i915_helpers"
echo "Building ${I915_HELPERS_DIR}..."

I915_DKMS_SRC_DIR=$(find /usr/src -maxdepth 1 -name "intel-i915-dkms*" | tail -n 1)

cat "${I915_DKMS_SRC_DIR}/i915-include/uapi/drm/i915_drm_prelim.h" |
    sed 's/#include "i915_drm.h"/#include <drm\/i915_drm.h>/' |
    sed '/define __I915_PMU_OTHER/i#ifndef __I915_PMU_OTHER' |
    sed '/define __I915_PMU_OTHER/a#endif' > "${I915_HELPERS_DIR}/i915_drm_prelim.h"

${CC} ${COMMON_FLAGS} -c \
  -I${I915_HELPERS_DIR} \
  ${I915_HELPERS_DIR}/i915_helpers.c \
  -o ${I915_HELPERS_DIR}/i915_helpers.o


####################
#   DRM HELPERS    #
####################
DRM_HELPERS_DIR="${SRC_DIR}/drm_helpers"
echo "Building ${DRM_HELPERS_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  -I${I915_HELPERS_DIR} \
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
${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  ${BPF_HELPERS_DIR}/bpf_map_helpers.c \
  -o ${BPF_HELPERS_DIR}/bpf_map_helpers.o

####################
#     STORES       #
####################
STORES_DIR="${SRC_DIR}/stores"
echo "Building ${STORES_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
  -I${IGA_INCLUDE_DIR} \
  ${STORES_DIR}/buffer_profile.c \
  -o ${STORES_DIR}/buffer_profile.o

${CC} ${COMMON_FLAGS} -c \
  -I${I915_HELPERS_DIR} \
  -I${PREFIX}/include \
  -I${IGA_INCLUDE_DIR} \
  ${STORES_DIR}/proto_flame.c \
  -o ${STORES_DIR}/proto_flame.o

####################
#   COLLECTORS     #
####################
COLLECTORS_DIR="${SRC_DIR}/collectors"
echo "Building ${COLLECTORS_DIR}..."

cd ${COLLECTORS_DIR}/bpf_i915/bpf
source build.sh
cd ${BASE_DIR}

${CC} ${COMMON_FLAGS} -c \
  -I${I915_HELPERS_DIR} \
  -I${PREFIX}/include \
  -std=c2x \
  ${COLLECTORS_DIR}/bpf_i915/bpf_i915_collector.c \
  -o ${COLLECTORS_DIR}/bpf_i915/bpf_i915_collector.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
  ${COLLECTORS_DIR}/debug_i915/debug_i915_collector.c \
  -o ${COLLECTORS_DIR}/debug_i915/debug_i915_collector.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
  ${COLLECTORS_DIR}/eustall/eustall_collector.c \
  -o ${COLLECTORS_DIR}/eustall/eustall_collector.o

####################
#    PRINTERS      #
####################
PRINTERS_DIR="${SRC_DIR}/printers"

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
  ${PRINTERS_DIR}/printer.c \
  -o ${PRINTERS_DIR}/printer.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
  ${PRINTERS_DIR}/flamegraph/flamegraph_printer.c \
  -o ${PRINTERS_DIR}/flamegraph/flamegraph_printer.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
  ${PRINTERS_DIR}/debug/debug_printer.c \
  -o ${PRINTERS_DIR}/debug/debug_printer.o

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
  ${PRINTERS_DIR}/stack/stack_printer.c \
  -o ${PRINTERS_DIR}/stack/stack_printer.o

####################
#     UTILS        #
####################
UTILS_DIR="${SRC_DIR}/utils"
echo "Building ${UTILS_DIR}..."

${CC} ${COMMON_FLAGS} -c \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
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
  -I${I915_HELPERS_DIR} \
  -I${IGA_INCLUDE_DIR} \
  ${GPU_PARSERS_DIR}/shader_decoder.c \
  -o ${GPU_PARSERS_DIR}/shader_decoder.o

####################
#     IAPROF       #
####################

${CC} ${COMMON_FLAGS} -c \
  -DGIT_COMMIT_HASH="\"${GIT_COMMIT_HASH}\"" \
  -I${PREFIX}/include \
  -I${I915_HELPERS_DIR} \
  ${SRC_DIR}/iaprof.c \
  -o ${SRC_DIR}/iaprof.o || exit $?

${CXX} ${LDFLAGS} \
  ${DRM_HELPERS_DIR}/drm_helpers.o \
  ${I915_HELPERS_DIR}/i915_helpers.o \
  \
  ${BPF_HELPERS_DIR}/trace_helpers.o \
  ${BPF_HELPERS_DIR}/uprobe_helpers.o \
  ${BPF_HELPERS_DIR}/bpf_map_helpers.o \
  \
  ${STORES_DIR}/buffer_profile.o \
  ${STORES_DIR}/proto_flame.o \
  \
  ${COLLECTORS_DIR}/bpf_i915/bpf_i915_collector.o \
  ${COLLECTORS_DIR}/eustall/eustall_collector.o \
  ${COLLECTORS_DIR}/debug_i915/debug_i915_collector.o \
  \
  ${PRINTERS_DIR}/printer.o \
  ${PRINTERS_DIR}/stack/stack_printer.o \
  ${PRINTERS_DIR}/flamegraph/flamegraph_printer.o \
  ${PRINTERS_DIR}/debug/debug_printer.o \
  \
  ${UTILS_DIR}/utils.o \
  ${UTILS_DIR}/array.o \
  ${UTILS_DIR}/demangle.o \
  \
  ${GPU_PARSERS_DIR}/shader_decoder.o \
  \
  ${SRC_DIR}/iaprof.o \
  \
  ${COMMON_FLAGS} \
  -o ${BASE_DIR}/iaprof \
  -L${PREFIX}/lib \
  -lpthread \
  ${PREFIX}/lib/libbpf.a \
  -lz \
  -lstdc++ \
  ${PREFIX}/lib/libdw.a \
  ${PREFIX}/lib/libelf.a \
  ${PREFIX}/lib/libiga64.a || exit $?
echo ""
