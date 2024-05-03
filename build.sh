#!/bin/bash
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CLANG=${CLANG:-clang}
CC=${CC:-${CLANG}}
LDFLAGS=${LDFLAGS:-}

DEPS_DIR="${BASE_DIR}/deps"
PREFIX="${DEPS_DIR}/install"
LOCAL_DEPS=( "${PREFIX}/lib/libbpf.a" "${PREFIX}/lib/libiga64.a" )

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
for dep in ${LOCAL_DEPS[@]}; do
  if [ ! -f ${dep} ]; then
    echo ""
    echo "ERROR: Dependency ${dep} does not exist. Either:"
    echo "  1. Pass '-d' to this script to build local dependencies, or"
    echo "  2. Check the above output for dependency build errors."
    exit 1
  fi
done

# Build common code
COMMON_DIR="${BASE_DIR}/common"
echo ""
echo "Building ${COMMON_DIR}..."
${CC} -gdwarf-4 -c \
  ${COMMON_DIR}/drm_helper.c -o ${COMMON_DIR}/drm_helper.o
${CC} -gdwarf-4 -c \
  ${COMMON_DIR}/trace_helpers.c -o ${COMMON_DIR}/trace_helpers.o
${CC} -gdwarf-4 -c \
  ${COMMON_DIR}/uprobe_helpers.c -o ${COMMON_DIR}/uprobe_helpers.o
  
# Create the bin directory
mkdir -p ${BASE_DIR}/bin

PROFILER_DIR="${BASE_DIR}/profiler"
echo "Building ${PROFILER_DIR}..."
cd ${PROFILER_DIR}/bpf
source build.sh
cd ${PROFILER_DIR}

# iaprof.c
${CC} -gdwarf-4 -c \
  -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/iaprof.c \
  -o ${PROFILER_DIR}/iaprof.o
  
# event_collector.c
${CC} -gdwarf-4 -c \
  -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/event_collector.c \
  -o ${PROFILER_DIR}/event_collector.o
  
# eustall_collector.c
${CC} -gdwarf-4 -c \
  -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/eustall_collector.c \
  -o ${PROFILER_DIR}/eustall_collector.o
  
# shader_decoder.c
${CC} -gdwarf-4 -c \
  -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/shader_decoder.c \
  -o ${PROFILER_DIR}/shader_decoder.o
  
# printer.c
${CC} -gdwarf-4 -c \
  -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/printer.c \
  -o ${PROFILER_DIR}/printer.o
  
# stack_printer.c
${CC} -gdwarf-4 -c \
  -I${COMMON_DIR} -I${PREFIX}/include \
  ${PROFILER_DIR}/stack_printer.c \
  -o ${PROFILER_DIR}/stack_printer.o
  
# utils.c
${CC} -gdwarf-4 -c \
  -I${COMMON_DIR} -I${PREFIX}/include \
  ${COMMON_DIR}/utils/utils.c \
  -o ${COMMON_DIR}/utils/utils.o
  
${CC} ${LDFLAGS} \
  ${COMMON_DIR}/drm_helper.o \
  ${COMMON_DIR}/trace_helpers.o \
  ${COMMON_DIR}/uprobe_helpers.o \
  \
  ${PROFILER_DIR}/iaprof.o \
  ${PROFILER_DIR}/event_collector.o \
  ${PROFILER_DIR}/eustall_collector.o \
  ${PROFILER_DIR}/shader_decoder.o \
  \
  ${PROFILER_DIR}/printer.o \
  ${PROFILER_DIR}/stack_printer.o \
  \
  ${COMMON_DIR}/utils/utils.o \
  \
  -gdwarf-4 \
  -o ${BASE_DIR}/bin/iaprof \
  -L${PREFIX}/lib \
  -lpthread \
  ${PREFIX}/lib/libbpf.a \
  -lelf -lz \
  -lstdc++ \
  ${PREFIX}/lib/libiga64.a
echo ""
