#!/bin/bash

###################################################################
#                              NOTE
#  This is NOT meant to be used standalone. It is intended to be run
#  from the build.sh in the parent directory.
###################################################################
BUILD_DEPS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PREFIX="${BUILD_DEPS_DIR}/install"

echo "Building dependencies..."

###################################################################
#                            bpftool
###################################################################
# Compile a standalone copy of bpftool. This is so that we no longer
# have to depend on the user installing `linux-tools` packages or
# equivalent, since that can sometimes be a pain, especially if
# they're not running the latest available kernel for their
# distribution. Also builds a static copy of libbpf.

BPFTOOL=${BPFTOOL:-bpftool}
BPFTOOL_SRC_DIR=${BUILD_DEPS_DIR}/bpftool/src
BPFTOOL_BUILD_LOG=${BUILD_DEPS_DIR}/bpftool.log
cd ${BPFTOOL_SRC_DIR}

echo "  Building libbpf and bpftool..."
# git submodule update --init
make &> ${BPFTOOL_BUILD_LOG}
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "  ERROR: Building bpftool failed. Check ${BPFTOOL_BUILD_LOG}"
  exit 1
fi

# Install the bpftool binary and the static libbpf.a
mkdir -p ${PREFIX}/bin
mkdir -p ${PREFIX}/lib
mkdir -p ${PREFIX}/include
cp bpftool ${PREFIX}/bin/bpftool
cp libbpf/libbpf.a ${PREFIX}/lib/libbpf.a
cp -r libbpf/include/* ${PREFIX}/include/

if ! command -v ${BPFTOOL} &> /dev/null; then
  export PATH="${PREFIX}/bin:${PATH}"
  echo "  No system bpftool found! Setting the PATH to use the bpftool we just built."
else
  echo "  Using system bpftool."
fi

###################################################################
#                 Intel Graphics Compiler (IGC)
###################################################################

IGC_DIR="${BUILD_DEPS_DIR}/igc"
IGC_BUILD_LOG="${BUILD_DEPS_DIR}/igc.log"

echo "  Building IGC..."

mkdir -p ${IGC_DIR}
cd ${IGC_DIR}
./build_igc.sh &> ${IGC_BUILD_LOG}
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "  ERROR: IGC failed to build."
  echo "  Please check ${IGC_BUILD_LOG} for details."
  exit 1
fi

echo "Done building dependencies. Installed to ${PREFIX}."
