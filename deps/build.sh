#!/bin/bash

###################################################################
#                              NOTE
#  This is NOT meant to be used standalone.
###################################################################
BUILD_DEPS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

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
PREFIX="${BUILD_DEPS_DIR}/install"
cd ${BPFTOOL_SRC_DIR}

git submodule update --init
make
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "ERROR: Building bpftool failed."
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
  echo "  No system bpftool found! Compiling libbpf and bpftool..."
else
  echo "  Using system bpftool."
fi
