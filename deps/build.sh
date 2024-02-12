#!/bin/bash

###################################################################
#                              NOTE
#  This is NOT meant to be used standalone. It is intended to be run
#  from the build.sh in the parent directory.
###################################################################
BUILD_DEPS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PREFIX="${BUILD_DEPS_DIR}/install"

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

###################################################################
#                 Intel Graphics Compiler (IGC)
###################################################################
# IGC expects its dependencies in a specific directory structure,
# so recreate that.
IGC_DIR="${BUILD_DEPS_DIR}/igc/"
IGC_LOG="${BUILD_DEPS_DIR}/igc/build.log"

cd ${IGC_DIR}
git clone https://github.com/intel/vc-intrinsics vc-intrinsics
git clone -b release/14.x https://github.com/llvm/llvm-project llvm-project
git clone -b ocl-open-140 https://github.com/intel/opencl-clang llvm-project/llvm/projects/opencl-clang
git clone -b llvm_release_140 https://github.com/KhronosGroup/SPIRV-LLVM-Translator llvm-project/llvm/projects/llvm-spirv
git clone https://github.com/KhronosGroup/SPIRV-Tools.git SPIRV-Tools
git clone https://github.com/KhronosGroup/SPIRV-Headers.git SPIRV-Headers

# Now build IGC
echo "Building IGC..."
sudo rm -rf build
mkdir -p build
cd build
cmake \
  -DIGC_OPTION__LLVM_MODE=Source \
  -DIGC_OPTION__LLVM_SOURCES_DIR=${IGC_DIR}/llvm-project \
  -DIGC_OPTION__LLVM_PREFERRED_VERSION=14.0.6 \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  ../igc \
  &> ${IGC_LOG}
make -j$(nproc) \
  &>> ${IGC_LOG}
make install \
  &>> ${IGC_LOG}
