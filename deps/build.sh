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
git submodule update --init
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
# IGC expects its dependencies in a specific directory structure,
# so recreate that.
IGC_DIR="${BUILD_DEPS_DIR}/igc/"
IGC_BUILD_LOG="${BUILD_DEPS_DIR}/igc.log"

# Clone the proper repos
cd ${IGC_DIR}
if [ ! -d vc-intrinsics ]; then
  git clone https://github.com/intel/vc-intrinsics vc-intrinsics
fi
if [ ! -d llvm-project ]; then
  git clone -b release/14.x https://github.com/llvm/llvm-project llvm-project
fi
if [ ! -d llvm-project/llvm/projects/opencl-clang ]; then
  git clone -b ocl-open-140 https://github.com/intel/opencl-clang llvm-project/llvm/projects/opencl-clang
fi
if [ ! -d llvm-project/llvm/projects/llvm-spirv ]; then
  git clone -b llvm_release_140 https://github.com/KhronosGroup/SPIRV-LLVM-Translator llvm-project/llvm/projects/llvm-spirv
fi
if [ ! -d SPIRV-Tools ]; then
  git clone https://github.com/KhronosGroup/SPIRV-Tools.git SPIRV-Tools
fi
if [ ! -d SPIRV-Headers ]; then
  git clone https://github.com/KhronosGroup/SPIRV-Headers.git SPIRV-Headers
fi

# Apply our patch
cd ${IGC_DIR}/igc
patch -R -p1 -s -f --dry-run < ${BUILD_DEPS_DIR}/iga.diff &>/dev/null
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  patch -p1 < ${BUILD_DEPS_DIR}/iga.diff &> ${IGC_BUILD_LOG}
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "  ERROR: The patch ${BUILD_DEPS_DIR}/iga.diff failed to apply."
    echo "  Please check ${IGC_BUILD_LOG} for details."
    exit 1
  fi
fi
cd ${IGC_DIR}

# Now build IGC
echo "  Building IGC..."
sudo rm -rf build
mkdir -p build
cd build
cmake \
  -DIGC_OPTION__LLVM_MODE=Source \
  -DIGC_OPTION__LLVM_SOURCES_DIR=${IGC_DIR}/llvm-project \
  -DIGC_OPTION__LLVM_PREFERRED_VERSION=14.0.6 \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  ../igc \
  &>> ${IGC_BUILD_LOG}
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "  ERROR: IGC failed to build."
  echo "  Please check ${IGC_BUILD_LOG} for details."
  exit 1
fi
make -j$(nproc) \
  &>> ${IGC_BUILD_LOG}
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "  ERROR: IGC failed to build."
  echo "  Please check ${IGC_BUILD_LOG} for details."
  exit 1
fi
make install \
  &>> ${IGC_BUILD_LOG}
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "  ERROR: IGC failed to build."
  echo "  Please check ${IGC_BUILD_LOG} for details."
  exit 1
fi
  
echo "Done building dependencies. Installed to ${PREFIX}."
