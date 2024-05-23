#!/bin/bash
BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PREFIX="${PREFIX:-${BASEDIR}/../install}"

BUILD_TYPE="Release"

# Branch names
LLVM_PROJECT_BRANCH="release/14.x"
OPENCL_CLANG_BRANCH="ocl-open-140"
LLVM_SPIRV_BRANCH="llvm_release_140"

# Commit hashes and tags
IGC_VERSION="igc-1.0.16510.2"
VC_INTRINSICS_VERSION="v0.18.0"
LLVM_PROJECT_VERSION="llvmorg-14.0.5"
OPENCL_CLANG_VERSION="cf95b33"
LLVM_SPIRV_VERSION="927efdc"
SPIRV_TOOLS_VERSION="v2023.6.rc1"
SPIRV_HEADERS_VERSION="1c6bb27"

cd ${BASEDIR}

###################################################################
#                 Intel Graphics Compiler (IGC)
###################################################################
# IGC expects its dependencies in a specific directory structure,
# so recreate that.
IGC_DIR="${BASEDIR}/igc"

# IGC itself
git clone --recursive https://github.com/intel/intel-graphics-compiler.git igc
cd igc
git checkout ${IGC_VERSION}
cd ${BASEDIR}

# vc-intrinsics
git clone --recursive https://github.com/intel/vc-intrinsics vc-intrinsics
cd vc-intrinsics 
git checkout ${VC_INTRINSICS_VERSION}
cd ${BASEDIR}

# llvm-project
git clone --recursive -b ${LLVM_PROJECT_BRANCH} https://github.com/llvm/llvm-project llvm-project
cd llvm-project
git checkout ${LLVM_PROJECT_VERSION}
cd ${BASEDIR}

git clone --recursive -b ${OPENCL_CLANG_BRANCH} https://github.com/intel/opencl-clang llvm-project/llvm/projects/opencl-clang
cd llvm-project/llvm/projects/opencl-clang && git checkout ${OPENCL_CLANG_VERSION} && cd ${BASEDIR}
git clone --recursive -b ${LLVM_SPIRV_BRANCH} https://github.com/KhronosGroup/SPIRV-LLVM-Translator llvm-project/llvm/projects/llvm-spirv
cd llvm-project/llvm/projects/llvm-spirv && git checkout ${LLVM_SPIRV_VERSION} && cd ${BASEDIR}
git clone --recursive https://github.com/KhronosGroup/SPIRV-Tools.git SPIRV-Tools
cd SPIRV-Tools && git checkout ${SPIRV_TOOLS_VERSION} && cd ${BASEDIR}
git clone --recursive https://github.com/KhronosGroup/SPIRV-Headers.git SPIRV-Headers
cd SPIRV-Headers && git checkout ${SPIRV_HEADERS_VERSION} && cd ${BASEDIR}

# Apply our patch
cd ${IGC_DIR}
patch -R -p1 -s -f --dry-run < ${BASEDIR}/iga.diff &>/dev/null
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  patch -p1 < ${BASEDIR}/iga.diff
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "  ERROR: The patch ${BASEDIR}/iga.diff failed to apply."
    echo "  Please check ${IGC_BUILD_LOG} for details."
    exit 1
  fi
fi
cd ${IGC_DIR}

# Now build IGC
cd ${BASEDIR}
sudo rm -rf build
mkdir -p build
cd build
cmake \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DIGC_OPTION__LLVM_MODE=Source \
  -DIGC_OPTION__LLVM_SOURCES_DIR=${BASEDIR}/llvm-project \
  -DIGC_OPTION__LLVM_PREFERRED_VERSION=14.0.5 \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  ${IGC_DIR}
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "  ERROR: IGC failed to build."
  echo "  Please check ${IGC_BUILD_LOG} for details."
  exit 1
fi
make -j$(nproc)
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "  ERROR: IGC failed to build."
  echo "  Please check ${IGC_BUILD_LOG} for details."
  exit 1
fi
make install
RETVAL=$?
if [ ${RETVAL} -ne 0 ]; then
  echo "  ERROR: IGC failed to build."
  echo "  Please check ${IGC_BUILD_LOG} for details."
  exit 1
fi
