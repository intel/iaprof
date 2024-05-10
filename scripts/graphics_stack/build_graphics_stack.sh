#!/bin/bash

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PREFIX="${BASEDIR}/install"

BUILD_TYPE="Debug"

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
LEVEL_ZERO_VERSON="v1.16.14"
GMM_VERSION="intel-gmmlib-22.3.18"
COMPUTE_RUNTIME_VERSION="24.13.29138.7"

###################################################################
#                 Intel Graphics Compiler (IGC)
###################################################################
# IGC expects its dependencies in a specific directory structure,
# so recreate that.
IGC_DIR="${BASEDIR}/igc"
IGC_LOG="${BASEDIR}/build.log"

git clone https://github.com/intel/intel-graphics-compiler.git igc
cd igc && git checkout ${IGC_VERSION} && cd ${BASEDIR}
git clone https://github.com/intel/vc-intrinsics vc-intrinsics
cd vc-intrinsics && git checkout ${VC_INTRINSICS_VERSION} && cd ${BASEDIR}
git clone -b ${LLVM_PROJECT_BRANCH} https://github.com/llvm/llvm-project llvm-project
cd llvm-project && git checkout ${LLVM_PROJECT_VERSION} && cd ${BASEDIR}
git clone -b ${OPENCL_CLANG_BRANCH} https://github.com/intel/opencl-clang llvm-project/llvm/projects/opencl-clang
cd llvm-project/llvm/projects/opencl-clang && git checkout ${OPENCL_CLANG_VERSION} && cd ${BASEDIR}
git clone -b ${LLVM_SPIRV_BRANCH} https://github.com/KhronosGroup/SPIRV-LLVM-Translator llvm-project/llvm/projects/llvm-spirv
cd llvm-project/llvm/projects/llvm-spirv && git checkout ${LLVM_SPIRV_VERSION} && cd ${BASEDIR}
git clone https://github.com/KhronosGroup/SPIRV-Tools.git SPIRV-Tools
cd SPIRV-Tools && git checkout ${SPIRV_TOOLS_VERSION} && cd ${BASEDIR}
git clone https://github.com/KhronosGroup/SPIRV-Headers.git SPIRV-Headers
cd SPIRV-Headers && git checkout ${SPIRV_HEADERS_VERSION} && cd ${BASEDIR}

# Now build IGC
cd ${BASEDIR}
echo "Building IGC..."
sudo rm -rf build
mkdir -p build
cd build
cmake \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DIGC_OPTION__LLVM_MODE=Source \
  -DIGC_OPTION__LLVM_SOURCES_DIR=${BASEDIR}/llvm-project \
  -DIGC_OPTION__LLVM_PREFERRED_VERSION=14.0.5 \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  ${IGC_DIR} \
  &> ${IGC_LOG}
make -j$(nproc) \
  &>> ${IGC_LOG}
make install \
  &>> ${IGC_LOG}
  
# Hopefully get NEO to find these headers
export PATH="${PREFIX}/bin:${PATH}"
export LD_LIBRARY_PATH="${PREFIX}/lib:${LD_LIBRARY_PATH}"
export C_INCLUDE_PATH="${PREFIX}/include"
export CPLUS_INCLUDE_PATH="${PREFIX}/include"
export CPATH="${PREFIX}/include"
  
###################################################################
#                 Intel Compute Runtime (NEO)
###################################################################
# Level Zero Loader first
cd ${BASEDIR}
git clone https://github.com/oneapi-src/level-zero.git level-zero
cd level-zero
git checkout ${LEVEL_ZERO_VERSION}
rm -rf build && mkdir build && cd build
cmake \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  ..
make -j$(nproc)
make install

# LibGMM
cd ${BASEDIR}
git clone https://github.com/intel/gmmlib.git gmmlib
cd gmmlib
git checkout ${GMM_VERSION}
rm -rf build && mkdir build && cd build
cmake \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  ..
make -j$(nproc)
make install

# Now the Compute Runtime library itself
cd ${BASEDIR}
git clone https://github.com/intel/compute-runtime.git compute-runtime
cd compute-runtime
git checkout ${COMPUTE_RUNTIME_VERSION}
rm -rf build && mkdir build && cd build
ulimit -c unlimited
cmake \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DNEO_SKIP_UNIT_TESTS=1 \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  -DIGC_DIR="${PREFIX}" \
  -DLEVEL_ZERO_ROOT="${PREFIX}" \
  -DGMM_DIR="${PREFIX}" \
  -DOCL_ICD_VENDORDIR="${PREFIX}/etc/OpenCL/vendors" \
  -G Ninja \
  ..
ninja -j$(nproc)
ninja install
