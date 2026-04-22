#!/bin/bash

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PREFIX="${PREFIX:-${BASEDIR}/install}"

export CMAKE_EXPORT_COMPILE_COMMANDS=1

# Arguments
GETOPT_OUTPUT=`getopt -o '' --long no-clone,runtime-only,no-patches,no-fp -n 'build_graphics_stack.sh' -- "$@"`
if [ $? != 0 ] ; then echo "'getopt' failed. Aborting." >&2 ; exit 1 ; fi
eval set -- "$GETOPT_OUTPUT"

# Handle arguments
NO_CLONE=false
RUNTIME_ONLY=false
NO_FP=false
NO_PATCHES=false
NO_BUILTIN_PATCH=false
NO_DEBUG_PATCH=false
while true; do
  case "$1" in
    --no-clone        ) NO_CLONE=true;         shift ;;
    --runtime-only    ) RUNTIME_ONLY=true;     shift ;;
    --no-fp-patch     ) NO_FP=true;            shift ;;
    --no-patches      ) NO_PATCHES=true;       shift ;;
    -- ) shift; break;;
    * ) break;;
  esac
done

if [[ "${NO_PATCHES}" == true ]]; then
    NO_BUILTIN_PATCH=true
    NO_DEBUG_PATCH=true
fi


BUILD_TYPE="Debug"

# Branch names
LLVM_PROJECT_BRANCH="release/15.x"
OPENCL_CLANG_BRANCH="ocl-open-150"
LLVM_SPIRV_BRANCH="llvm_release_150"

# Commit hashes and tags
IGC_VERSION="v2.11.7"
LEVEL_ZERO_VERSION="v1.21.9"
GMM_VERSION="intel-gmmlib-22.7.0"
COMPUTE_RUNTIME_VERSION="25.18.33578.6"
OPENCL_LOADER_VERSION="v2024.10.24"

OPENCL_CLANG_VERSION="5824297"
LLVM_SPIRV_VERSION="2d4f2e7"
SPIRV_TOOLS_VERSION="v2025.1.rc1"
SPIRV_HEADERS_VERSION="0e71067"
VC_INTRINSICS_VERSION="v0.22.1"
LLVM_PROJECT_VERSION="llvmorg-15.0.7"
SYCL_VERSION="v6.3.0"

# Hopefully get NEO to find these headers
export PATH="${PREFIX}/bin:${PATH}"
export LD_LIBRARY_PATH="${PREFIX}/lib:${LD_LIBRARY_PATH}"
export C_INCLUDE_PATH="${PREFIX}/include"
export CPLUS_INCLUDE_PATH="${PREFIX}/include"
export CPATH="${PREFIX}/include"

if [[ "${NO_CLONE}" != true ]]; then
    cd ${BASEDIR}
    rm -rf gmmlib llvm-project SPIRV-Headers igc \
    OpenCL-Headers SPIRV-Tools compute-runtime level-zero OpenCL-ICD-Loader \
    vc-intrinsics
fi

if [[ "${RUNTIME_ONLY}" != true ]]; then
    ###################################################################
    #                 Intel Graphics Compiler (IGC)
    ###################################################################
    # IGC expects its dependencies in a specific directory structure,
    # so recreate that.
    IGC_DIR="${BASEDIR}/igc"

    if [[ "${NO_CLONE}" != true ]]; then
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
    fi

    # Now build IGC
    cd ${BASEDIR}
    echo "Building IGC..."
    rm -rf build
    mkdir -p build
    cd build
    cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DIGC_OPTION__LLVM_MODE=Source \
    -DCMAKE_CXX_FLAGS="-include cstdint -Wno-cpp -Wno-free-nonheap-object" \
    -DCMAKE_C_FLAGS="-include stdint.h -Wno-free-nonheap-object" \
    -DIGC_OPTION__LLVM_SOURCES_DIR=${BASEDIR}/llvm-project \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} \
    ${IGC_DIR}
    make -j$(nproc)
    make install

    ###################################################################
    #                    Khronos OpenCL Loader
    ###################################################################
    cd ${BASEDIR}

    if [[ "${NO_CLONE}" != true ]]; then
        # Clone everything
        git clone --recursive https://github.com/KhronosGroup/OpenCL-ICD-Loader
        cd OpenCL-ICD-Loader
        git checkout ${OPENCL_LOADER_VERSION}
        cd ..
        git clone --recursive https://github.com/KhronosGroup/OpenCL-Headers
        cd OpenCL-Headers
        git checkout ${OPENCL_LOADER_VERSION}
        cd ..
        git clone --recursive https://github.com/KhronosGroup/OpenCL-CLHPP
        cd OpenCL-CLHPP
        git checkout ${OPENCL_LOADER_VERSION}
        cd ..
    fi

    cd ${BASEDIR}/OpenCL-Headers
    rm -rf build && mkdir build && cd build
    cmake \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    ..
    make install

    cd ${BASEDIR}/OpenCL-ICD-Loader
    rm -rf build && mkdir build && cd build
    cmake \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DCMAKE_PREFIX_PATH="${PREFIX}" \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    ..
    make install

    cd ${BASEDIR}/OpenCL-CLHPP
    rm -rf build && mkdir build && cd build
    cmake \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DCMAKE_PREFIX_PATH="${PREFIX}" \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    ..
    make install

    # Level Zero Loader first
    cd ${BASEDIR}

    if [[ "${NO_CLONE}" != true ]]; then
        git clone https://github.com/oneapi-src/level-zero.git level-zero
        cd level-zero
        git checkout ${LEVEL_ZERO_VERSION}
    fi

    cd ${BASEDIR}/level-zero

    rm -rf build && mkdir build && cd build
    cmake \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} \
    -DCMAKE_PREFIX_PATH="${PREFIX}" \
    ..
    make -j$(nproc)
    make install

    # LibGMM
    cd ${BASEDIR}

    if [[ "${NO_CLONE}" != true ]]; then
        git clone https://github.com/intel/gmmlib.git gmmlib
        cd gmmlib
        git checkout ${GMM_VERSION}
    fi

    cd ${BASEDIR}/gmmlib

    rm -rf build && mkdir build && cd build
    cmake \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} \
    -DCMAKE_PREFIX_PATH="${PREFIX}" \
    ..
    make -j$(nproc)
    make install
fi


###################################################################
#                 Intel Compute Runtime (NEO)
###################################################################

# Now the Compute Runtime library itself
cd ${BASEDIR}

if [[ "${NO_CLONE}" != true ]]; then
    git clone --recursive https://github.com/intel/compute-runtime.git compute-runtime
    cd compute-runtime
    git checkout ${COMPUTE_RUNTIME_VERSION}
fi


cd ${BASEDIR}/compute-runtime

function apply_patch_to_compute_runtime() {
    cd ${BASEDIR}/compute-runtime

    PATCH=$(realpath $1)

    if ! [[ -f "${PATCH}" ]]; then
        echo "  ERROR: Could not find patch ${PATCH}."
        exit 1
    fi

    echo "Applying patch ${PATCH}..."

    # Apply our patch
    patch -R -p1 -s -f --dry-run < "${PATCH}" &>/dev/null
    RETVAL=$?
    if [ ${RETVAL} -ne 0 ]; then
        patch -p1 < "${PATCH}"
        RETVAL=$?
        if [ ${RETVAL} -ne 0 ]; then
            echo "  ERROR: The patch ${PATCH} failed to apply."
            exit 1
        fi
    fi
}

if [[ "${NO_PATCHES}" != true ]]; then
#     apply_patch_to_compute_runtime ${BASEDIR}/compute-runtime-usdt.diff
#     apply_patch_to_compute_runtime ${BASEDIR}/compute-runtime-kernel-debug-info.diff
    apply_patch_to_compute_runtime ${BASEDIR}/compute-runtime-usdt-25.18.33578.6.diff
    apply_patch_to_compute_runtime ${BASEDIR}/compute-runtime-kernel-debug-info-25.18.33578.6.diff
fi

if [[ "${NO_FP}" != true ]]; then
    FP="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer"
fi

cd ${BASEDIR}/compute-runtime

rm -rf build && mkdir build && cd build
ulimit -c unlimited
cmake \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DCMAKE_PREFIX_PATH="${PREFIX}" \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  -DIGC_DIR="${PREFIX}" \
  -DLEVEL_ZERO_ROOT="${PREFIX}" \
  -DGMM_DIR="${PREFIX}" \
  -DOCL_ICD_VENDORDIR="${PREFIX}/etc/OpenCL/vendors" \
  -DCMAKE_CXX_FLAGS="${FP} -include cstdint -Wno-cpp -Wno-free-nonheap-object" \
  -DCMAKE_C_FLAGS="${FP} -include stdint.h -Wno-free-nonheap-object" \
  -DKHRONOS_HEADERS_DIR="${PREFIX}/" \
  -DNEO_ENABLE_XE_EU_DEBUG_SUPPORT=1 \
  -DNEO_USE_XE_EU_DEBUG_EXP_UPSTREAM=1 \
  -DNEO_SKIP_UNIT_TESTS=1 \
  ..
make -j$(nproc)
make install

###################################################################
#                               SYCL
###################################################################

cd ${BASEDIR}

export PATH="${PREFIX}/bin:${PATH}"
export LD_LIBRARY_PATH="${PREFIX}/lib:${LD_LIBRARY_PATH}"

git clone https://github.com/intel/llvm -b sycl sycl
cd sycl
git checkout ${SYCL_VERSION}
rm -rf build
python3 ./buildbot/configure.py \
  -t Release \
  --cmake-opt=-DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
  --cmake-opt=-DCMAKE_C_FLAGS="-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer" \
  --cmake-opt=-DCMAKE_INSTALL_PREFIX="${PREFIX}" \
  --cmake-opt=-DUR_COMPUTE_RUNTIME_REPO="${BASEDIR}/compute-runtime"
cd build
ninja deploy-sycl-toolchain
ninja install
