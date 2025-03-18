.PHONY: all clone_deps patch build install fullclean clean

BASEDIR := $(shell pwd)
PREFIX ?= $(BASEDIR)/../install
BUILD_DIR := $(BASEDIR)/build
IGC_DIR := $(BASEDIR)/igc
BUILD_TYPE := Release
PATCH_MARKER := $(IGC_DIR)/.patched

# NOTE: The large variety of branches/tags/commits makes this a full
# script-like makefile instead of a submodule.

# Branch names
LLVM_PROJECT_BRANCH := release/14.x
OPENCL_CLANG_BRANCH := ocl-open-140
LLVM_SPIRV_BRANCH := llvm_release_140

# Commit hashes and tags
IGC_VERSION := igc-1.0.16510.2
VC_INTRINSICS_VERSION := v0.18.0
LLVM_PROJECT_VERSION := llvmorg-14.0.5
OPENCL_CLANG_VERSION := cf95b33
LLVM_SPIRV_VERSION := 927efdc
SPIRV_TOOLS_VERSION := v2023.6.rc1
SPIRV_HEADERS_VERSION := 1c6bb27

all: clone_deps patch build install

clone_deps:
	# Ephemerally clone or update if already exists.

	@set -eux; \
	if [ ! -d "$(IGC_DIR)/.git" ]; then \
		echo "Cloning IGC repository..."; \
		git clone --recursive https://github.com/intel/intel-graphics-compiler.git $(IGC_DIR); \
		cd $(IGC_DIR) && git checkout $(IGC_VERSION); \
	fi; \

	if [ ! -d "vc-intrinsics/.git" ]; then \
		echo "Cloning vc-intrinsics repository..."; \
		git clone --recursive https://github.com/intel/vc-intrinsics vc-intrinsics; \
		cd vc-intrinsics && git checkout $(VC_INTRINSICS_VERSION); \
	fi; \

	if [ ! -d "llvm-project/.git" ]; then \
		echo "Cloning llvm-project repository..."; \
		git clone --recursive -b $(LLVM_PROJECT_BRANCH) https://github.com/llvm/llvm-project llvm-project; \
		cd llvm-project && git checkout $(LLVM_PROJECT_VERSION); \
	fi; \

	if [ ! -d "llvm-project/llvm/projects/opencl-clang/.git" ]; then \
		echo "Cloning opencl-clang repository..."; \
		git clone --recursive -b $(OPENCL_CLANG_BRANCH) https://github.com/intel/opencl-clang llvm-project/llvm/projects/opencl-clang; \
		cd llvm-project/llvm/projects/opencl-clang && git checkout $(OPENCL_CLANG_VERSION); \
	fi; \

	if [ ! -d "llvm-project/llvm/projects/llvm-spirv/.git" ]; then \
		echo "Cloning llvm-spirv repository..."; \
		git clone --recursive -b $(LLVM_SPIRV_BRANCH) https://github.com/KhronosGroup/SPIRV-LLVM-Translator llvm-project/llvm/projects/llvm-spirv; \
		cd llvm-project/llvm/projects/llvm-spirv && git checkout $(LLVM_SPIRV_VERSION); \
	fi; \

	if [ ! -d "SPIRV-Tools/.git" ]; then \
		echo "Cloning SPIRV-Tools repository..."; \
		git clone --recursive https://github.com/KhronosGroup/SPIRV-Tools.git SPIRV-Tools; \
		cd SPIRV-Tools && git checkout $(SPIRV_TOOLS_VERSION); \
	fi; \

	if [ ! -d "SPIRV-Headers/.git" ]; then \
		echo "Cloning SPIRV-Headers repository..."; \
		git clone --recursive https://github.com/KhronosGroup/SPIRV-Headers.git SPIRV-Headers; \
		cd SPIRV-Headers && git checkout $(SPIRV_HEADERS_VERSION); \
	fi

patch: $(PATCH_MARKER)

$(PATCH_MARKER):
	cd $(IGC_DIR) && patch -p1 < $(BASEDIR)/iga.diff && touch $@

build: clone_deps patch $(PREFIX)/igc/lib/libiga64.a
	@set -eux; \
	if [ -d "$(PREFIX)/igc" ]; then \
		echo "IGC is already built and installed in $(PREFIX)/igc. Skipping build..."; \
	else \
		echo "Building IGC..."; \
		rm -rf $(BUILD_DIR); \
		mkdir -p $(BUILD_DIR); \
		cd $(BUILD_DIR) && \
			cmake \
			cmake -DCMAKE_VERBOSE_MAKEFILE=ON \
			-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
			-DCMAKE_CXX_FLAGS="-Wno-maybe-uninitialized -Wno-uninitialized -Wno-free-nonheap-object -Wno-nonnull" \
			-DIGC_OPTION__LLVM_MODE=Source \
			-DIGC_OPTION__LLVM_SOURCES_DIR=$(BASEDIR)/llvm-project \
			-DIGC_OPTION__LLVM_PREFERRED_VERSION=14.0.5 \
			-DCMAKE_INSTALL_PREFIX=$(PREFIX)/igc \
			$(IGC_DIR); \
		cd $(BUILD_DIR) && $(MAKE) -j$(shell nproc); \
	fi

$(PREFIX)/igc/lib/libiga64.a:
	rm -rf $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && \
		cmake \
		-DCMAKE_VERBOSE_MAKEFILE=ON \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DCMAKE_CXX_FLAGS="-Wno-maybe-uninitialized -Wno-uninitialized -Wno-free-nonheap-object -Wno-nonnull" \
		-DIGC_OPTION__LLVM_MODE=Source \
		-DIGC_OPTION__LLVM_SOURCES_DIR=$(BASEDIR)/llvm-project \
		-DIGC_OPTION__LLVM_PREFERRED_VERSION=14.0.5 \
		-DCMAKE_INSTALL_PREFIX=$(PREFIX)/igc \
		$(IGC_DIR)
	cd $(BUILD_DIR) && $(MAKE) -j$(shell nproc)

install: build
	cd $(BUILD_DIR) && $(MAKE) install

fullclean: clean
	# Remove git clone'ed repositories
	rm -rf $(IGC_DIR) vc-intrinsics llvm-project SPIRV-Tools SPIRV-Headers

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(PREFIX)/igc
