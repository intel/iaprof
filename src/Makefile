BASE_DIR := $(shell pwd)
SRC_DIR := $(BASE_DIR)
PREFIX := $(BASE_DIR)/../deps/install
CC := clang
CXX := clang++
LLVM_CONFIG := llvm-config
GIT_HASH := $(shell git rev-parse HEAD)
CFLAGS := -O0 -gdwarf-4 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -Wall -Werror -Wno-unused-function -DDEBUG -DGIT_COMMIT_HASH=\"$(GIT_HASH)\"
BPF_CFLAGS := -O2
LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags --libs demangle)

DRIVER_HELPERS_DIR := $(SRC_DIR)/driver_helpers

GENERATED_HEADERS_DIR := $(SRC_DIR)/collectors/bpf/bpf/generated_headers
VMLINUX_H := $(GENERATED_HEADERS_DIR)/vmlinux.h
DRM_H := $(GENERATED_HEADERS_DIR)/drm.h

BPFTOOL := $(PREFIX)/bpftool/bin/bpftool

# If applicable, find the i915 prelim headers from the DKMS version
I915_DKMS_SRC_DIR := $(shell find /usr/src -maxdepth 1 -name "intel-i915-dkms*" | tail -n 1)
ifeq (,$(I915_DKMS_SRC_DIR))
  $(warning "Couldn't find the intel-i915-dkms directory in /usr/src. Proceeding without.")
  IAPROF_XE_DRIVER := 1
endif

BPF_DIR := $(SRC_DIR)/collectors/bpf/bpf
BPF_PROG_O := $(BPF_DIR)/main.bpf.o

ifdef IAPROF_XE_DRIVER
  CFLAGS += -DXE_DRIVER
  DRIVER_HELPERS := $(DRIVER_HELPERS_DIR)/xe_helpers.o
  DRIVER_H := $(GENERATED_HEADERS_DIR)/xe.h
  DRIVER_CFLAGS := -DGPU_PLATFORM_xe=2 -DGPU_PLATFORM=GPU_PLATFORM_xe -DGPU_DRIVER_xe=2 -DGPU_DRIVER=GPU_DRIVER_xe -DCOLLECTOR_uprobe=2 -DKERNEL_LAUNCH_COLLECTOR=COLLECTOR_driver
else
  DRIVER_HELPERS := $(DRIVER_HELPERS_DIR)/i915_helpers.o
  DRIVER_HELPERS_INCL := $(DRIVER_HELPERS_DIR)/drm/i915_drm_prelim.h
  DRIVER_H := $(GENERATED_HEADERS_DIR)/i915.h
  DRIVER_CFLAGS := -DGPU_PLATFORM_pvc=1 -DGPU_PLATFORM=GPU_PLATFORM_pvc -DGPU_DRIVER_i915=1 -DGPU_DRIVER=GPU_DRIVER_i915 -DCOLLECTOR_driver=1 -DKERNEL_LAUNCH_COLLECTOR=COLLECTOR_driver
endif

MAIN_SKEL_H := $(BPF_DIR)/main.skel.h

DRM_HELPERS := $(SRC_DIR)/drm_helpers/drm_helpers.o
BPF_HELPERS := $(SRC_DIR)/bpf_helpers/trace_helpers.o \
               $(SRC_DIR)/bpf_helpers/uprobe_helpers.o \
               $(SRC_DIR)/bpf_helpers/bpf_map_helpers.o
STORES := $(SRC_DIR)/stores/gpu_kernel_stalls.o \
	  $(SRC_DIR)/stores/interval_profile.o
COLLECTORS := $(SRC_DIR)/collectors/bpf/bpf_collector.o \
	      $(SRC_DIR)/collectors/debug/debug_collector.o \
	      $(SRC_DIR)/collectors/eustall/eustall_collector.o
PRINTERS := $(SRC_DIR)/printers/debug/debug_printer.o \
	    $(SRC_DIR)/printers/stack/stack_printer.o \
	    $(SRC_DIR)/printers/interval/interval_printer.o
UTILS := $(SRC_DIR)/utils/utils.o \
         $(SRC_DIR)/utils/array.o
DEMANGLE := $(SRC_DIR)/utils/demangle.o
GPU_PARSERS := $(SRC_DIR)/gpu_parsers/shader_decoder.o
COMMANDS := $(SRC_DIR)/commands/record.o \
	    $(SRC_DIR)/commands/flame.o
IAPROF := $(SRC_DIR)/iaprof.o

OBJECTS := $(DRM_HELPERS) $(DRIVER_HELPERS) $(BPF_HELPERS) $(STORES) $(COLLECTORS) $(PRINTERS) $(UTILS) $(DEMANGLE) $(GPU_PARSERS) $(COMMANDS) $(IAPROF)

all: $(SRC_DIR)/../iaprof

$(SRC_DIR)/../iaprof: $(BPF_PROG_O) $(MAIN_SKEL_H) $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@ -L$(PREFIX)/lib -lpthread $(PREFIX)/bpftool/lib/libbpf.a -lz -lzstd -lstdc++ $(PREFIX)/libelf/lib/libdw.a $(PREFIX)/libelf/lib/libelf.a $(PREFIX)/igc/lib/libiga64.a

$(VMLINUX_H):
	mkdir -p $(GENERATED_HEADERS_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(DRIVER_H):
	mkdir -p $(GENERATED_HEADERS_DIR)
ifdef IAPROF_XE_DRIVER
	$(BPFTOOL) btf dump file /sys/kernel/btf/xe format c > $@
else
	$(BPFTOOL) btf dump file /sys/kernel/btf/i915 format c > $@
endif

$(DRM_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/drm format c > $@

$(MAIN_SKEL_H): $(BPF_DIR)/main.bpf.o
	$(BPFTOOL) gen skeleton $(BPF_DIR)/main.bpf.o > $@

$(DRIVER_HELPERS_DIR)/xe_helpers.o: $(DRIVER_HELPERS_DIR)/xe_helpers.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(SRC_DIR)/driver_helpers -c $< -o $@

$(DRIVER_HELPERS_DIR)/i915_helpers.o: $(DRIVER_HELPERS_DIR)/i915_helpers.c $(DRIVER_HELPERS_INCL)
	$(CC) $(CFLAGS) $(DRIVER_CFLAGS) -I$(SRC_DIR) -I$(SRC_DIR)/driver_helpers -c $< -o $@

$(BPF_PROG_O): $(DRIVER_HELPERS_INCL) $(VMLINUX_H) $(DRIVER_H) $(DRM_H)
	$(CC) $(BPF_CFLAGS) -target bpf -D__TARGET_ARCH_x86 -g -v -Wno-pass-failed $(DRIVER_CFLAGS) -I$(GENERATED_HEADERS_DIR) -I$(BPF_DIR) -I$(SRC_DIR) -I$(PREFIX)/libbpf/include -c $(BPF_DIR)/main.bpf.c -o $@

$(DEMANGLE):
	$(CXX) $(CFLAGS) $(shell $(LLVM_CONFIG) --cppflags) -I$(PREFIX) -I$(SRC_DIR) -c $(SRC_DIR)/utils/demangle.cpp -o $@

$(DRIVER_HELPERS_INCL):
	@if [ -n "$(I915_DKMS_SRC_DIR)" ]; then \
		mkdir -p $(DRIVER_HELPERS_DIR)/drm; \
		printf "Copying $(I915_DKMS_SRC_DIR)/i915-include/uapi/drm/i915_drm_prelim.h into $@\n"; \
		cat "$(I915_DKMS_SRC_DIR)/i915-include/uapi/drm/i915_drm_prelim.h" | \
			sed 's/#include "i915_drm.h"/#include <drm\/i915_drm.h>/' | \
			sed '/define __I915_PMU_OTHER/i#ifndef __I915_PMU_OTHER' | \
			sed '/define __I915_PMU_OTHER/a#endif' > "$@"; \
		printf "Using i915_drm_prelim.h from DKMS source\n"; \
	else \
		printf "warning: Couldn't find the intel-i915-dkms directory in /usr/src. Proceeding without.\n"; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) $(DRIVER_CFLAGS) -I$(SRC_DIR) -I$(SRC_DIR)/driver_helpers -I$(SRC_DIR)/utils -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -I$(PREFIX)/libelf/include -c $< -o $@

%.o: %.cpp
	$(CXX) $(CFLAGS) -I$(SRC_DIR) $(shell $(LLVM_CONFIG) --cppflags) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(SRC_DIR)/../iaprof
	rm -rf $(SRC_DIR)/driver_helpers/drm
	rm -rf $(GENERATED_HEADERS_DIR)
	rm -f $(MAIN_SKEL_H) $(VMLINUX_H) $(DRIVER_H) $(DRM_H)
	rm -f $(BPF_PROG_O)
