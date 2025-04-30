BASE_DIR := $(shell pwd)
SRC_DIR := $(BASE_DIR)
PREFIX := $(BASE_DIR)/../deps/install

CC := clang
CXX := clang++
LLVM_CONFIG := llvm-config
GIT_HASH := $(shell git rev-parse HEAD)
CFLAGS := -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -Wall -Werror -Wno-unused-function -DGIT_COMMIT_HASH=\"$(GIT_HASH)\"
LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags --libs demangle)
BPF_CFLAGS := -O2 -DDEBUG
LLVM_STRIP := llvm-strip
BPFTOOL := $(PREFIX)/bpftool/bin/bpftool

ifdef DEBUG
  CFLAGS += -g -O0 -DDEBUG
else
  CFLAGS += -g -O0 -DDEBUG
endif

ifdef FUZZ
  CFLAGS += -fsanitize=fuzzer-no-link,address -fprofile-instr-generate -fcoverage-mapping
  LDFLAGS += -fsanitize=fuzzer,address -fprofile-instr-generate -fcoverage-mapping
endif

DRIVER_HELPERS_DIR := $(SRC_DIR)/driver_helpers
GENERATED_HEADERS_DIR := $(SRC_DIR)/collectors/bpf/bpf/generated_headers

# If applicable, find the i915 prelim headers from the DKMS version,
# which is a typical setup on Intel® Tiber™ AI Cloud, otherwise detect
# as an Xe-based driver.
I915_DKMS_SRC_DIR := $(shell find /usr/src -maxdepth 1 -name "intel-i915-dkms*" | tail -n 1)
ifeq (,$(I915_DKMS_SRC_DIR))
  $(warning "Couldn't find the intel-i915-dkms directory in /usr/src. Proceeding as Xe build.")

  IAPROF_XE_DRIVER := 1
  GPU_PLATFORM := xe2
  GPU_DRIVER := xe
  KERNEL_LAUNCH_COLLECTOR := uprobe

  DRIVER_HELPERS := $(DRIVER_HELPERS_DIR)/xe_helpers.o
  DRIVER_H := $(GENERATED_HEADERS_DIR)/xe.h
else
  $(warning "Proceeding as PVC build.")
  GPU_PLATFORM := pvc
  GPU_DRIVER := i915
  KERNEL_LAUNCH_COLLECTOR := driver

  DRIVER_HELPERS := $(DRIVER_HELPERS_DIR)/i915_helpers.o
  DRIVER_HELPERS_INCL := $(DRIVER_HELPERS_DIR)/drm/i915_drm_prelim.h
  DRIVER_H := $(GENERATED_HEADERS_DIR)/i915.h
endif

CONFIG_CFLAGS := -DGPU_PLATFORM_pvc=1 -DGPU_PLATFORM_xe=2 -DGPU_PLATFORM=GPU_PLATFORM_$(GPU_PLATFORM) -DGPU_DRIVER_i915=1 -DGPU_DRIVER_xe=2 -DGPU_DRIVER=GPU_DRIVER_$(GPU_DRIVER) -DCOLLECTOR_driver=1 -DCOLLECTOR_uprobe=2 -DKERNEL_LAUNCH_COLLECTOR=COLLECTOR_$(KERNEL_LAUNCH_COLLECTOR)

VMLINUX_H := $(GENERATED_HEADERS_DIR)/vmlinux.h
DRM_H := $(GENERATED_HEADERS_DIR)/drm.h

BPF_DIR := $(SRC_DIR)/collectors/bpf/bpf
BPF_PROG_O := $(BPF_DIR)/main.bpf.o
MAIN_SKEL_H := $(BPF_DIR)/main.skel.h

DRM_HELPERS := $(SRC_DIR)/drm_helpers/drm_helpers.o
BPF_HELPERS := $(SRC_DIR)/bpf_helpers/trace_helpers.o \
               $(SRC_DIR)/bpf_helpers/uprobe_helpers.o
STORES := $(SRC_DIR)/stores/gpu_kernel.o
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
	    $(SRC_DIR)/commands/flame.o \
		$(SRC_DIR)/commands/flamescope.o
IAPROF := $(SRC_DIR)/iaprof.o

OBJECTS := $(DRM_HELPERS) $(BPF_HELPERS) $(STORES) $(COLLECTORS) $(PRINTERS) $(UTILS) $(DEMANGLE) $(GPU_PARSERS) $(COMMANDS) $(DRIVER_HELPERS) $(IAPROF)

all: $(SRC_DIR)/../iaprof

$(SRC_DIR)/../iaprof: $(BPF_PROG_O) $(MAIN_SKEL_H) $(DRM_HELPERS) $(BPF_HELPERS) $(STORES) $(COLLECTORS) $(PRINTERS) $(UTILS) $(DEMANGLE) $(GPU_PARSERS) $(COMMANDS) $(DRIVER_HELPERS) $(IAPROF)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@ -lpthread $(PREFIX)/bpftool/lib/libbpf.a -lz -lzstd -lstdc++ $(PREFIX)/libelf/lib/libdw.a $(PREFIX)/libelf/lib/libelf.a $(PREFIX)/igc/lib/libiga64.a

$(SRC_DIR)/drm_helpers/drm_helpers.o: $(DRIVER_HELPERS_INCL) $(SRC_DIR)/drm_helpers/drm_helpers.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(PREFIX)/../kernel_headers -I$(SRC_DIR) -I$(SRC_DIR)/driver_helpers -c $(SRC_DIR)/drm_helpers/drm_helpers.c -o $@

$(SRC_DIR)/bpf_helpers/%.o: $(SRC_DIR)/bpf_helpers/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(PREFIX)/libbpf/include -c $< -o $@

$(SRC_DIR)/stores/%.o: $(SRC_DIR)/stores/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(PREFIX)/igc/include -I$(PREFIX)/../kernel_headers -I$(SRC_DIR) -I$(DRIVER_HELPERS_DIR) -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -c $< -o $@

$(SRC_DIR)/collectors/bpf/bpf_collector.o: $(MAIN_SKEL_H) $(SRC_DIR)/collectors/bpf/bpf_collector.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) --std=c2x -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(DRIVER_HELPERS_DIR) -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -c $(SRC_DIR)/collectors/bpf/bpf_collector.c -o $@

$(SRC_DIR)/collectors/debug/%.o: $(SRC_DIR)/collectors/debug/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(PREFIX)/../kernel_headers -I$(PREFIX)/libelf/include -I$(SRC_DIR) -I$(DRIVER_HELPERS_DIR) -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -c $< -o $@

$(SRC_DIR)/collectors/eustall/%.o: $(SRC_DIR)/collectors/eustall/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(DRIVER_HELPERS_DIR) -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -c $< -o $@

$(SRC_DIR)/printers/debug/%.o: $(SRC_DIR)/printers/debug/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(DRIVER_HELPERS_DIR) -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -c $< -o $@

$(SRC_DIR)/printers/stack/%.o: $(SRC_DIR)/printers/stack/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -c $< -o $@

$(SRC_DIR)/printers/interval/%.o: $(SRC_DIR)/printers/interval/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(DRIVER_HELPERS_DIR) -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -c $< -o $@

$(SRC_DIR)/utils/utils.o: $(SRC_DIR)/utils/utils.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/utils/array.o: $(SRC_DIR)/utils/array.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(DEMANGLE):
	$(CXX) $(CFLAGS) $(CONFIG_CFLAGS) $(shell $(LLVM_CONFIG) --cppflags) -I$(SRC_DIR) -c $(SRC_DIR)/utils/demangle.cpp -o $@

$(SRC_DIR)/gpu_parsers/%.o: $(SRC_DIR)/gpu_parsers/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/igc/include -c $< -o $@

$(SRC_DIR)/commands/%.o: $(SRC_DIR)/commands/%.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(DRIVER_HELPERS_DIR) -I$(PREFIX)/libbpf/include -I$(PREFIX)/igc/include -c $< -o $@

$(SRC_DIR)/iaprof.o: $(SRC_DIR)/iaprof.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(DRIVER_HELPERS_DIR) -c $< -o $@

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
	@if [ -e /sys/kernel/btf/drm ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/drm format c > $@; \
	fi;

$(MAIN_SKEL_H): $(BPF_DIR)/main.bpf.o
	$(BPFTOOL) gen skeleton $(BPF_DIR)/main.bpf.o > $@

$(DRIVER_HELPERS_DIR)/xe_helpers.o: $(DRIVER_HELPERS_DIR)/xe_helpers.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(SRC_DIR)/driver_helpers -c $< -o $@

$(DRIVER_HELPERS_DIR)/i915_helpers.o: $(DRIVER_HELPERS_DIR)/i915_helpers.c $(DRIVER_HELPERS_INCL)
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) -I$(SRC_DIR) -I$(PREFIX)/../kernel_headers -I$(SRC_DIR)/driver_helpers -c $< -o $@

$(BPF_PROG_O): $(DRIVER_HELPERS_INCL) $(VMLINUX_H) $(DRIVER_H) $(DRM_H)
	$(CC) $(BPF_CFLAGS) $(CONFIG_CFLAGS) -target bpf -D__TARGET_ARCH_x86 -g -v -Wno-pass-failed -I$(GENERATED_HEADERS_DIR) -I$(BPF_DIR) -I$(SRC_DIR) -I$(PREFIX)/libbpf/include -c $(BPF_DIR)/main.bpf.c -o $@

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

save_config:
	@echo "GPU_PLATFORM=$(GPU_PLATFORM)" > $(SRC_DIR)/../config.env
	@echo "GPU_DRIVER=$(GPU_DRIVER)" >> $(SRC_DIR)/../config.env
	@echo "KERNEL_LAUNCH_COLLECTOR=$(KERNEL_LAUNCH_COLLECTOR)" >> $(SRC_DIR)/../config.env
	@echo "Configuration saved to config.env"

clean:
	rm -f $(OBJECTS) $(SRC_DIR)/../iaprof
	rm -f $(OBJECTS) $(SRC_DIR)/../config.env
	rm -rf $(SRC_DIR)/driver_helpers/drm
	rm -rf $(GENERATED_HEADERS_DIR)
	rm -f $(MAIN_SKEL_H) $(VMLINUX_H) $(DRIVER_H) $(DRM_H)
	rm -f $(BPF_PROG_O)
