.PHONY: all bpftool elfutils igc kernel_headers clean

ROOT_DIR := $(shell pwd)
PREFIX := $(ROOT_DIR)/install

# Get the running kernel headers by default.
KERNEL_SRC := /lib/modules/$(shell uname -r)/build/include/uapi
KERNEL_HEADERS_DIR := $(ROOT_DIR)/kernel_headers

all: bpftool elfutils igc kernel_headers

bpftool: $(PREFIX)/bpftool/bin/bpftool $(PREFIX)/bpftool/lib/libbpf.a $(PREFIX)/libbpf/include

$(PREFIX)/bpftool/bin/bpftool:
	$(MAKE) -C bpftool/src bpftool
	mkdir -vp $(shell dirname $@)
	cp bpftool/src/bpftool $@

$(PREFIX)/bpftool/lib/libbpf.a:
	$(MAKE) -C bpftool/libbpf/src
	mkdir -vp $(shell dirname $@)
	cp bpftool/libbpf/src/libbpf.a $@

$(PREFIX)/libbpf/include:
	mkdir -p $(PREFIX)/libbpf/include
	cp -R bpftool/src/libbpf/include/bpf $(PREFIX)/libbpf/include

elfutils: $(PREFIX)/libelf/lib/libelf.a

$(PREFIX)/libelf/lib/libelf.a:
	cd elfutils && autoreconf -i -f && ./configure --enable-maintainer-mode --prefix=$(PREFIX)/libelf
	$(MAKE) -C elfutils
	$(MAKE) -C elfutils install

igc: $(PREFIX)/igc/lib/libiga64.a

$(PREFIX)/igc/lib/libiga64.a:
	$(MAKE) -C igc PREFIX=$(PREFIX)

kernel_headers:
	@if [ -d "$(KERNEL_SRC)" ]; then \
		if [ ! -d "$(KERNEL_HEADERS_DIR)/uapi" ]; then \
			echo "Copying kernel headers from $(KERNEL_SRC) to $(KERNEL_HEADERS_DIR)..."; \
			mkdir -p $(KERNEL_HEADERS_DIR); \
			cp -r $(KERNEL_SRC)/ $(KERNEL_HEADERS_DIR)/; \
			echo "Kernel headers copied successfully."; \
		fi \
	else \
		echo "Error: Kernel headers source directory $(KERNEL_SRC) does not exist."; \
		exit 1; \
	fi

clean_bpftool:
	$(MAKE) -C bpftool/src clean
	rm -f $(PREFIX)/bpftool/bin/bpftool
	rm -f $(PREFIX)/bpftool/lib/libbpf.a
	rm -rf $(PREFIX)/libbpf/include

clean_elfutils:
	@set -x
	if [ -f elfutils/Makefile ]; then \
	  make -C elfutils clean; \
	fi; \
	rm -rf $(PREFIX)/libelf;

clean_igc:
	make -C igc clean

clean_kernel_headers:
	rm -rf $(KERNEL_HEADERS_DIR)

clean: clean_bpftool clean_elfutils clean_igc clean_kernel_headers
