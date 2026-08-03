PROJECT_NAME := ebpf-file-access-filter

SRC_DIR ?= src

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(CURDIR)/../build
INCLUDE_DIR := $(CURDIR)/../include

CC := clang
CFLAGS := -Wall -Wextra -Werror -Isrc -I/usr/include/$(uname -m)-linux-gnu -I$(INCLUDE_DIR)

BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

.PHONY: all clean

all: $(BUILD_DIR)/include/faf/skel.h

$(BUILD_DIR)/include/faf/skel.h: $(BUILD_DIR)/faf.bpf.o
	mkdir -p $(BUILD_DIR)/include/faf
	bpftool gen skeleton $(BUILD_DIR)/faf.bpf.o > $@

$(BUILD_DIR)/faf.bpf.o: $(SRC_DIR)/vmlinux.h
	mkdir -p $(BUILD_DIR)
# 	$(CC) $(CFLAGS) -target bpf -O2 -g -c $(SRC_DIR)/lsm.bpf.c -o $@
	$(CC) $(CFLAGS) -target bpf -O2 -g -c $(SRC_DIR)/fmod_ret.bpf.c -o $@

$(SRC_DIR)/vmlinux.h:
	@if [ -f "$(VMLINUX_BTF)" ]; then \
		echo "Generating vmlinux.h from kernel..."; \
		$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@; \
	else \
		echo "ERROR: Local BTF not found. Exitting..."; \
		exit; \
	fi

clean:
	rm -rf $(BUILD_DIR)
	rm -f vmlinux.h