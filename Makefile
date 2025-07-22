# Kernel Debug Tracer Module Makefile
# SPDX-License-Identifier: GPL-2.0

obj-m += kernel_debug_tracer.o

# Core module objects
kernel_debug_tracer-objs := main.o \
                           breakpoint_manager.o \
                           symbol_resolver.o \
                           kprobe_handler.o \
                           call_stack_tracer.o \
                           variable_extractor.o \
                           data_collector.o \
                           debugfs_interface.o

# Kernel build directory - adjust as needed
# For local development (outside Docker)
KDIR ?= /lib/modules/$(shell uname -r)/build

# For Docker environment with RISC-V64 cross compilation
ifdef CROSS_COMPILE
    KDIR = ../linux
    ARCH = riscv
    export ARCH CROSS_COMPILE
endif

# Auto-detect Docker environment
ifneq ($(wildcard ../linux/Makefile),)
    KDIR = ../linux
    ARCH ?= riscv
    CROSS_COMPILE ?= riscv64-unknown-linux-gnu-
    export ARCH CROSS_COMPILE
endif

# Use compiled kernel if available
ifneq ($(wildcard ../output/current/build/linux-local/Makefile),)
    KDIR = ../output/current/build/linux-local
    ARCH ?= riscv
    CROSS_COMPILE ?= riscv64-unknown-linux-gnu-
    export ARCH CROSS_COMPILE
endif

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

# Development targets
debug:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="-DDEBUG -g"

help:
	@echo "Available targets:"
	@echo "  all     - Build the kernel module"
	@echo "  clean   - Clean build files"
	@echo "  install - Install the module"
	@echo "  debug   - Build with debug symbols"
	@echo "  riscv   - Build for RISC-V64 (cross-compile)"
	@echo "  prepare - Prepare kernel for module compilation"
	@echo "  info    - Show build configuration"
	@echo "  help    - Show this help"
	@echo ""
	@echo "Environment:"
	@echo "  KDIR=$(KDIR)"
	@echo "  ARCH=$(ARCH)"
	@echo "  CROSS_COMPILE=$(CROSS_COMPILE)"

# RISC-V64 specific target
riscv:
	$(MAKE) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- KDIR=$(KDIR) -C $(KDIR) M=$(PWD) modules \
		EXTRA_CFLAGS="-Wno-error" \
		CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO=n \
		CONFIG_STACKPROTECTOR_PER_TASK=n

# Show build configuration
info:
	@echo "Build Configuration:"
	@echo "  Kernel Directory: $(KDIR)"
	@echo "  Architecture: $(ARCH)"
	@echo "  Cross Compiler: $(CROSS_COMPILE)"
	@echo "  PWD: $(PWD)"
	@echo "  Module Objects: $(kernel_debug_tracer-objs)"

# Prepare kernel for module compilation (Docker environment)
prepare:
ifneq ($(wildcard ../linux/Makefile),)
	@echo "Preparing kernel for module compilation..."
	@if [ ! -f "../linux/.config" ]; then \
		echo "Creating default RISC-V configuration..."; \
		$(MAKE) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -C ../linux defconfig; \
	fi
	@echo "Preparing kernel headers and build files..."
	$(MAKE) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -C ../linux prepare
	@if [ ! -f "../linux/Module.symvers" ]; then \
		echo "Generating Module.symvers..."; \
		$(MAKE) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -C ../linux modules_prepare; \
	fi
	@echo "Kernel preparation completed"
else
	@echo "Not in Docker environment, kernel preparation not needed"
endif

.PHONY: all clean install debug riscv info help prepare