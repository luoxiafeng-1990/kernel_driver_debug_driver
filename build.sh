#!/bin/bash
# Simple build script for kernel debug tracer module

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Build the module
build_module() {
    # Check for compiled kernel first
    if [ -d "../output/current/build/linux-local" ] && [ -f "../output/current/build/linux-local/Makefile" ]; then
        echo_info "Building module with compiled kernel..."
        make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- KDIR=../output/current/build/linux-local -C ../output/current/build/linux-local M=$(pwd) modules
    elif [ -d "../linux" ] && [ -f "../linux/Makefile" ]; then
        echo_info "Building module with kernel source..."
        make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- KDIR=../linux -C ../linux M=$(pwd) modules
    elif [ -d "/lib/modules/$(uname -r)/build" ]; then
        echo_info "Building module locally..."
        make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
    else
        echo_error "Cannot find kernel build directory"
        echo_error "Checked:"
        echo_error "  - ../output/current/build/linux-local"
        echo_error "  - ../linux"
        echo_error "  - /lib/modules/$(uname -r)/build"
        exit 1
    fi
    
    if [ $? -eq 0 ]; then
        echo_info "Build completed successfully!"
        ls -la *.ko 2>/dev/null || echo "No .ko files found"
    else
        echo_error "Build failed!"
        exit 1
    fi
}

# Clean build artifacts
clean_build() {
    echo_info "Cleaning build artifacts..."
    if [ -d "../output/current/build/linux-local" ]; then
        make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- KDIR=../output/current/build/linux-local -C ../output/current/build/linux-local M=$(pwd) clean
    elif [ -d "../linux" ]; then
        make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- KDIR=../linux -C ../linux M=$(pwd) clean
    else
        make -C /lib/modules/$(uname -r)/build M=$(pwd) clean
    fi
    echo_info "Clean completed"
}

# Prepare kernel (only when explicitly requested)
prepare_kernel() {
    if [ -d "../linux" ] && [ -f "../linux/Makefile" ]; then
        echo_info "Preparing kernel for module compilation..."
        make -C ../linux ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- defconfig
        make -C ../linux ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- prepare
        echo_info "Kernel preparation completed"
    else
        echo_info "Not in Docker environment, kernel preparation not needed"
    fi
}

# Main script
case "${1:-build}" in
    "build"|"")
        build_module
        ;;
    "clean")
        clean_build
        ;;
    "prepare")
        prepare_kernel
        ;;
    "help")
        echo "Usage: $0 [command]"
        echo "Commands:"
        echo "  build   - Build the kernel module (default)"
        echo "  clean   - Clean build artifacts"
        echo "  prepare - Prepare kernel for module compilation"
        echo "  help    - Show this help"
        ;;
    *)
        echo_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac