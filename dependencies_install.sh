#!/bin/bash

# FunAFL dependencies installation script
# notice: install libgtk-3-dev may cause some issues with gnome of ubuntu 22.04, which use gtk4. 
# ignore this package if you are using ubuntu 22.04 or later. 

for arg in "$@"; do
    case "$arg" in
        -h|--help)
            echo "Usage: $0 [--install] to install dependencies"
            echo "Usage: $0 [--alt] to install llvm-15 dependencies as alternatives"
            exit 0
            ;;
        --alt)
            echo "update alternatives..."
            sudo update-alternatives --install /usr/bin/lld lld /usr/bin/lld-15 100
            sudo update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/ld.lld-15 100
            sudo update-alternatives --install /usr/bin/wasm-ld wasm-ld /usr/bin/wasm-ld-15 100

            sudo update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-15 100
            sudo update-alternatives --install /usr/bin/llc llc /usr/bin/llc-15 100
            sudo update-alternatives --install /usr/bin/opt opt /usr/bin/opt-15 100
            sudo update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-15 100
            sudo update-alternatives --install /usr/bin/llvm-as llvm-as /usr/bin/llvm-as-15 100

            sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100
            sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-15 100
            # sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-15 100
            # sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-15 100

            sudo update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-15 100
            sudo update-alternatives --install /usr/bin/llvm-nm llvm-nm /usr/bin/llvm-nm-15 100
            sudo update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-15 100
            sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-15 100

            llvm-config --version   # should show 15.x.x
            clang --version         # should show clang 15
            lld --version
            ;;
        --install)
            echo "Installing dependencies..."
            sudo apt-get update
            sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo
            # sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev

            sudo apt-get install -y lld-15 llvm-15 llvm-15-dev clang-15
            sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
            sudo apt-get install -y ninja-build # for QEMU mode
            sudo apt-get install -y cpio libcapstone-dev # for Nyx mode
            sudo apt-get install -y wget curl # for Frida mode
            sudo apt-get install -y python3-pip # for Unicorn mode
            ;;
        *)
            echo "Invalid option: $arg"
            echo "Usage: $0 [--install] to install dependencies"
            echo "Usage: $0 [--alt] to install llvm-15 dependencies as alternatives"
            exit 1
            ;;
    esac
done
