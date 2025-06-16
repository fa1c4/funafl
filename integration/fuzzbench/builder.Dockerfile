# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG parent_image
FROM $parent_image

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        python3-dev \
        python3-setuptools \
        automake \
        cmake \
        git \
        flex \
        bison \
        libglib2.0-dev \
        libpixman-1-dev \
        cargo \
        libgtk-3-dev \
        # for QEMU mode
        ninja-build \
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
        libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

# copy local aicfg into docker 
COPY aicfg /out/aicfg

# Download afl++.
# RUN git clone -b dev https://github.com/AFLplusplus/AFLplusplus /afl && \
#     cd /afl && \
#     git checkout 56d5aa3101945e81519a3fac8783d0d8fad82779 || \
#     true

# Download funafl & checkout v0.98
RUN git clone -b main https://github.com/fa1c4/funafl.git /afl && \
    cd /afl && \
    git checkout 720865790f808ef7dc2cba03eccc9a85fbdb4e78

RUN echo "Installing dependencies..." && \
    apt-get update && \
    # apt-get install -y lld-15 llvm-15 llvm-15-dev clang-15 && \
    apt-get install -y cpio libcapstone-dev && \
    apt-get install -y wget curl && \
    apt-get install -y python3-pip

# RUN echo "update alternatives..." && \
#     update-alternatives --install /usr/bin/lld lld /usr/bin/lld-15 100 && \
#     update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/ld.lld-15 100 && \
#     update-alternatives --install /usr/bin/wasm-ld wasm-ld /usr/bin/wasm-ld-15 100 && \
#     update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-15 100 && \
#     update-alternatives --install /usr/bin/llc llc /usr/bin/llc-15 100 && \
#     update-alternatives --install /usr/bin/opt opt /usr/bin/opt-15 100 && \
#     update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-15 100 && \
#     update-alternatives --install /usr/bin/llvm-as llvm-as /usr/bin/llvm-as-15 100 && \
#     update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100 && \
#     update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-15 100 && \
#     update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-15 100 && \
#     update-alternatives --install /usr/bin/llvm-nm llvm-nm /usr/bin/llvm-nm-15 100 && \
#     update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-15 100 && \
#     update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-15 100

RUN llvm-config --version && \
    clang --version && \
    lld --version || true
# (echo "Command failed, entering container..."; /bin/bash)

# Build without Python support as we don't need it.
# Set AFL_NO_X86 to skip flaky tests.
RUN cd /afl && \
    make clean && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang AFL_NO_X86=1 && \
    PYTHON_INCLUDE=/ make && \
    cp utils/aflpp_driver/libAFLDriver.a /
