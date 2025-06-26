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

RUN echo "Installing dependencies..." && \
    apt-get update && \
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
        ninja-build \
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
        libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev \
        wget \
        curl \
        cpio \
        libcapstone-dev

# install python3.10.8
RUN cd /tmp && \
    wget https://www.python.org/ftp/python/3.10.8/Python-3.10.8.tgz && \
    tar xzf Python-3.10.8.tgz && \
    cd Python-3.10.8 && \
    ./configure --enable-optimizations --enable-shared --with-ensurepip=install && \
    make -j$(nproc) && \
    make altinstall && \
    ldconfig && \
    # Create symlinks for python3 and python3-config
    ln -sf /usr/local/bin/python3.10 /usr/local/bin/python && \
    ln -sf /usr/local/bin/python3.10-config /usr/local/bin/python-config && \
    ln -sf /usr/local/bin/pip3.10 /usr/local/bin/pip && \
    ln -sf /usr/local/bin/python3.10 /usr/local/bin/python3 && \
    ln -sf /usr/local/bin/python3.10-config /usr/local/bin/python3-config && \
    ln -sf /usr/local/bin/pip3.10 /usr/local/bin/pip3
    # Update PATH to prioritize our Python installation
    # echo 'export PATH="/usr/local/bin:$PATH"' >> /etc/bash.bashrc && \

# Verify Python installation
RUN python --version && \
    python-config --cflags && \
    python-config --ldflags

# copy local aicfg into docker 
COPY aicfg /out/aicfg

# Download funafl & checkout [version 0.999]
RUN git clone -b main https://github.com/fa1c4/funafl.git /afl && \
    cd /afl && \
    git checkout 0900477b61957967b9161fbf3cb8eeecbb582b7c

RUN llvm-config --version && clang --version && lld --version || true

# enable python support
RUN cd /afl && \
    make clean && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang AFL_NO_X86=1 && \
    make && \
    cp utils/aflpp_driver/libAFLDriver.a /

# check python support or exit
RUN cd /afl && ./afl-fuzz 2>&1 | grep -i python || sh -c 'echo "Warning: Python support check failed" && exit 1'
