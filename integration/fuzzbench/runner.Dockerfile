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

FROM gcr.io/fuzzbench/base-image

# This makes interactive docker runs painless:
ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/out"
#ENV AFL_MAP_SIZE=2621440
ENV PATH="$PATH:/out"
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
ENV AFL_TESTCACHE_SIZE=2
# RUN apt-get update && apt-get upgrade && apt install -y unzip git gdb joe

# [PATH beta] install python3.10 libraries
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

# clone the funafl source code for custom_mutator module [version: 0.999] 
RUN git clone -b main https://github.com/fa1c4/funafl.git /afl && \
    cd /afl && \
    git checkout 0900477b61957967b9161fbf3cb8eeecbb582b7c

RUN cd /tmp && \
    wget https://www.python.org/ftp/python/3.10.8/Python-3.10.8.tgz && \
    tar xzf Python-3.10.8.tgz && \
    cd Python-3.10.8 && \
    ./configure --enable-optimizations --enable-shared --with-ensurepip=install --prefix=/opt/python3.10.8 && \
    make -j$(nproc) && \
    make altinstall && \
    cp /opt/python3.10.8/lib/libpython3.10.so.1.0 /usr/local/lib/ && \
    cp /opt/python3.10.8/lib/libpython3.10.so /usr/local/lib/ && \
    ldconfig
