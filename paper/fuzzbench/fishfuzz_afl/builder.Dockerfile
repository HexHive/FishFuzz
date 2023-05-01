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

# Download and compile AFL v2.57b.
# Set AFL_NO_X86 to skip flaky tests.
# RUN git clone \
#         --depth 1 \
#         --branch v2.57b \
#         https://github.com/google/AFL.git /afl && \
#     cd /afl && \
#     CFLAGS= CXXFLAGS= AFL_NO_X86=1 make

# if we start from empty image
# FROM ubuntu:20.04

# for binutils & llvm-12 dependencies
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
    apt install git gcc g++ make cmake wget \
        libgmp-dev libmpfr-dev texinfo bison python3 -y 

# manually build clang-12 with gold plugin
# RUN mkdir -p /build && \
#     git clone \
#          --depth 1 \
#          --branch release/12.x \
#         https://github.com/llvm/llvm-project /llvm && \
#     git clone \
#         --depth 1 \
#         --branch binutils-2_40-branch \
#         git://sourceware.org/git/binutils-gdb.git /llvm/binutils && \
#     mkdir /llvm/binutils/build && cd /llvm/binutils/build && \
#         CFLAGS="" CXXFLAGS="" CC=gcc CXX=g++ \
#         ../configure --enable-gold --enable-plugins --disable-werror && \
#         make all-gold -j$(nproc) && \
#     cd /llvm/ && mkdir build && cd build &&\
#     CFLAGS="" CXXFLAGS="" CC=gcc CXX=g++ \
#     cmake -DCMAKE_BUILD_TYPE=Release \
#           -DLLVM_BINUTILS_INCDIR=/llvm/binutils/include \
#           -DLLVM_ENABLE_PROJECTS="compiler-rt;clang" \
#           -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" ../llvm && \
#     make -j$(nproc) && \
#     cp /llvm/build/lib/LLVMgold.so //usr/lib/bfd-plugins/ && \
#     cp /llvm/build/lib/libLTO.so //usr/lib/bfd-plugins/

# ENV PATH="/llvm/build/bin:${PATH}"
# ENV LD_LIBRARY_PATH="/llvm/build/lib/x86_64-unknown-linux-gnu/c++/:${LD_LIBRARY_PATH}"

# copied from aflpp script, build clang-12 + gold automatically

RUN apt install -y lsb-release wget software-properties-common && wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 12 all && \
    cp /usr/lib/llvm-12/lib/LLVMgold.so //usr/lib/bfd-plugins/ && \
    cp /usr/lib/llvm-12/lib/libLTO.so //usr/lib/bfd-plugins/


RUN update-alternatives \
      --install /usr/lib/llvm              llvm             /usr/lib/llvm-12  100 \
      --slave   /usr/bin/llvm-config       llvm-config      /usr/bin/llvm-config-12  \
        --slave   /usr/bin/llvm-ar           llvm-ar          /usr/bin/llvm-ar-12 \
        --slave   /usr/bin/llvm-as           llvm-as          /usr/bin/llvm-as-12 \
        --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer  /usr/bin/llvm-bcanalyzer-12 \
        --slave   /usr/bin/llvm-c-test       llvm-c-test      /usr/bin/llvm-c-test-12 \
        --slave   /usr/bin/llvm-cov          llvm-cov         /usr/bin/llvm-cov-12 \
        --slave   /usr/bin/llvm-diff         llvm-diff        /usr/bin/llvm-diff-12 \
        --slave   /usr/bin/llvm-dis          llvm-dis         /usr/bin/llvm-dis-12 \
        --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump   /usr/bin/llvm-dwarfdump-12 \
        --slave   /usr/bin/llvm-extract      llvm-extract     /usr/bin/llvm-extract-12 \
        --slave   /usr/bin/llvm-link         llvm-link        /usr/bin/llvm-link-12 \
        --slave   /usr/bin/llvm-mc           llvm-mc          /usr/bin/llvm-mc-12 \
        --slave   /usr/bin/llvm-nm           llvm-nm          /usr/bin/llvm-nm-12 \
        --slave   /usr/bin/llvm-objdump      llvm-objdump     /usr/bin/llvm-objdump-12 \
        --slave   /usr/bin/llvm-ranlib       llvm-ranlib      /usr/bin/llvm-ranlib-12 \
        --slave   /usr/bin/llvm-readobj      llvm-readobj     /usr/bin/llvm-readobj-12 \
        --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld      /usr/bin/llvm-rtdyld-12 \
        --slave   /usr/bin/llvm-size         llvm-size        /usr/bin/llvm-size-12 \
        --slave   /usr/bin/llvm-stress       llvm-stress      /usr/bin/llvm-stress-12 \
        --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer  /usr/bin/llvm-symbolizer-12 \
        --slave   /usr/bin/llvm-tblgen       llvm-tblgen      /usr/bin/llvm-tblgen-12 \
        --slave   /usr/bin/llc               llc              /usr/bin/llc-12 \
        --slave   /usr/bin/opt               opt              /usr/bin/opt-12 && \
    update-alternatives \
      --install /usr/bin/clang                 clang                  /usr/bin/clang-12     100 \
      --slave   /usr/bin/clang++               clang++                /usr/bin/clang++-12 \
      --slave   /usr/bin/clang-cpp             clang-cpp              /usr/bin/clang-cpp-12

# put the /usr/bin of the highest priority, to make sure clang-12 is called before clang-15, which is in /usr/local/bin
ENV PATH="/usr/bin:${PATH}"

# for fishfuzz dependencies
RUN apt-get update && \
    apt-get install libboost-all-dev libjsoncpp-dev libgraphviz-dev pkg-config libglib2.0-dev -y

COPY FishFuzz /FishFuzz 
RUN  cd /FishFuzz/ && \
     CFLAGS="" CXXFLAGS="" make -C llvm_mode && \
     CFLAGS="" CXXFLAGS="" CC=gcc CXX=g++ make -C dyncfg && \
     CFLAGS="" CXXFLAGS="" CC=gcc CXX=g++ AFL_NO_X86=1 make 

# Use afl_driver.cpp from LLVM as our fuzzing library.
RUN wget https://raw.githubusercontent.com/llvm/llvm-project/5feb80e748924606531ba28c97fe65145c65372e/compiler-rt/lib/fuzzer/afl/afl_driver.cpp -O /FishFuzz/afl_driver.cpp && \
    clang++ -stdlib=libc++ -std=c++11 -O2 -c /FishFuzz/afl_driver.cpp -o /FishFuzz/afl_driver.o && \
    ar r /libAFL.a /FishFuzz/afl_driver.o /FishFuzz/afl-llvm-rt.o
