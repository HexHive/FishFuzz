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

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
    apt install git gcc g++ make cmake wget \
        libgmp-dev libmpfr-dev texinfo bison python3 -y 

# for runtime library, we just need libc++-12-dev libc++abi-12-dev
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key|apt-key add - && \
    printf  "deb http://apt.llvm.org/focal/ llvm-toolchain-focal main\n" \
            "deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal main\n" \
            "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-12 main\n" \
            "deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-12 main\n" \
          >> /etc/apt/sources.list && \
    apt update && \
    apt install libc++-12-dev libc++abi-12-dev -y



# for FF runtime
RUN apt-get update && \
    apt-get install libboost-all-dev libjsoncpp-dev libgraphviz-dev pkg-config libglib2.0-dev libunwind-17 -y