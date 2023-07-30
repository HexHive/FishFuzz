FROM ubuntu:20.04

# for binutils & llvm-12 dependencies
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
    apt install git gcc g++ make cmake wget \
        libgmp-dev libmpfr-dev texinfo bison python3 -y 

# build clang-12 with gold plugin
RUN mkdir -p /build && \
    git clone \
         --depth 1 \
         --branch release/12.x \
        https://github.com/llvm/llvm-project /llvm && \
    git clone \
        --depth 1 \
        --branch binutils-2_40-branch \
        git://sourceware.org/git/binutils-gdb.git /llvm/binutils && \
    mkdir /llvm/binutils/build && cd /llvm/binutils/build && \
        CFLAGS="" CXXFLAGS="" CC=gcc CXX=g++ \
        ../configure --enable-gold --enable-plugins --disable-werror && \
        make all-gold -j$(nproc) && \
    cd /llvm/ && mkdir build && cd build &&\
    CFLAGS="" CXXFLAGS="" CC=gcc CXX=g++ \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DLLVM_BINUTILS_INCDIR=/llvm/binutils/include \
          -DLLVM_ENABLE_PROJECTS="compiler-rt;clang" \
          -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" ../llvm && \
    make -j$(nproc) && \
    cp /llvm/build/lib/LLVMgold.so //usr/lib/bfd-plugins/ && \
    cp /llvm/build/lib/libLTO.so //usr/lib/bfd-plugins/

ENV PATH="/llvm/build/bin:${PATH}"
ENV LD_LIBRARY_PATH="/llvm/build/lib/x86_64-unknown-linux-gnu/c++/:${LD_LIBRARY_PATH}"


# for fishfuzz dependencies
RUN apt-get update && \
    apt-get install libboost-all-dev libjsoncpp-dev libgraphviz-dev pkg-config libglib2.0-dev -y

# build FF_AFL
# COPY FF_AFL /FishFuzz 
RUN  git clone https://github.com/HexHive/FishFuzz /ff_repo && \
     cd /ff_repo && git checkout 88735f0a218baa0bbce40a89cc8910fde1c50c1a && \
    mv /ff_repo/FF_AFL /FishFuzz && mv /ff_repo/FF_AFL++ /Fish++ && \
    # mv $(find /ff_repo/paper/two-stage -type d -name build) /build_script && \
    rm -r /ff_repo

COPY build/ /build_script


RUN  cd /FishFuzz/ && \
     unset CFLAGS CXXFLAGS && \
     make -C llvm_mode && \
     CC=gcc CXX=g++ make -C dyncfg && \
     CC=gcc CXX=g++ AFL_NO_X86=1 make && \
     chmod +x scripts/*.py 

# build FF_AFL++
# COPY FF_AFL++ /Fish++
RUN  cd /Fish++ && \
    unset CFLAGS CXXFLAGS && \
    export CC=gcc AFL_NO_X86=1 && \
    make clean && \
    rm -f ff-all-in-one ff-all-in-one++ && \
    PYTHON_INCLUDE=/ make && \
    make -C dyncfg && chmod +x scripts/*.py 

# build AFL++
RUN git clone https://github.com/AFLplusplus/AFLplusplus /AFL++ && \
    cd /AFL++ && git checkout 4.00c && \
    NO_NYX=1 make source-only -j

# build AFL
RUN git clone https://github.com/google/afl /AFL && \
    cd /AFL && git checkout v2.57b && \
    # ugly patch to add timestamp
    sed -i 's/id\:%06u\,%s/id\:%06u\,%s,%lld/g' `ls afl-fuzz.c` && \
    sed -i 's/id\:%06llu,%s/id\:%06llu,%s\,%lld/g' `ls afl-fuzz.c` && \
    sed -i 's/id\:%06llu\,sig\:%02u\,%s/id\:%06llu\,sig\:%02u\,%s\,%lld/g' `ls afl-fuzz.c` && \
    sed -i 's/describe_op(0)/describe_op(0), get_cur_time() - start_time/g' `ls afl-fuzz.c` && \
    sed -i 's/describe_op(hnb)/describe_op(hnb), get_cur_time() - start_time/g' `ls afl-fuzz.c` && \
    make -j && make -C llvm_mode

# prepare source package
RUN mkdir -p /benchmark/source/ /binary/afl \
    /binary/aflpp /binary/ffafl /binary/ffapp /binary/neutral && \
    cd /benchmark/source/ && \
    wget https://ftp.gnu.org/gnu/cflow/cflow-1.6.tar.gz && \
    wget https://ftp.gnu.org/gnu/binutils/binutils-2.30.tar.gz && \
    git clone https://github.com/davea42/libdwarf-code \
        --depth 1 --branch 20190529 /benchmark/source/libdwarf-20190529 && \
    wget https://mujs.com/downloads/mujs-1.0.2.tar.gz && \
    wget https://mupdf.com/downloads/archive/mupdf-1.12.0-source.tar.gz && \
    wget https://ftp.gnu.org/gnu/ncurses/ncurses-6.2.tar.gz && \
    git clone https://github.com/tats/w3m \
    --depth 1 --branch v0.5.3+git20220429 /benchmark/source/w3m-v0.5.3+git20220429 

# package requirement for the w3m and mupdf
RUN apt update && apt install -y libgc-dev libreadline-dev \
    mesa-common-dev libglu1-mesa-dev freeglut3-dev libxrandr-dev libxi-dev \
    cron 

# for analysis
RUN apt update && apt install python3-pip -y && pip3 install progress

# build all
# COPY build /build_script

RUN chmod +x /build_script/*.sh 

RUN /build_script/cflow.sh 

RUN /build_script/cxxfilt.sh 

RUN /build_script/dwarfdump.sh 

RUN /build_script/mujs.sh

RUN /build_script/mupdf.sh 

RUN /build_script/tic.sh 

RUN /build_script/w3m.sh 
