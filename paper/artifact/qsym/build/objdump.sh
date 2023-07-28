#!/bin/bash

export FF_DRIVER_NAME=objdump
export SRC_DIR=/benchmark/binutils-2.31
export __FF_ONLY_UBSAN=1
export USE_UBSAN_LABEL=1

tar xzf /benchmark/source/binutils-2.31.tar.gz -C /benchmark

export FUZZ_DIR=/binary/ffafl

# step 1, generating .bc file, you can use wllvm or similar approach as you wish
export CC="clang" 
export CFLAGS="-fsanitize=integer,bounds,shift -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps -Wno-unused-command-line-argument"
export CXX="clang++" 
export CXXFLAGS="-fsanitize=integer,bounds,shift -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps -Wno-unused-command-line-argument"

cd $SRC_DIR && ./configure --disable-shared && make -j$(nproc)

# step 2, coverage instrumentation and analysis
export PREFUZZ=/FishFuzz/
export TMP_DIR=$PWD/TEMP_$FF_DRIVER_NAME
export ADDITIONAL_COV="-load $PREFUZZ/afl-llvm-pass.so -test -outdir=$TMP_DIR -pmode=conly"
export ADDITIONAL_ANALYSIS="-load $PREFUZZ/afl-llvm-pass.so -test -outdir=$TMP_DIR -pmode=aonly"
export BC_PATH=$(find . -name "$FF_DRIVER_NAME.0.5.precodegen.bc" -printf "%h\n")/
mkdir -p $TMP_DIR
opt $ADDITIONAL_COV $BC_PATH$FF_DRIVER_NAME.0.5.precodegen.bc -o $BC_PATH$FF_DRIVER_NAME.final.bc 
opt $ADDITIONAL_ANALYSIS $BC_PATH$FF_DRIVER_NAME.final.bc -o $BC_PATH$FF_DRIVER_NAME.temp.bc

# step 3, static distance map calculation
opt -dot-callgraph $BC_PATH$FF_DRIVER_NAME.0.5.precodegen.bc && mv $BC_PATH$FF_DRIVER_NAME.0.5.precodegen.bc.callgraph.dot $TMP_DIR/dot-files/callgraph.dot
$PREFUZZ/scripts/gen_initial_distance.py $TMP_DIR

# step 4, generating final target
export ADDITIONAL_FUNC="-pmode=fonly -funcid=$TMP_DIR/funcid.csv -outdir=$TMP_DIR"
export CC=$PREFUZZ/afl-clang-fast
export CXX=$PREFUZZ/afl-clang-fast++
export EXTRA_LDFLAGS="-ldl -lpthread -lrt -lm"
$CC $ADDITIONAL_FUNC -fsanitize=integer,bounds,shift $BC_PATH$FF_DRIVER_NAME.final.bc -o $FF_DRIVER_NAME.fuzz $EXTRA_LDFLAGS 

mv $TMP_DIR $FUZZ_DIR/
mv $FF_DRIVER_NAME.fuzz $FUZZ_DIR/$FF_DRIVER_NAME


unset CFLAGS CXXFLAGS

# build afl binary
cd && rm -r $SRC_DIR/ && tar xzf /benchmark/source/binutils-2.31.tar.gz -C /benchmark

export FUZZ_DIR=/binary/afl
export CC="/AFL/afl-clang-fast -fsanitize=integer,bounds,shift"
export CXX="/AFL/afl-clang-fast++ -fsanitize=integer,bounds,shift"
cd $SRC_DIR && ./configure --disable-shared  && make -j$(nproc)
mv $(find . -type f -executable -name $FF_DRIVER_NAME -printf "%h\n")/$FF_DRIVER_NAME $FUZZ_DIR/

# build vanilla binary
cd && rm -r $SRC_DIR/ && tar xzf /benchmark/source/binutils-2.31.tar.gz -C /benchmark

export FUZZ_DIR=/binary/vanilla
export CC=gcc
export CXX=g++
cd $SRC_DIR && ./configure --disable-shared  && make -j$(nproc)
mv $(find . -type f -executable -name $FF_DRIVER_NAME -printf "%h\n")/$FF_DRIVER_NAME $FUZZ_DIR/

