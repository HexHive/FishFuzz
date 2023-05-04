#!/bin/bash

export FF_DRIVER_NAME=cflow
export SRC_DIR=/benchmark/cflow-1.6

tar xzf /benchmark/source/cflow-1.6.tar.gz -C /benchmark

export FUZZ_DIR=/binary/ffafl

# step 1, generating .bc file, you can use wllvm or similar approach as you wish
export CC=clang 
export CFLAGS="-fsanitize=address -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps -Wno-unused-command-line-argument"
export CXX=clang++ 
export CXXFLAGS="-fsanitize=address -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps -Wno-unused-command-line-argument"
cd $SRC_DIR && ./configure --with-shared=no && make -j$(nproc)

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
export ASAN_LIBS=$(find `llvm-config --libdir` -name libclang_rt.asan-*.a |head -n 1)
export EXTRA_LDFLAGS="-ldl -lpthread -lrt -lm"
$CC $ADDITIONAL_FUNC $BC_PATH$FF_DRIVER_NAME.final.bc -o $FF_DRIVER_NAME.fuzz $EXTRA_LDFLAGS $ASAN_LIBS

mv $TMP_DIR $FUZZ_DIR/
mv $FF_DRIVER_NAME.fuzz $FUZZ_DIR/$FF_DRIVER_NAME


# Build ffapp binary

cd && rm -r $SRC_DIR/ && tar xzf /benchmark/source/cflow-1.6.tar.gz -C /benchmark
export FUZZ_DIR=/binary/ffapp

# step 1, generating .bc file, you can use wllvm or similar approach as you wish
export CC=clang 
export CFLAGS="-fsanitize=address -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps -Wno-unused-command-line-argument"
export CXX=clang++ 
export CXXFLAGS="-fsanitize=address -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps -Wno-unused-command-line-argument"
cd $SRC_DIR && ./configure --with-shared=no && make -j$(nproc)

# step 2, coverage instrumentation and analysis
export PREFUZZ=/Fish++/
export TMP_DIR=$PWD/TEMP_$FF_DRIVER_NAME
export ADDITIONAL_RENAME="-load $PREFUZZ/afl-fish-pass.so -test -outdir=$TMP_DIR -pmode=rename"
export ADDITIONAL_COV="-load $PREFUZZ/SanitizerCoveragePCGUARD.so -cov"
export ADDITIONAL_ANALYSIS="-load $PREFUZZ/afl-fish-pass.so -test -outdir=$TMP_DIR -pmode=aonly"
export BC_PATH=$(find . -name "$FF_DRIVER_NAME.0.5.precodegen.bc" -printf "%h\n")/
mkdir -p $TMP_DIR
opt $ADDITIONAL_RENAME $BC_PATH$FF_DRIVER_NAME.0.5.precodegen.bc -o $BC_PATH$FF_DRIVER_NAME.rename.bc 
opt $ADDITIONAL_COV $BC_PATH$FF_DRIVER_NAME.rename.bc -o $BC_PATH$FF_DRIVER_NAME.cov.bc 
opt $ADDITIONAL_ANALYSIS $BC_PATH$FF_DRIVER_NAME.rename.bc -o $BC_PATH$FF_DRIVER_NAME.temp.bc

# step 3, static distance map calculation
opt -dot-callgraph $BC_PATH$FF_DRIVER_NAME.0.5.precodegen.bc && mv $BC_PATH$FF_DRIVER_NAME.0.5.precodegen.bc.callgraph.dot $TMP_DIR/dot-files/callgraph.dot
$PREFUZZ/scripts/gen_initial_distance.py $TMP_DIR


# step 4, generating final target
export ADDITIONAL_FUNC="-pmode=fonly -funcid=$TMP_DIR/funcid.csv -outdir=$TMP_DIR"
export CC=$PREFUZZ/afl-fish-fast
export CXX=$PREFUZZ/afl-fish-fast++
export ASAN_LIBS=$(find `llvm-config --libdir` -name libclang_rt.asan-*.a |head -n 1)
export EXTRA_LDFLAGS="-ldl -lpthread -lrt -lm"
$CC $ADDITIONAL_FUNC $BC_PATH$FF_DRIVER_NAME.cov.bc -o $FF_DRIVER_NAME.fuzz $EXTRA_LDFLAGS $ASAN_LIBS

mv $TMP_DIR $FUZZ_DIR/
mv $FF_DRIVER_NAME.fuzz $FUZZ_DIR/$FF_DRIVER_NAME

unset CFLAGS CXXFLAGS

# build afl binary
cd && rm -r $SRC_DIR/ && tar xzf /benchmark/source/cflow-1.6.tar.gz -C /benchmark

export FUZZ_DIR=/binary/afl
export CC="/AFL/afl-clang-fast -fsanitize=address"
export CXX="/AFL/afl-clang-fast++ -fsanitize=address"
cd $SRC_DIR && ./configure --with-shared=no && make -j$(nproc)
mv $(find . -name $FF_DRIVER_NAME -printf "%h\n")/$FF_DRIVER_NAME $FUZZ_DIR/

# build afl++ binary
cd && rm -r $SRC_DIR/ && tar xzf /benchmark/source/cflow-1.6.tar.gz -C /benchmark

export FUZZ_DIR=/binary/aflpp
export CC="/AFL++/afl-clang-fast -fsanitize=address"
export CXX="/AFL++/afl-clang-fast++ -fsanitize=address"
cd $SRC_DIR && ./configure --with-shared=no && make -j$(nproc)
mv $(find . -name $FF_DRIVER_NAME -printf "%h\n")/$FF_DRIVER_NAME $FUZZ_DIR/
