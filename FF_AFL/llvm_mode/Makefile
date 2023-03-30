
HELPER_PATH = "/usr/local/lib/afl\"
DOC_PATH = "/usr/local/share/doc/afl\"
BIN_PATH = "/usr/local/bin\"
INCLUDE_PATH = "../"

CFLAGS    = -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g  \
	    -Wno-pointer-sign -Wno-unused-function -Wno-unused-result
CFLAGS    += -DAFL_PATH=\$(HELPER_PATH) -DDOC_PATH=\$(DOC_PATH) \
	    -DBIN_PATH=\$(BIN_PATH)  -I$(INCLUDE_PATH) 

LDFLAGS  	= -ldl -lm
LDFLAGS 	+= -lcgraph `pkg-config --cflags --libs glib-2.0`

LLVM_CONFIG ?= llvm-config

CLANG_CFL    = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS)
CLANG_LFL    = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

ifdef AFL_TRACE_PC
  CFLAGS    += -DUSE_TRACE_PC=1
endif

all : ../afl-clang-fast ../afl-llvm-pass.so ../afl-llvm-rt.o ../ff-all-in-one

../afl-clang-fast: afl-clang-fast.c 
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	ln -sf afl-clang-fast ../afl-clang-fast++

#../afl-llvm-link: afl-llvm-link.c
#	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
../ff-all-in-one: ff-all-in-one.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	ln -sf ff-all-in-one ../ff-all-in-one++


../afl-llvm-pass.so: afl-llvm-pass.so.cc 
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

../afl-llvm-rt.o: afl-llvm-rt.o.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@


clean :
	rm ../afl-clang-fast ../afl-clang-fast++ ../afl-llvm-pass.so ../afl-llvm-rt.o
