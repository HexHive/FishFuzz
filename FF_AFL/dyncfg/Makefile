

CXXFLAGS += -Wall -Wextra -O2 -march=native -Wno-unused-variable

LDFLAGS  += -lboost_program_options -lboost_graph -ljsoncpp

INCLUDE_PATH = "../"

all : dis_calc runtime.o

dis_calc : main.cpp 
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

runtime.o : runtime.o.cc
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_PATH) $^ -c  -o $@

clean :
	rm dis_calc runtime.o

