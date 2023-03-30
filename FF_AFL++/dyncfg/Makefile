

CXXFLAGS += -Wall -Wextra -O2 -march=native -Wno-unused-variable -g

LDFLAGS  += -lboost_program_options -lboost_graph -ljsoncpp

INCLUDE_PATH = "../include"

all : dis_calc 

dis_calc : main.cpp 
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_PATH) $^ -o $@ $(LDFLAGS)

# runtime.o : runtime.o.cc
# 	$(CXX) $(CXXFLAGS) -I$(INCLUDE_PATH) $^ -c  -o $@

clean :
	rm dis_calc

