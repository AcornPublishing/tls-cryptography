CXX = g++
CPPFLAGS = -I../
CXXFLAGS = -g -std=c++17 -fmax-errors=1
OBJ = $(patsubst %.cc, ../obj/%.o, $(wildcard *.cc))

all : $(OBJ) ../incltouch.x

../obj/%.o : %.cc 
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

../incltouch.x : incltouch.cpp graph.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ -lstdc++fs
