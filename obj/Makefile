CXX = g++
TOBJ = $(wildcard *.tst.o)
OBJ = $(patsubst %.tst.o,, $(wildcard *.o))
EXE = $(patsubst %.x, ../%.x, $(wildcard *.x))
LDFLAGS = 
LDLIBS = -lgmpxx -lgmp -lstdc++fs -lnettle -ljsoncpp -lpthread -lhogweed


all : $(EXE)

../catch.tst.x : catch.tst.x $(TOBJ) $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

../%.x : %.x $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)


#    $@ |현재 목표 파일의 이름
#    $* | 확장자를 제외한 현재 목표 파일의 이름
#    $< | 현재 필수 조건 파일 중 첫 번째 파일 이름
#    $? | 현재 대상보다 최슨에 변경된 함수 조건 파일 이름
#    $^ | 현재 모든 필수 조건 파일들

