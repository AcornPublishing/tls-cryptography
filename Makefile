SHELL := /bin/bash

all : 
	make -C util/
	./incltouch.x
	make -C tcpip/
	make -C src/
	make -C tst/
	make -C obj/
	./catch.tst.x

clean :
	mv obj/catch.tst.x obj/catch.tst
	rm *.x obj/*.?
	mv obj/catch.tst obj/catch.tst.x

# incltouch will touch source files, according to inclusion of header files.
# incltouch generate tree of header inclusion.
# So it can track inclusion tree. 
# But there is one including rule.
# Any header file that is made by you and will be edited should use " ", not < >.
# Any header files that will not be edited by you should use < >. ie)standard library.
# And you should alwasy use directory structure.
# root dir - src directories.
#          |- src2 directory
#          |- src3 : src name can vary.
#          |- obj : object files will be placed here
#          |- tst : test files will be placed here
# And you should not add include path except -I../ and library include directory.
# In the end, the header inclusion will be like #include "src/header.h" when
# it is in the different directory.
# Or "header.h" when it is in the same directory.

