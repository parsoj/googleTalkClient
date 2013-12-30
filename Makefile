# CS438 - spring 2013 MP0
#
# This is a simple example of a makefile, use this for reference when you create your own
#
# NOTE: if you decide to write your solution in C++, you will have to change the compiler 
# in this file. 

CC=/usr/bin/gcc
CC_OPTS=-g3 -Wall
CC_LIBS=-L lib -lgnutls -lgsasl -lrecv_xml_nonblock
CC_INCLUDES=-I include 
CC_ARGS=${CC_OPTS} ${CC_DEFINES} ${CC_INCLUDES}

# clean is not a file
.PHONY=clean

#target "all" depends on all others
all: iGtalk

# client C depends on source file client.c, if that changes, make client will 
# rebuild the binary
iGtalk: iGtalk.c
	@${CC} ${CC_ARGS}  -o iGtalk iGtalk.c ${CC_LIBS}

clean:
	@rm -f iGtalk *.o
