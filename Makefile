# the compiler: gcc for C program, define as g++ for C++
CC = gcc
CPP = g++
# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall 
LIBNAME = -lcapstone -lelf
# the build target executable:
TARGET = hw4

all: $(TARGET)

.PHONY: clean

hw4: sdb.cpp
	$(CPP) $(CFLAGS) $< $(LIBNAME) -o $@

clean:
	$(RM) $(TARGET) 