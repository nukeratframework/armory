BOFNAME := ASRenum-BOF

CC_x64 := x86_64-w64-mingw32-g++
CC_x86 := i686-w64-mingw32-g++

all:
	$(CC_x64) -Wno-unused-variable -Wno-write-strings -fno-exceptions -fno-rtti -fno-asynchronous-unwind-tables -fno-unwind-tables -Os -o $(BOFNAME).x64.o -c ASRenum-BOF.cpp -masm=intel
	$(CC_x86) -Wno-unused-variable -Wno-write-strings -fno-exceptions -fno-rtti -fno-asynchronous-unwind-tables -fno-unwind-tables -Os -o $(BOFNAME).x86.o -c ASRenum-BOF.cpp -masm=intel