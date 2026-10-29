BOFNAME := silentchrome
SRC := src
CC_x64 := x86_64-w64-mingw32-gcc
CFLAGS := -I $(SRC) -Os -c -DBOF

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(CFLAGS) $(SRC)/entry.c

debug:
	$(CC_x64) -o $(BOFNAME)-debug.x64.o $(CFLAGS) -DDEBUG $(SRC)/entry.c

clean:
	rm -f $(BOFNAME).*.o $(BOFNAME)-debug.*.o $(BOFNAME).*.exe
