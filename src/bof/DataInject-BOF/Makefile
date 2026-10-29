CC_x64 := x86_64-w64-mingw32-gcc

OPTIONS := -masm=intel -Wall -Os

all: clean
	$(CC_x64) -o dist/datainject.x64.o $(OPTIONS) -c entry.c

clean:
	rm -f dist/datainject.x64.o