PROJECT = clipboard-monitor

CCX64  := x86_64-w64-mingw32-gcc
CCX86  := i686-w64-mingw32-gcc
CFLAGS := -Wall -Werror -Os -s -Iinclude -D_NO_NTDLL_CRT_ -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions -fno-stack-protector -ffreestanding

.DEFAULT: all
all: bof

bof: dist/$(PROJECT).x64.o dist/$(PROJECT).x86.o

dist/$(PROJECT).x64.o: src/main.c include/common.h
	$(CCX64) -c src/main.c -o $@ $(CFLAGS)
	objcopy --remove-section .pdata --remove-section .xdata --remove-section .eh_frame $@

dist/$(PROJECT).x86.o: src/main.c include/common.h
	$(CCX86) -c src/main.c -o $@ $(CFLAGS)
	objcopy --remove-section .pdata --remove-section .xdata --remove-section .eh_frame $@

clean:
	rm -f dist/$(PROJECT)*.o
