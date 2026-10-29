override CC_X64 := x86_64-w64-mingw32-gcc
STRIP_X64 ?= x86_64-w64-mingw32-strip

CFLAGS := -Os -std=c99 \
	-fno-stack-protector -fno-stack-check -mno-stack-arg-probe \
	-fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove \
	-nostdlib \
	-fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident \
	-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable \
	-fno-leading-underscore -fno-ms-extensions

SRC = PortScan.c
HEADERS = $(wildcard *.h)

all: PortScan.o

PortScan.o: PortScan.c $(HEADERS)
	$(CC_X64) $(CFLAGS) -c -o $@ $<
	@if command -v $(STRIP_X64) >/dev/null 2>&1; then \
		$(STRIP_X64) --strip-unneeded $@ 2>/dev/null || true; \
	fi

clean:
	rm -f *.o
