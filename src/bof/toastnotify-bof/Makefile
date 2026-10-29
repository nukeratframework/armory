PRJNAME := toastnotify

SRC     := $(wildcard src/*.c)
BUILD   := build
INCLUDE := -I src/

CC_x64  := x86_64-w64-mingw32-gcc
CC_x86  := i686-w64-mingw32-gcc

OUT_x64 := $(BUILD)/$(PRJNAME).x64.o
OUT_x86 := $(BUILD)/$(PRJNAME).x86.o

.PHONY: all x64 x86 clean

all: x64 x86

x64: $(OUT_x64)
x86: $(OUT_x86)

$(OUT_x64): $(SRC) | $(BUILD)
	$(CC_x64) $(CFLAGS) $(INCLUDE) -o $@ -c $(SRC)

$(OUT_x86): $(SRC) | $(BUILD)
	$(CC_x86) $(CFLAGS) $(INCLUDE) -o $@ -c $(SRC)

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -f $(OUT_x64) $(OUT_x86)
