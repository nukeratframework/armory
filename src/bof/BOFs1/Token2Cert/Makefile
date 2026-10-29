#
# Token2Cert BOF - Makefile
# Compile with: make
#

CC_x64 = x86_64-w64-mingw32-gcc

CFLAGS = -c -Os -fno-stack-protector -fno-asynchronous-unwind-tables
CFLAGS += -masm=intel -fno-ident -Wno-pointer-arith
CFLAGS += -DBOF
CFLAGS += -I include

SRC = src/Token2Cert.c
OUT = cobaltstrike/bofs/Token2Cert.x64.o

.PHONY: all clean dirs

all: dirs $(OUT)
	@echo "[+] Build complete: $(OUT)"

dirs:
	@mkdir -p cobaltstrike/bofs

$(OUT): $(SRC)
	@echo "[*] Compiling Token2Cert BOF..."
	$(CC_x64) $(CFLAGS) -o $@ $<

clean:
	@echo "[*] Cleaning..."
	rm -f $(OUT)
	@echo "[+] Clean complete"

standalone:
	@echo "[*] Compiling standalone executable..."
	x86_64-w64-mingw32-gcc -o Token2Cert.exe src/Token2Cert.c \
		-I include \
		-lwtsapi32 -ladvapi32 -lcrypt32 -lole32 -loleaut32 \
		-lws2_32 -lnetapi32 -lwldap32
	@echo "[+] Built: Token2Cert.exe"
