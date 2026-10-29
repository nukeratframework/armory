#!/bin/bash
#
# Token2Cert BOF - Build Script
#

set -e

echo ""
echo "=========================================="
echo "  Token2Cert BOF - Build Script"
echo "=========================================="
echo ""

# Check for mingw compiler
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[-] x86_64-w64-mingw32-gcc not found!"
    echo "    Install with: sudo apt install mingw-w64"
    exit 1
fi

# Create output directories
mkdir -p cobaltstrike/bofs
mkdir -p havoc/bofs

# Compile
echo "[*] Compiling Token2Cert BOF..."

x86_64-w64-mingw32-gcc \
    -c -Os \
    -fno-stack-protector \
    -fno-asynchronous-unwind-tables \
    -masm=intel \
    -fno-ident \
    -Wno-pointer-arith \
    -DBOF \
    -I include \
    -o cobaltstrike/bofs/Token2Cert.x64.o \
    src/Token2Cert.c

# Copy to havoc
cp cobaltstrike/bofs/Token2Cert.x64.o havoc/bofs/

echo ""
echo "[+] Build complete!"
echo ""
echo "    Cobalt Strike: cobaltstrike/bofs/Token2Cert.x64.o"
echo "    Havoc:         havoc/bofs/Token2Cert.x64.o"
echo ""
echo "Load in Cobalt Strike:"
echo "    Script Manager -> Load -> cobaltstrike/Token2Cert.cna"
echo ""
