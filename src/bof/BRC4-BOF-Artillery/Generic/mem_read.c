#include <windows.h>
#include <stdio.h>
#include "../../Cookie-and-Handle-Stealer/beacon.h"

WINADVAPI FARPROC WINAPI Kernel32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINADVAPI HMODULE WINAPI Kernel32$GetModuleHandleA(LPCSTR lpModuleName);

static int split_args(char *line, char **argv, int max_args) {
    int count = 0;
    char *cursor = line;
    char *token = NULL;

    while (count < max_args && cursor && *cursor) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
            cursor++;
        }
        if (!*cursor) {
            break;
        }
        token = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '\r' && *cursor != '\n') {
            cursor++;
        }
        if (*cursor) {
            *cursor++ = '\0';
        }
        argv[count++] = token;
    }
    return count;
}

static void run_mem_read(int argc, char **argv) {
    if (argc > 1) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Loading library '%s'\n", argv[0]);
        HANDLE hModule = Kernel32$GetModuleHandleA(argv[0]);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Library loaded at '%p'\n", hModule);
        for (int i = 1; i < argc; i++) {
            unsigned char buf[11] = { 0 };
            PVOID myProc = (PVOID)Kernel32$GetProcAddress(hModule, argv[i]);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Reading first 10 bytes from '%s (%p)'\n  - Bytes: { ", argv[i], myProc);
            if (myProc) {
                for (int j = 0; j < 10; j++) {
                    buf[j] = ((unsigned char *)myProc)[j];
                }
            }
            for (int j = 0; j < 10; j++) {
                BeaconPrintf(CALLBACK_OUTPUT, "0x%02X ", buf[j]);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "}\n");
        }
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: bof-mem-read --- <dll> <function1> [function2 ...]\n");
}

void go(char *args, int len) {
    datap parser;
    char *packed = NULL;
    char *argv[16] = { 0 };
    int argc = 0;
    int packed_len = 0;

    if (len <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: bof-mem-read --- <dll> <function1> [function2 ...]\n");
        return;
    }

    BeaconDataParse(&parser, args, len);
    packed = BeaconDataExtract(&parser, &packed_len);
    if (!packed || packed_len <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: bof-mem-read --- <dll> <function1> [function2 ...]\n");
        return;
    }

    argc = split_args(packed, argv, 16);
    run_mem_read(argc, argv);
}
