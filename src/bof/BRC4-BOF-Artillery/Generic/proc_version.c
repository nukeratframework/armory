#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

WINBASEAPI WINBOOL WINAPI KERNEL32$Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
WINBASEAPI WINBOOL WINAPI KERNEL32$Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT WINBOOL WINAPI VERSION$GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
DECLSPEC_IMPORT DWORD WINAPI VERSION$GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle);
DECLSPEC_IMPORT WINBOOL WINAPI VERSION$VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void*);

void go(char *args, int len) {
    datap parser;
    formatp obj;
    int outSize = 0;
    char *dataOut = NULL;
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32 moduleEntry;
    int pid = 0;

    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);

    if (pid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid process ID: %d\n", pid);
        return;
    }

    BeaconFormatAlloc(&obj, 2048);

    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unable to create snapshot of the process.\n");
        return;
    }

    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (KERNEL32$Module32First(snapshot, &moduleEntry)) {
        do {
            if (moduleEntry.th32ProcessID == pid) {
                BeaconFormatPrintf(&obj, "[*] Name: %s\n", moduleEntry.szModule);
                BeaconFormatPrintf(&obj, "[*] File Path: %s\n", moduleEntry.szExePath);

                DWORD dwHandle = 0;
                DWORD dwSize = VERSION$GetFileVersionInfoSizeA(moduleEntry.szExePath, &dwHandle);

                if (dwSize > 0) {
                    LPVOID lpVersionInfo = MSVCRT$malloc(dwSize);

                    if (lpVersionInfo != NULL &&
                        VERSION$GetFileVersionInfoA(moduleEntry.szExePath, dwHandle, dwSize, lpVersionInfo)) {
                        VS_FIXEDFILEINFO *fileInfo = NULL;
                        UINT fileInfoLen = 0;

                        if (VERSION$VerQueryValueA(lpVersionInfo, "\\", (LPVOID *)&fileInfo, &fileInfoLen)) {
                            BeaconFormatPrintf(
                                &obj,
                                "[*] Version: %u.%u.%u.%u\n",
                                HIWORD(fileInfo->dwFileVersionMS),
                                LOWORD(fileInfo->dwFileVersionMS),
                                HIWORD(fileInfo->dwFileVersionLS),
                                LOWORD(fileInfo->dwFileVersionLS));
                        }
                    }

                    MSVCRT$free(lpVersionInfo);
                }

                break;
            }
        } while (KERNEL32$Module32Next(snapshot, &moduleEntry));
    }

    KERNEL32$CloseHandle(snapshot);

    dataOut = BeaconFormatToString(&obj, &outSize);
    if (outSize > 0) {
        BeaconOutput(CALLBACK_OUTPUT, dataOut, outSize);
    }

    BeaconFormatFree(&obj);
}
