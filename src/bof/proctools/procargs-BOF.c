#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <winternl.h>
#include "beacon.h"

#pragma comment(lib, "ntdll.lib")

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
WINBASEAPI BOOL WINAPI KERNEL32$ReadProcessMemory (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void*);

void go (char* args, int len) {

    datap parser;
    BeaconDataParse(&parser, args, len);
    int pid = BeaconDataInt(&parser);

    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] Failed to open process");
        return;
    }

    // get process basic info
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NTDLL$NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL);

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] Failed to query process information");
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    // read PEB
    PEB peb;
    if (!KERNEL32$ReadProcessMemory(
        hProcess,
        pbi.PebBaseAddress,
        &peb,
        sizeof(PEB),
        NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] Failed to read PEB");
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    // read the process parameters
    RTL_USER_PROCESS_PARAMETERS parameters;
    if (!KERNEL32$ReadProcessMemory(
        hProcess,
        peb.ProcessParameters,
        &parameters,
        sizeof(RTL_USER_PROCESS_PARAMETERS),
        NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] Failed to read process parameters");
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    // read the command line buffer
    SIZE_T commandLineChars = parameters.CommandLine.Length / sizeof(wchar_t);
    SIZE_T commandLineBufferBytes = parameters.CommandLine.Length + sizeof(wchar_t);
    wchar_t* commandLineBuffer = (wchar_t*)MSVCRT$malloc(commandLineBufferBytes);
    if (commandLineBuffer == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] Failed to allocate command line buffer");
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    if (!KERNEL32$ReadProcessMemory(
        hProcess,
        parameters.CommandLine.Buffer,
        commandLineBuffer,
        parameters.CommandLine.Length,
        NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] Failed to read command line buffer");
        MSVCRT$free(commandLineBuffer);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    commandLineBuffer[commandLineChars] = L'\0';

    int narrowLen = (int)(commandLineChars * 4) + 1;
    char* commandLineA = (char*)MSVCRT$malloc(narrowLen);
    if (commandLineA == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[-] Failed to allocate output buffer");
        MSVCRT$free(commandLineBuffer);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    KERNEL32$WideCharToMultiByte(
        CP_UTF8,
        0,
        commandLineBuffer,
        -1,
        commandLineA,
        narrowLen,
        NULL,
        NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] CmdLine Args: %s\n", commandLineA);

    MSVCRT$free(commandLineA);
    MSVCRT$free(commandLineBuffer);
    KERNEL32$CloseHandle(hProcess);

    return;
}
