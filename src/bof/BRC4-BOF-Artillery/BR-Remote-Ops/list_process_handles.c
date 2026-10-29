#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include "../../Cookie-and-Handle-Stealer/beacon.h"

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

DECLSPEC_IMPORT NTSTATUS Ntdll$NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS Ntdll$NtQueryObject(HANDLE ObjectHandle, ULONG ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS Ntdll$NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);

DECLSPEC_IMPORT DWORD WINAPI Kernel32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$GetProcessHeap();
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$GetCurrentProcess();
DECLSPEC_IMPORT DWORD WINAPI Kernel32$CloseHandle(HANDLE hObjec);
DECLSPEC_IMPORT BOOL WINAPI Kernel32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT LPVOID WINAPI Kernel32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT LPVOID WINAPI Kernel32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
DECLSPEC_IMPORT HANDLE WINAPI Kernel32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

static void zero_mem(void *dest, size_t len) {
    unsigned char *p = (unsigned char *)dest;
    while (len--) {
        *p++ = 0;
    }
}

VOID ListProcessHandles(DWORD pid) {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Listing handles for PID: %lu\n\n", pid);
    BeaconPrintf(CALLBACK_OUTPUT, "----------------------------------------------------------\n");
    BeaconPrintf(CALLBACK_OUTPUT, "%-10s  | %-25s| %-20s\n", "Handle", "Object Type", "Name");
    BeaconPrintf(CALLBACK_OUTPUT, "----------------------------------------------------------\n");

    DWORD dwErrorCode = ERROR_SUCCESS;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle = NULL;
    ULONG i = 0;
    HANDLE dupHandle = NULL;
    POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
    PVOID objectNameInfo = NULL;

    processHandle = Kernel32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!processHandle) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error OpenProcess: %lu\n", Kernel32$GetLastError());
        goto cleanup;
    }
    handleInfo = (PSYSTEM_HANDLE_INFORMATION)Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize);
    if (!handleInfo) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error HeapAlloc: %lu\n", ERROR_OUTOFMEMORY);
        goto cleanup;
    }
    while ((dwErrorCode = (DWORD)Ntdll$NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)Kernel32$HeapReAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfo, handleInfoSize *= 2);
        if (!handleInfo) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Error HeapAlloc: %lu\n", ERROR_OUTOFMEMORY);
            goto cleanup;
        }
    }
    if (!NT_SUCCESS(dwErrorCode)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error NtQuerySystemInformation: %lu\n", dwErrorCode);
        goto cleanup;
    }
    for (i = 0; i < handleInfo->Count; i++) {
        SYSTEM_HANDLE_ENTRY handle = handleInfo->Handle[i];
        UNICODE_STRING objectName;
        ULONG returnLength = 0;
        zero_mem(&objectName, sizeof(UNICODE_STRING));
        if (objectTypeInfo) {
            Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, objectTypeInfo);
            objectTypeInfo = NULL;
        }
        if (objectNameInfo) {
            Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, objectNameInfo);
            objectNameInfo = NULL;
        }
        if (dupHandle) {
            Kernel32$CloseHandle(dupHandle);
            dupHandle = NULL;
        }
        if (handle.OwnerPid != pid) {
            continue;
        }
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
        dwErrorCode = (DWORD)Ntdll$NtDuplicateObject(processHandle, (HANDLE)handle.HandleValue, (HANDLE)-1, &dupHandle, 0, 0, 0);
#pragma GCC diagnostic pop
        if (!NT_SUCCESS(dwErrorCode)) {
            if (dwErrorCode != 0xc00000bb) {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] Error NtDuplicateObject: %lx\n", dwErrorCode);
            }
            continue;
        }
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
        if (!objectTypeInfo) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Error HeapAlloc: %lu\n", ERROR_OUTOFMEMORY);
            continue;
        }
        dwErrorCode = (DWORD)Ntdll$NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL);
        if (!NT_SUCCESS(dwErrorCode)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Error NtQueryObject :%lu\n", dwErrorCode);
            continue;
        }
        if (handle.AccessMask == 0x0012019f) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] [%d] %S: (did not get name)\n", handle.HandleValue, objectTypeInfo->TypeName.Buffer);
            continue;
        }
        objectNameInfo = Kernel32$HeapAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
        if (!objectNameInfo) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Error HeapAlloc: %lu\n", ERROR_OUTOFMEMORY);
            continue;
        }
        dwErrorCode = (DWORD)Ntdll$NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);
        if (!NT_SUCCESS(dwErrorCode)) {
            objectNameInfo = Kernel32$HeapReAlloc(Kernel32$GetProcessHeap(), HEAP_ZERO_MEMORY, objectNameInfo, returnLength);
            if (NULL == objectNameInfo) {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] Error HeapAlloc: %lu\n", ERROR_OUTOFMEMORY);
                continue;
            }
            dwErrorCode = (DWORD)Ntdll$NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL);
            if (!NT_SUCCESS(dwErrorCode)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] [%d] %S: (could not get name)\n", handle.HandleValue, objectTypeInfo->TypeName.Buffer);
                continue;
            }
        }
        objectName = *(PUNICODE_STRING)objectNameInfo;
        if (objectName.Length) {
            BeaconPrintf(CALLBACK_OUTPUT, "0x%-10d| %-25S| %-20S\n", handle.HandleValue, objectTypeInfo->TypeName.Buffer, objectName.Buffer);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "0x%-10d| %-25S| (unnamed)\n", handle.HandleValue, objectTypeInfo->TypeName.Buffer);
        }
    }
    dwErrorCode = ERROR_SUCCESS;

cleanup:
    if (handleInfo) {
        Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, handleInfo);
        handleInfo = NULL;
    }
    if (processHandle) {
        Kernel32$CloseHandle(processHandle);
        processHandle = NULL;
    }
    if (objectTypeInfo) {
        Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, objectTypeInfo);
        objectTypeInfo = NULL;
    }
    if (objectNameInfo) {
        Kernel32$HeapFree(Kernel32$GetProcessHeap(), 0, objectNameInfo);
        objectNameInfo = NULL;
    }
    if (dupHandle) {
        Kernel32$CloseHandle(dupHandle);
        dupHandle = NULL;
    }
}

static DWORD parse_pid_arg(char *args, int len) {
    datap parser;
    char *pidStr = NULL;
    int pidStrLen = 0;
    DWORD dwPid = 0;
    int i = 0;

    if (len <= 0) {
        return 0;
    }

    BeaconDataParse(&parser, args, len);
    if (BeaconDataLength(&parser) >= (int)sizeof(int)) {
        dwPid = (DWORD)BeaconDataInt(&parser);
        if (dwPid != 0) {
            return dwPid;
        }
        BeaconDataParse(&parser, args, len);
    }

    pidStr = BeaconDataExtract(&parser, &pidStrLen);
    if (!pidStr || pidStrLen <= 0) {
        return 0;
    }

    for (i = 0; i < pidStrLen && pidStr[i] >= '0' && pidStr[i] <= '9'; i++) {
        dwPid = (dwPid * 10) + (DWORD)(pidStr[i] - '0');
    }
    return dwPid;
}

void go(char *args, int len) {
    DWORD dwPid = parse_pid_arg(args, len);

    if (dwPid == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: bof-list-process-handles --- <pid>\n");
        return;
    }
    ListProcessHandles(dwPid);
}
