#include <windows.h>
#include <stdarg.h>
#include "../../CS-Remote-OPs-BOF/src/common/beacon.h"

extern void coffee(char **argv, int argc, WCHAR **dispatch);
extern WCHAR **g_dispatch;

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

DECLSPEC_IMPORT int MSVCRT$vsnprintf(char *buffer, size_t count, const char *format, va_list arg);
DECLSPEC_IMPORT int MSVCRT$vswprintf(wchar_t *buffer, size_t count, const wchar_t *format, va_list arg);
DECLSPEC_IMPORT int MSVCRT$strcmp(const char *s1, const char *s2);
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *s);
DECLSPEC_IMPORT size_t MSVCRT$wcslen(const wchar_t *s);
DECLSPEC_IMPORT void *MSVCRT$memcpy(void *dest, const void *src, size_t count);
DECLSPEC_IMPORT void *MSVCRT$memset(void *dest, int ch, size_t count);
DECLSPEC_IMPORT int MSVCRT$atoi(const char *s);
DECLSPEC_IMPORT int MSVCRT$wcscmp(const wchar_t *s1, const wchar_t *s2);

void ___chkstk_ms(void) {
}

int BadgerDispatch(WCHAR **dispatch, const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    int n;

    (void)dispatch;
    va_start(ap, fmt);
    n = MSVCRT$vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buf, n);
    }
    return 0;
}

int BadgerDispatchW(WCHAR **dispatch, const WCHAR *fmt, ...) {
    wchar_t wbuf[2048];
    char buf[4096];
    va_list ap;
    int n;

    (void)dispatch;
    va_start(ap, fmt);
    MSVCRT$vswprintf(wbuf, sizeof(wbuf) / sizeof(wchar_t), fmt, ap);
    va_end(ap);
    n = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, sizeof(buf), NULL, NULL);
    if (n > 1) {
        BeaconOutput(CALLBACK_OUTPUT, buf, n - 1);
    }
    return 0;
}

size_t BadgerStrlen(CHAR *buf) {
    return MSVCRT$strlen((const char *)buf);
}

size_t BadgerWcslen(WCHAR *buf) {
    return MSVCRT$wcslen((const wchar_t *)buf);
}

void *BadgerMemcpy(void *dest, const void *src, size_t len) {
    return MSVCRT$memcpy(dest, src, len);
}

void *BadgerMemset(void *dest, int val, size_t len) {
    return MSVCRT$memset(dest, val, len);
}

int BadgerStrcmp(const char *p1, const char *p2) {
    return MSVCRT$strcmp(p1, p2);
}

int BadgerWcscmp(const wchar_t *s1, const wchar_t *s2) {
    return MSVCRT$wcscmp(s1, s2);
}

int BadgerAtoi(char *string) {
    return MSVCRT$atoi((const char *)string);
}

PVOID BadgerAlloc(SIZE_T length) {
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, length);
}

VOID BadgerFree(PVOID *memptr) {
    if (memptr != NULL && *memptr != NULL) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, *memptr);
        *memptr = NULL;
    }
}

BOOL BadgerSetdebug(void) {
    return TRUE;
}

ULONG BadgerGetBufferSize(PVOID buffer) {
    (void)buffer;
    return 0;
}

UINT_PTR BadgerSpoofStackFrame(UINT_PTR pWinAPI, int argc, ...) {
    (void)pWinAPI;
    (void)argc;
    return 0;
}

VOID BadgerSetHTTPBuffer(PVOID buffer) {
    (void)buffer;
}

VOID BadgerSetToken(HANDLE hToken) {
    (void)hToken;
}

BOOL BadgerAddPrivilege(CHAR *privilegeName) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, (LPCSTR)privilegeName, &luid)) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    KERNEL32$CloseHandle(hToken);
    return TRUE;
}

static int split_command_line(char *line, char **argv, int maxargc) {
    int argc = 0;
    char *p = line;

    while (*p && argc < maxargc) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        if (*p == '"') {
            p++;
            argv[argc++] = p;
            while (*p && *p != '"') {
                p++;
            }
            if (*p == '"') {
                *p++ = '\0';
            }
        } else {
            argv[argc++] = p;
            while (*p && *p != ' ' && *p != '\t') {
                p++;
            }
            if (*p) {
                *p++ = '\0';
            }
        }
    }

    return argc;
}

#ifndef BRC4_CUSTOM_GO
void go(char *args, int len) {
    datap parser;
    char line[8192];
    char *argv[32] = {0};
    char argstorage[32][512];
    char *chunks[32] = {0};
    int sizes[32] = {0};
    int chunkCount = 0;
    int argc = 0;
    int i = 0;

    if (args == NULL || len <= 0) {
        g_dispatch = NULL;
        coffee(argv, 0, NULL);
        return;
    }

    BeaconDataParse(&parser, args, len);
    while (chunkCount < 32 && BeaconDataLength(&parser) > 0) {
        chunks[chunkCount] = BeaconDataExtract(&parser, &sizes[chunkCount]);
        if (chunks[chunkCount] == NULL || sizes[chunkCount] <= 0) {
            break;
        }
        chunkCount++;
    }

    if (chunkCount == 0) {
        g_dispatch = NULL;
        coffee(argv, 0, NULL);
        return;
    }

    if (chunkCount == 1) {
        for (i = 0; chunks[0][i] != '\0' && i < (int)sizeof(line) - 1; i++) {
            line[i] = chunks[0][i];
        }
        line[i] = '\0';
        argc = split_command_line(line, argv, 32);
    } else {
        for (i = 0; i < chunkCount && i < 32; i++) {
            if ((sizes[i] % 2) == 0) {
                KERNEL32$WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    (const wchar_t *)chunks[i],
                    sizes[i] / (int)sizeof(wchar_t),
                    argstorage[argc],
                    sizeof(argstorage[argc]),
                    NULL,
                    NULL);
            } else {
                MSVCRT$memcpy(argstorage[argc], chunks[i], sizes[i] > 0 ? (size_t)(sizes[i] - 1) : 0);
                argstorage[argc][sizes[i] > 0 ? sizes[i] - 1 : 0] = '\0';
            }
            argv[argc] = argstorage[argc];
            argc++;
        }
    }

    g_dispatch = NULL;
    coffee(argv, argc, NULL);
}
#endif
