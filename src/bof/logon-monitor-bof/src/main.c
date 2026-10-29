#include <windows.h>
#include "beacon.h"
#include "common.h"

SESSION_SNAPSHOT SessionSnapshot(HANDLE hServer) {
    SESSION_SNAPSHOT snapshot;
    MSVCRT$memset(&snapshot, 0, sizeof(SESSION_SNAPSHOT));

    PWTS_SESSION_INFOW pSessions = NULL;
    DWORD count = 0;

    if (!WTSAPI32$WTSEnumerateSessionsW(hServer, 0, 1, &pSessions, &count))
        return snapshot;

    for (DWORD i = 0; i < count && snapshot.count < MAX_SESSIONS; i++) {
        if (pSessions[i].SessionId == 0)
            continue;

        LPWSTR wsUser = NULL;
        DWORD  userLen = 0;
        BOOL hasUser = WTSAPI32$WTSQuerySessionInformationW(hServer, pSessions[i].SessionId, WTSUserName, &wsUser, &userLen);

        BOOL empty = (!hasUser || !wsUser || wsUser[0] == L'\0');
        if (wsUser) WTSAPI32$WTSFreeMemory(wsUser);
        if (empty) continue;

        snapshot.ids[snapshot.count]    = pSessions[i].SessionId;
        snapshot.states[snapshot.count] = pSessions[i].State;
        snapshot.count++;
    }

    WTSAPI32$WTSFreeMemory(pSessions);
    return snapshot;
}

DWORD GetSessionProcess(DWORD sessionId, char* nameBuf, int nameBufLen) {
    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    DWORD pid = 0;
    if (KERNEL32$Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
                continue;

            DWORD sid = 0;
            if (!KERNEL32$ProcessIdToSessionId(pe.th32ProcessID, &sid))
                continue;
            if (sid != sessionId)
                continue;

            pid = pe.th32ProcessID;
            if (nameBuf && nameBufLen > 0) {
                KERNEL32$WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nameBuf, nameBufLen - 1, NULL, NULL);
                nameBuf[nameBufLen - 1] = '\0';
            }
            break;
        } while (KERNEL32$Process32NextW(hSnap, &pe));
    }

    KERNEL32$CloseHandle(hSnap);
    return pid;
}

BOOL IsTargetUser(const wchar_t* wsUser, const wchar_t* wsTargetUsers) {
    if (!wsTargetUsers || wsTargetUsers[0] == L'\0')
        return TRUE;

    const wchar_t* p = wsTargetUsers;
    while (*p) {
        const wchar_t* end = p;
        while (*end && *end != L',') 
            end++;

        int len = (int)(end - p);
        if (len > 0 && len < 256) {
            wchar_t tmp[256];
            MSVCRT$memcpy(tmp, p, len * sizeof(wchar_t));
            tmp[len] = L'\0';
            if (KERNEL32$lstrcmpiW(tmp, wsUser) == 0)
                return TRUE;
        }

        p = (*end == L',') ? end + 1 : end;
    }
    return FALSE;
}

VOID NotifyLogon(HANDLE hServer, DWORD sessionId, LPWSTR wsUser, LPWSTR wsDomain) {
    char user[256];
    char domain[256];
    MSVCRT$memset(user, 0, sizeof(user));
    MSVCRT$memset(domain, 0, sizeof(domain));
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wsUser, -1, user, sizeof(user) - 1, NULL, NULL);
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wsDomain, -1, domain, sizeof(domain) - 1, NULL, NULL);

    char procName[256];
    MSVCRT$memset(procName, 0, sizeof(procName));
    DWORD pid = 0;
    if (!hServer)
        pid = GetSessionProcess(sessionId, procName, sizeof(procName));

    SYSTEMTIME now;
    KERNEL32$GetLocalTime(&now);

    // Print logon information 
    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] %02d-%02d-%04d %02d:%02d:%02d - New logon detected:\n"
        "    User     : %s\\%s\n"
        "    Session  : %lu\n", now.wDay, now.wMonth, now.wYear, now.wHour, now.wMinute, now.wSecond, domain, user, (unsigned long)sessionId);
    if(pid) BeaconPrintf(CALLBACK_OUTPUT, "    Process  : %lu/%s\n", (unsigned long)pid, procName); 
}

VOID go(char* args, int argc) {
    datap parser = { 0 };

    BeaconDataParse(&parser, args, argc);
    int interval = BeaconDataInt(&parser);
    if (interval <= 0)
        interval = 5;
    wchar_t* targetUsers = (wchar_t*)BeaconDataExtract(&parser, NULL);
    wchar_t* server = (wchar_t*)BeaconDataExtract(&parser, NULL);
    
    // Connect to target server
    HANDLE hServer = NULL;
    if (server && server[0] != L'\0') {
        hServer = WTSAPI32$WTSOpenServerW(server);
        if (!hServer) {
            BeaconPrintf(CALLBACK_ERROR, "[-] WTSOpenServerW failed (error: %lu)\n", KERNEL32$GetLastError());
            return;
        }
    }    
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Logon monitor started.\n"); 
    if (server && server[0]){
        char szServer[256];
        MSVCRT$memset(szServer, 0, sizeof(szServer));
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, server, -1, szServer,  sizeof(szServer) - 1, NULL, NULL); 
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target server: %s\n", szServer); 
    }

    if (targetUsers && targetUsers[0]) {
        char szTargets[256];
        MSVCRT$memset(szTargets, 0, sizeof(szTargets));
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, targetUsers, -1, szTargets,  sizeof(szTargets) - 1, NULL, NULL);        
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target users: %s\n", szTargets); 
    }

    // Start monitoring for two types of logons 
    // - WTSActive: Session has active physical or virtual desktop 
    // - WTSConnected: Session is connected, desktop is not rendered/interacted with
    SESSION_SNAPSHOT prev = SessionSnapshot(hServer);
    do {
        SESSION_SNAPSHOT curr = SessionSnapshot(hServer);

        for (DWORD i = 0; i < curr.count; i++) {
            if (curr.states[i] != WTSActive && curr.states[i] != WTSConnected)
                continue;

            BOOL wasActive = FALSE;
            for (DWORD j = 0; j < prev.count; j++) {
                if (curr.ids[i] == prev.ids[j]) {
                    if (prev.states[j] == WTSActive || prev.states[j] == WTSConnected)
                        wasActive = TRUE;
                    break;
                }
            }
            if (wasActive) continue;

            LPWSTR wsUser, wsDomain = NULL; 
            DWORD userLen, domLen = 0;

            // Retrieve username
            if (!WTSAPI32$WTSQuerySessionInformationW(hServer, curr.ids[i], WTSUserName, &wsUser, &userLen) || !wsUser || wsUser[0] == L'\0') {
                if (wsUser) 
                    WTSAPI32$WTSFreeMemory(wsUser);
                continue;
            }

            // Retrieve domain name
            if (!WTSAPI32$WTSQuerySessionInformationW(hServer, curr.ids[i], WTSDomainName, &wsDomain, &domLen) || !wsDomain) {
                WTSAPI32$WTSFreeMemory(wsUser);
                if (wsDomain) 
                    WTSAPI32$WTSFreeMemory(wsDomain);
                continue;
            }

            // Check if logon belongs to a target user
            if (targetUsers && targetUsers[0] != L'\0') {
                if (!IsTargetUser(wsUser, targetUsers)) {
                    WTSAPI32$WTSFreeMemory(wsUser);
                    WTSAPI32$WTSFreeMemory(wsDomain);
                    continue;
                }
            }

            NotifyLogon(hServer, curr.ids[i], wsUser, wsDomain);
            WTSAPI32$WTSFreeMemory(wsUser);
            WTSAPI32$WTSFreeMemory(wsDomain);
        }

        // Update cache
        prev = curr;

        KERNEL32$Sleep((DWORD)(interval * 1000));

    } while (TRUE);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] BOF execution completed.\n");
    
    // Cleanup
    if (hServer)
        WTSAPI32$WTSCloseServer(hServer);
}
