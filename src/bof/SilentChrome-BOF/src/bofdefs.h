#pragma once
#pragma intrinsic(memcmp, memcpy, strcpy, strcmp, _stricmp, strlen)
#define SECURITY_WIN32
#include <windows.h>
#include <process.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <bcrypt.h>

#ifdef BOF

// KERNEL32
WINBASEAPI void* WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI int WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI VOID WINAPI KERNEL32$SetLastError(DWORD dwErrCode);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
WINBASEAPI BOOL WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI BOOL WINAPI KERNEL32$SystemTimeToFileTime(CONST SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime);
WINBASEAPI int WINAPI Kernel32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

// File I/O
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI KERNEL32$CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileA(LPCSTR lpFileName);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);

// Process
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI KERNEL32$TerminateProcess(HANDLE hProcess, UINT uExitCode);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
DECLSPEC_IMPORT DWORD KERNEL32$GetCurrentProcessId(VOID);

// MSVCRT
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void* __cdecl MSVCRT$malloc(size_t _Size);
WINBASEAPI void* __cdecl MSVCRT$realloc(void* _Memory, size_t _NewSize);
WINBASEAPI void __cdecl MSVCRT$free(void* _Memory);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict__ _Dst, const void* __restrict__ _Src, size_t _MaxCount);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void* _Buf1, const void* _Buf2, size_t _Size);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI void* __cdecl MSVCRT$memmove(void* dest, const void* src, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* _Str);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char* string1, const char* string2);
WINBASEAPI int __cdecl MSVCRT$strncmp(const char* _Str1, const char* _Str2, size_t _MaxCount);
WINBASEAPI char* __cdecl MSVCRT$strcpy(char* __restrict__ __dst, const char* __restrict__ __src);
WINBASEAPI char* __cdecl MSVCRT$strncpy(char* __restrict__ __dst, const char* __restrict__ __src, size_t _MaxCount);
WINBASEAPI char* __cdecl MSVCRT$strcat(char* __restrict__ _Dest, const char* __restrict__ _Source);
WINBASEAPI char* __cdecl MSVCRT$strstr(const char* haystack, const char* needle);
WINBASEAPI char* __cdecl MSVCRT$strchr(const char* haystack, int needle);
WINBASEAPI char* __cdecl MSVCRT$strrchr(const char* _Str, int _Ch);
WINBASEAPI int __cdecl MSVCRT$sprintf(char* __stream, const char* __format, ...);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char* __restrict__ d, size_t n, const char* __restrict__ format, ...);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char* __restrict__ d, size_t n, const char* __restrict__ format, va_list arg);
WINBASEAPI int __cdecl MSVCRT$sscanf(const char* _Src, const char* _Format, ...);
WINBASEAPI double __cdecl MSVCRT$strtod(const char* _Str, char** _EndPtr);
WINBASEAPI long __cdecl MSVCRT$strtol(const char* _Str, char** _EndPtr, int _Radix);
WINBASEAPI unsigned long __cdecl MSVCRT$strtoul(const char* __restrict__ _Str, char** __restrict__ _EndPtr, int _Radix);
WINBASEAPI double __cdecl MSVCRT$floor(double _X);
WINBASEAPI double __cdecl MSVCRT$pow(double _X, double _Y);
WINBASEAPI double __cdecl MSVCRT$fabs(double _X);
WINBASEAPI int __cdecl MSVCRT$_vscprintf(const char* _Format, va_list _ArgList);
WINBASEAPI int __cdecl MSVCRT$tolower(int _Ch);
WINBASEAPI int __cdecl MSVCRT$toupper(int _Ch);
WINBASEAPI int __cdecl MSVCRT$isdigit(int _Ch);
WINBASEAPI int __cdecl MSVCRT$isxdigit(int _Ch);
WINBASEAPI int __cdecl MSVCRT$isprint(int _Ch);

// ADVAPI32
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread(VOID);
WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINADVAPI BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid, LPSTR* StringSid);
WINADVAPI BOOL WINAPI ADVAPI32$ConvertStringSidToSidA(LPCSTR StringSid, PSID* Sid);
WINADVAPI BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);

DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

// BCrypt
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, DWORD dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, DWORD dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE *phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);

// Heap macros
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size) (ptr) ? KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) : KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

// cJSON compatibility shims
#define malloc(size) MSVCRT$malloc(size)
#define calloc(num, size) MSVCRT$calloc(num, size)
#define realloc(ptr, size) MSVCRT$realloc(ptr, size)
#define free(ptr) MSVCRT$free(ptr)
#define memcpy(dst, src, n) MSVCRT$memcpy(dst, src, n)
#define memcmp(a, b, n) MSVCRT$memcmp(a, b, n)
#define memset(dst, c, n) MSVCRT$memset(dst, c, n)
#define memmove(dst, src, n) MSVCRT$memmove(dst, src, n)
#define strlen(s) MSVCRT$strlen(s)
#define strcmp(a, b) MSVCRT$strcmp(a, b)
#define strncmp(a, b, n) MSVCRT$strncmp(a, b, n)
#define strcpy(dst, src) MSVCRT$strcpy(dst, src)
#define strncpy(dst, src, n) MSVCRT$strncpy(dst, src, n)
#define strcat(dst, src) MSVCRT$strcat(dst, src)
#define strstr(h, n) MSVCRT$strstr(h, n)
#define strchr(h, n) MSVCRT$strchr(h, n)
#define strrchr(s, c) MSVCRT$strrchr(s, c)
#define sprintf MSVCRT$sprintf
#define snprintf MSVCRT$_snprintf
#define vsnprintf MSVCRT$vsnprintf
#define sscanf MSVCRT$sscanf
#define strtod(s, e) MSVCRT$strtod(s, e)
#define strtol(s, e, b) MSVCRT$strtol(s, e, b)
#define strtoul(s, e, b) MSVCRT$strtoul(s, e, b)
#define floor(x) MSVCRT$floor(x)
#define pow(x, y) MSVCRT$pow(x, y)
#define fabs(x) MSVCRT$fabs(x)
#define tolower(c) MSVCRT$tolower(c)
#define toupper(c) MSVCRT$toupper(c)
#define isdigit(c) MSVCRT$isdigit(c)
#define isxdigit(c) MSVCRT$isxdigit(c)
#define isprint(c) MSVCRT$isprint(c)
#define _vscprintf(f, a) MSVCRT$_vscprintf(f, a)

#else

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size) (ptr) ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size) : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)
#define intZeroMemory(addr,size) memset((addr),0,size)

#endif
