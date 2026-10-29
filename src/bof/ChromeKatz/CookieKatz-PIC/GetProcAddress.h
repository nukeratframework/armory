#pragma once
#include <wtypes.h>

enum class Config {
    Chrome,
    Edge
};

struct Pointers {

    Config targetConfig = Config::Chrome;

    typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);
    typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
    typedef LPVOID(WINAPI* fnHeapAlloc)(HANDLE, DWORD, SIZE_T);
    typedef BOOL(WINAPI* fnHeapFree)(HANDLE, DWORD, LPVOID);

    fnGetProcAddress pGetProcAddress = nullptr;
    fnLoadLibraryA pLoadLibraryA = nullptr;
    fnHeapAlloc pHeapAlloc = nullptr;
    fnHeapFree pHeapFree = nullptr;
    HANDLE hHeap = nullptr;
    HANDLE hOutFile = nullptr;

    //Output functions
    typedef HANDLE(WINAPI* fnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL(WINAPI* fnSetFilePointerEx)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
    typedef BOOL(WINAPI* fnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL(WINAPI* fnCloseHandle)(HANDLE);

    fnCreateFileA pCreateFileA = nullptr;
    fnSetFilePointerEx pSetFilePointerEx = nullptr;
    fnWriteFile pWriteFile = nullptr;
    fnCloseHandle pCloseHandle = nullptr;
};

BOOL InitPointers(Pointers* ctx, const char* filePath);
FARPROC GetProc(const char* module, const char* func, Pointers* ctx);
HMODULE GetLoadedDLLBasePEB(LPCWSTR Name);

LPVOID MyHeapAlloc(SIZE_T size, Pointers* ctx);
BOOL MyHeapFree(LPVOID ptr, Pointers* ctx);