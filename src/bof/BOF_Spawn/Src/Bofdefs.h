#include <windows.h>
#include <tlhelp32.h>

DECLSPEC_IMPORT	PRUNTIME_FUNCTION WINAPI	KERNEL32$RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase,PUNWIND_HISTORY_TABLE HistoryTable);
DECLSPEC_IMPORT	HMODULE WINAPI	            KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT FARPROC WINAPI 	            KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

DECLSPEC_IMPORT ULONG NTAPI 	            NTDLL$RtlRandomEx(PULONG seed);

DECLSPEC_IMPORT PCHAR __cdecl 	            MSVCRT$strcmp(const char* str1, const char* str2);

#define RtlLookupFunctionEntry  KERNEL32$RtlLookupFunctionEntry
#define GetModuleHandleA        KERNEL32$GetModuleHandleA
#define GetProcAddress          KERNEL32$GetProcAddress

#define RtlRandomEx             NTDLL$RtlRandomEx

#define strcmp                  MSVCRT$strcmp


DECLSPEC_IMPORT HANDLE WINAPI 	            KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessId);
DECLSPEC_IMPORT BOOL WINAPI 	            KERNEL32$Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT BOOL WINAPI 	            KERNEL32$Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT DWORD WINAPI 	            KERNEL32$GetLastError();


DECLSPEC_IMPORT PCWSTR WINAPI         SHLWAPI$StrStrW(PCWSTR pszFirst, PCWSTR pszSrch);


#define CreateToolhelp32Snapshot   KERNEL32$CreateToolhelp32Snapshot
#define Process32FirstW            KERNEL32$Process32FirstW
#define Process32NextW             KERNEL32$Process32NextW
#define GetLastError                KERNEL32$GetLastError

#define Process32First              Process32FirstW
#define Process32Next               Process32NextW


#define StrStrW                     SHLWAPI$StrStrW


DECLSPEC_IMPORT VOID    NTAPI   NTDLL$RtlInitUnicodeString(PUNICODE_STRING  DestinationString, PCWSTR SourceString);
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$RtlCreateProcessParametersEx(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags );
DECLSPEC_IMPORT PVOID   NTAPI NTDLL$RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);


#define RtlInitUnicodeString    NTDLL$RtlInitUnicodeString
#define RtlCreateProcessParametersEx    NTDLL$RtlCreateProcessParametersEx
#define RtlAllocateHeap         NTDLL$RtlAllocateHeap