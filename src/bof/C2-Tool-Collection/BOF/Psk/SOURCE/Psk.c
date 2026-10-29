#include <windows.h>
#include "beacon.h"
#include "Psk.h"

#define MAX_SEC_PRD 20
#define MAX_STRING 8192
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef NTSTATUS (NTAPI *fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

INT g_iGarbage = 1;
LPSTREAM g_lpStream = (LPSTREAM)1;
LPWSTR g_lpwPrintBuffer = (LPWSTR)1;
PSECPROD g_pSecProducts[MAX_SEC_PRD] = { (PSECPROD)1 };
DWORD g_dwMSMod = 1, g_dwNonMSMod = 1, g_dwSecModCount = 1, g_dwTotalMod = 1;

HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
	HRESULT hr = S_FALSE;
	va_list argList;
	DWORD dwWritten = 0;

	if (g_lpStream <= (LPSTREAM)1) {
		hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &g_lpStream);
		if (FAILED(hr)) {
			return hr;
		}
	}

	if (g_lpwPrintBuffer <= (LPWSTR)1) {
		g_lpwPrintBuffer = (LPWSTR)MSVCRT$calloc(MAX_STRING, sizeof(WCHAR));
		if (g_lpwPrintBuffer == NULL) {
			hr = E_FAIL;
			goto CleanUp;
		}
	}

	va_start(argList, lpwFormat);
	if (!MSVCRT$_vsnwprintf_s(g_lpwPrintBuffer, MAX_STRING, MAX_STRING - 1, lpwFormat, argList)) {
		hr = E_FAIL;
		goto CleanUp;
	}

	if (g_lpStream != NULL) {
		if (FAILED(hr = g_lpStream->lpVtbl->Write(g_lpStream, g_lpwPrintBuffer,
			(ULONG)MSVCRT$wcslen(g_lpwPrintBuffer) * sizeof(WCHAR), &dwWritten))) {
			goto CleanUp;
		}
	}

	hr = S_OK;

CleanUp:
	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR));
	}
	va_end(argList);
	return hr;
}

VOID BeaconOutputStreamW(void) {
	STATSTG ssStreamData = { 0 };
	SIZE_T cbSize = 0;
	ULONG cbRead = 0;
	LARGE_INTEGER pos;
	LPWSTR lpwOutput = NULL;

	if (FAILED(g_lpStream->lpVtbl->Stat(g_lpStream, &ssStreamData, STATFLAG_NONAME))) {
		return;
	}

	cbSize = ssStreamData.cbSize.LowPart;
	lpwOutput = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 1);
	if (lpwOutput != NULL) {
		pos.QuadPart = 0;
		if (FAILED(g_lpStream->lpVtbl->Seek(g_lpStream, pos, STREAM_SEEK_SET, NULL))) {
			goto CleanUp;
		}
		if (FAILED(g_lpStream->lpVtbl->Read(g_lpStream, lpwOutput, (ULONG)cbSize, &cbRead))) {
			goto CleanUp;
		}
		BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);
	}

CleanUp:
	if (g_lpStream != NULL) {
		g_lpStream->lpVtbl->Release(g_lpStream);
		g_lpStream = NULL;
	}
	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$free(g_lpwPrintBuffer);
		g_lpwPrintBuffer = NULL;
	}
	if (lpwOutput != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
	}
}

static BOOL ConvertKernelPathToDos(_In_z_ const CHAR *kernelPath, _Out_writes_(maxLen) WCHAR *dosPath, _In_ DWORD maxLen) {
	WCHAR winDir[MAX_PATH] = { 0 };
	const CHAR *suffix = NULL;

	if (kernelPath == NULL || dosPath == NULL || maxLen == 0) {
		return FALSE;
	}

	if (KERNEL32$GetWindowsDirectoryW(winDir, _countof(winDir)) == 0) {
		return FALSE;
	}

	if (MSVCRT$_strnicmp(kernelPath, "\\SystemRoot\\", 12) == 0) {
		suffix = kernelPath + 12;
	} else if (kernelPath[0] == '\\') {
		suffix = kernelPath + 1;
	} else {
		suffix = kernelPath;
	}

	MSVCRT$swprintf_s(dosPath, maxLen, L"%ls\\%hs", winDir, suffix);
	return TRUE;
}

BOOL EnumSecurityProc(_In_ LPWSTR lpCompany, _In_ LPWSTR lpDescription) {
	LPCWSTR pwszCompany[27];
	DWORD i = 0;

	pwszCompany[0] = L"ESET";
	pwszCompany[1] = L"McAfee";
	pwszCompany[2] = L"Symantec";
	pwszCompany[3] = L"Sophos";
	pwszCompany[4] = L"Panda";
	pwszCompany[5] = L"Bitdefender";
	pwszCompany[6] = L"Kaspersky";
	pwszCompany[7] = L"AVG";
	pwszCompany[8] = L"Avast";
	pwszCompany[9] = L"Trend Micro";
	pwszCompany[10] = L"F-Secure";
	pwszCompany[11] = L"Comodo";
	pwszCompany[12] = L"Cylance";
	pwszCompany[13] = L"CrowdStrike";
	pwszCompany[14] = L"Carbon Black";
	pwszCompany[15] = L"Palo Alto";
	pwszCompany[16] = L"Sentinel";
	pwszCompany[17] = L"Endgame";
	pwszCompany[18] = L"Cisco";
	pwszCompany[19] = L"Splunk";
	pwszCompany[20] = L"LogRhythm";
	pwszCompany[21] = L"Rapid7";
	pwszCompany[22] = L"Sysinternals";
	pwszCompany[23] = L"FireEye";
	pwszCompany[24] = L"Cybereason";
	pwszCompany[25] = L"Ivanti";
	pwszCompany[26] = L"Darktrace";

	for (i = 0; i < _countof(pwszCompany) && g_dwSecModCount < MAX_SEC_PRD; i++) {
		if (SHLWAPI$StrStrIW(lpCompany, pwszCompany[i])) {
			MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcCompany, lpCompany,
				MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
			MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcDescription, lpDescription,
				MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
			g_dwSecModCount++;
		}
	}

	if (g_dwSecModCount < MAX_SEC_PRD &&
		(SHLWAPI$StrStrIW(lpDescription, L"Antimalware") || SHLWAPI$StrStrIW(lpDescription, L"Windows Defender"))) {
		MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcCompany, lpCompany,
			MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
		MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcDescription, lpDescription,
			MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
		g_dwSecModCount++;
	}

	if (g_dwSecModCount < MAX_SEC_PRD && SHLWAPI$StrStrIW(lpDescription, L"Carbon Black")) {
		MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcCompany, lpCompany,
			MSVCRT$wcslen(lpCompany) * sizeof(WCHAR));
		MSVCRT$memcpy(g_pSecProducts[g_dwSecModCount]->wcDescription, lpDescription,
			MSVCRT$wcslen(lpDescription) * sizeof(WCHAR));
		g_dwSecModCount++;
	}

	if (SHLWAPI$StrStrIW(lpCompany, L"Microsoft")) {
		g_dwMSMod++;
	} else {
		g_dwNonMSMod++;
	}

	return TRUE;
}

BOOL PrintSummary(void) {
	if (g_dwSecModCount > 0) {
		BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
		BeaconPrintToStreamW(L"[!] Security products found: %d\n", g_dwSecModCount);
		for (DWORD i = 0; i < g_dwSecModCount; i++) {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Vendor:", g_pSecProducts[i]->wcCompany);
			BeaconPrintToStreamW(L"%-18ls %ls\n\n", L"    Product:", g_pSecProducts[i]->wcDescription);
		}
	}

	BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
	BeaconPrintToStreamW(L"[S] Kernel Module summary:\n");
	BeaconPrintToStreamW(L"    Microsoft kernel modules:   %d\n", g_dwMSMod);
	BeaconPrintToStreamW(L"    Non Microsoft modules:      %d\n\n", g_dwNonMSMod);
	BeaconPrintToStreamW(L"    Total active Modules:       %d\n\n", g_dwTotalMod);
	return TRUE;
}

BOOL EnumFileProperties(_In_ DWORD dwCount, _In_z_ const CHAR *kernelPath, _In_opt_ PVOID moduleBase, _In_ BOOL bEnumSecurityProc) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBinaryType = SCS_32BIT_BINARY;
	PBYTE lpVerInfo = NULL;
	LPWSTR lpCompany = NULL;
	LPWSTR lpDescription = NULL;
	LPWSTR lpProductVersion = NULL;
	WCHAR dosPath[MAX_PATH] = { 0 };

	if (!ConvertKernelPathToDos(kernelPath, dosPath, _countof(dosPath))) {
		goto CleanUp;
	}

	hFile = KERNEL32$CreateFileW(dosPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		goto CleanUp;
	}

	if (dwCount == 0) {
		BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Path:", dosPath);
	} else {
		BeaconPrintToStreamW(L"%-18ls %ls\n", L"[K] ModulePath:", dosPath);
	}

#if !defined(WOW64)
	if (moduleBase != NULL) {
		BeaconPrintToStreamW(L"%-18ls 0x%p \n", L"    BaseAddress:", moduleBase);
	}

	if (KERNEL32$GetBinaryTypeW(dosPath, &dwBinaryType)) {
		BeaconPrintToStreamW(L"%-18ls %ls\n", L"    ImageType:",
			(dwBinaryType == SCS_64BIT_BINARY) ? L"64-bit" : L"32-bit");
	}
#endif

	DWORD dwHandle = 0;
	DWORD dwLen = VERSION$GetFileVersionInfoSizeW(dosPath, &dwHandle);
	if (!dwLen) {
		goto CleanUp;
	}

	lpVerInfo = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
	if (lpVerInfo == NULL) {
		goto CleanUp;
	}

	if (!VERSION$GetFileVersionInfoW(dosPath, 0L, dwLen, lpVerInfo)) {
		goto CleanUp;
	}

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	WCHAR wcCodePage[MAX_PATH] = { 0 };
	WCHAR wcCompanyName[MAX_PATH] = { 0 };
	WCHAR wcDescription[MAX_PATH] = { 0 };
	WCHAR wcProductVersion[MAX_PATH] = { 0 };
	UINT uLen = 0;

	if (VERSION$VerQueryValueW(lpVerInfo, L"\\VarFileInfo\\Translation", (void **)&lpTranslate, &uLen)) {
		MSVCRT$swprintf_s(wcCodePage, _countof(wcCodePage), L"%04x%04x",
			lpTranslate->wLanguage, lpTranslate->wCodePage);

		MSVCRT$wcscat_s(wcCompanyName, _countof(wcCompanyName), L"\\StringFileInfo\\");
		MSVCRT$wcscat_s(wcCompanyName, _countof(wcCompanyName), wcCodePage);
		MSVCRT$wcscat_s(wcCompanyName, _countof(wcCompanyName), L"\\CompanyName");

		MSVCRT$wcscat_s(wcDescription, _countof(wcDescription), L"\\StringFileInfo\\");
		MSVCRT$wcscat_s(wcDescription, _countof(wcDescription), wcCodePage);
		MSVCRT$wcscat_s(wcDescription, _countof(wcDescription), L"\\FileDescription");

		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\StringFileInfo\\");
		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), wcCodePage);
		MSVCRT$wcscat_s(wcProductVersion, _countof(wcProductVersion), L"\\ProductVersion");

		if (VERSION$VerQueryValueW(lpVerInfo, wcCompanyName, (void **)&lpCompany, &uLen)) {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    CompanyName:", lpCompany);
		}
		if (VERSION$VerQueryValueW(lpVerInfo, wcDescription, (void **)&lpDescription, &uLen)) {
			BeaconPrintToStreamW(L"%-18ls %ls\n", L"    Description:", lpDescription);
		}
		if (VERSION$VerQueryValueW(lpVerInfo, wcProductVersion, (void **)&lpProductVersion, &uLen)) {
			BeaconPrintToStreamW(L"%-18ls %ls\n\n", L"    Version:", lpProductVersion);
		}

		if (bEnumSecurityProc && lpCompany != NULL && lpDescription != NULL) {
			EnumSecurityProc(lpCompany, lpDescription);
		}
	}

CleanUp:
	if (hFile != INVALID_HANDLE_VALUE) {
		KERNEL32$CloseHandle(hFile);
	}
	if (lpVerInfo != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpVerInfo);
	}
	return TRUE;
}

BOOL EnumKernel(void) {
	fnNtQuerySystemInformation NtQuerySystemInformation = NULL;
	NTSTATUS status = 0;
	LPVOID pModInfoBuffer = NULL;
	ULONG modInfoSize = 0x10000;
	ULONG uReturnLength = 0;
	PSYSTEM_MODULE_INFORMATION pModuleInfo = NULL;

	NtQuerySystemInformation = (fnNtQuerySystemInformation)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[-] NtQuerySystemInformation not found.\n");
		return FALSE;
	}

	do {
		if (pModInfoBuffer != NULL) {
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pModInfoBuffer);
			pModInfoBuffer = NULL;
		}

		pModInfoBuffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, modInfoSize);
		if (pModInfoBuffer == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory.\n");
			return FALSE;
		}

		status = NtQuerySystemInformation(SystemModuleInformation, pModInfoBuffer, modInfoSize, &uReturnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			modInfoSize = uReturnLength + 0x1000;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (status != 0) {
		BeaconPrintf(CALLBACK_ERROR, "[-] NtQuerySystemInformation failed: 0x%lx\n", status);
		goto CleanUp;
	}

	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)pModInfoBuffer;
	g_dwTotalMod = pModuleInfo->NumberOfModules;

	for (DWORD i = 0; i < pModuleInfo->NumberOfModules; i++) {
		EnumFileProperties(i, (const CHAR *)pModuleInfo->Module[i].FullPathName,
			pModuleInfo->Module[i].ImageBase, TRUE);
	}

CleanUp:
	if (pModInfoBuffer != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pModInfoBuffer);
	}
	return TRUE;
}

VOID go(_In_ PCHAR Args, _In_ ULONG Length) {
	DWORD sessionId = 0;

	(void)Args;
	(void)Length;

	g_dwMSMod = 0;
	g_dwNonMSMod = 0;
	g_dwSecModCount = 0;
	g_dwTotalMod = 0;

	for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
		g_pSecProducts[i] = (PSECPROD)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECPROD));
	}

	BeaconPrintToStreamW(L"%-19ls %ls\n", L"\n[I] ProcessName:", L"System");
	BeaconPrintToStreamW(L"%-18ls %lu\n", L"    ProcessID:", 4);
	if (KERNEL32$ProcessIdToSessionId(4, &sessionId)) {
		BeaconPrintToStreamW(L"%-18ls %d\n", L"    SessionID:", sessionId);
	}

	EnumKernel();
	PrintSummary();

	if (g_pSecProducts[0] != NULL) {
		for (DWORD i = 0; i < MAX_SEC_PRD; i++) {
			KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, g_pSecProducts[i]);
		}
	}

	BeaconOutputStreamW();
}
