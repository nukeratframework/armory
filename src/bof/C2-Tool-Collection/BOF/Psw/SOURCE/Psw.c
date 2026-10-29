#include <windows.h>
#include "beacon.h"
#include "Psw.h"

#define MAX_NAME 8192
#define MAX_CACHE 64

typedef struct {
	ULONG count;
	ULONG pids[MAX_CACHE];
	CHAR names[MAX_CACHE][MAX_PATH];
} PROCESS_CACHE;

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$K32GetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize);

typedef struct {
	PROCESS_CACHE *cache;
} PSW_CONTEXT;

static const CHAR *GetBaseNameA(_In_z_ const CHAR *path) {
	const CHAR *slash = path;

	if (path == NULL) {
		return "unknown";
	}

	while (*path != '\0') {
		if (*path == '\\' || *path == '/') {
			slash = path + 1;
		}
		path++;
	}

	return (*slash != '\0') ? slash : "unknown";
}

static const CHAR *LookupProcessName(_Inout_ PROCESS_CACHE *cache, _In_ ULONG processId) {
	ULONG i = 0;
	HANDLE hProcess = NULL;
	CHAR imagePath[MAX_PATH] = { 0 };

	if (cache == NULL || processId == 0) {
		return "unknown";
	}

	for (i = 0; i < cache->count; i++) {
		if (cache->pids[i] == processId) {
			return cache->names[i];
		}
	}

	if (cache->count >= MAX_CACHE) {
		return "unknown";
	}

	hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (hProcess == NULL) {
		hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
	}
	if (hProcess == NULL) {
		MSVCRT$strncpy(cache->names[cache->count], "unknown", MAX_PATH - 1);
	}
	else if (KERNEL32$K32GetProcessImageFileNameA(hProcess, imagePath, MAX_PATH) == 0) {
		MSVCRT$strncpy(cache->names[cache->count], "unknown", MAX_PATH - 1);
	}
	else {
		MSVCRT$strncpy(cache->names[cache->count], GetBaseNameA(imagePath), MAX_PATH - 1);
	}
	cache->names[cache->count][MAX_PATH - 1] = '\0';
	cache->pids[cache->count] = processId;
	cache->count++;

	if (hProcess != NULL) {
		KERNEL32$CloseHandle(hProcess);
	}

	return cache->names[cache->count - 1];
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	PSW_CONTEXT *ctx = (PSW_CONTEXT *)lParam;
	DWORD dwProcessId = 0;
	PCHAR pWindowTitle = NULL;
	const CHAR *processName = NULL;

	if (!hWnd || ctx == NULL || ctx->cache == NULL) {
		return TRUE;
	}

	if (!USER32$IsWindowVisible(hWnd)) {
		return TRUE;
	}

	pWindowTitle = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_NAME);
	if (pWindowTitle == NULL) {
		return TRUE;
	}

	if (!USER32$SendMessageA(hWnd, WM_GETTEXT, MAX_NAME, (LPARAM)pWindowTitle) || pWindowTitle[0] == '\0') {
		goto CleanUp;
	}

	USER32$GetWindowThreadProcessId(hWnd, &dwProcessId);
	if (dwProcessId == 0) {
		goto CleanUp;
	}

	processName = LookupProcessName(ctx->cache, dwProcessId);
	BeaconPrintf(CALLBACK_OUTPUT,
		"[+] ProcessName:\t %s\n"
		"    ProcessID:\t %d\n"
		"    WindowTitle:\t %s\n",
		processName,
		dwProcessId,
		pWindowTitle);

CleanUp:

	if (pWindowTitle != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pWindowTitle);
	}

	return TRUE;
}

VOID go(IN PCHAR Args, IN ULONG Length) {
	PROCESS_CACHE *cache = NULL;
	PSW_CONTEXT ctx = { 0 };

	(void)Args;
	(void)Length;

	cache = (PROCESS_CACHE *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PROCESS_CACHE));
	if (cache == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate process cache.\n");
		return;
	}

	ctx.cache = cache;
	USER32$EnumWindows(EnumWindowsProc, (LPARAM)&ctx);
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, cache);
}
