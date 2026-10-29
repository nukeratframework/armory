#include "GetProcAddress.h"
#include "PEB.h"
#include "my_cstring.h"
#include "Helper.h"
#include "FileIO.h"
#include "win32.h"

typedef FARPROC(WINAPI* MyGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI* MyLoadLibraryA)(LPCSTR lpModuleName);

typedef FARPROC(WINAPI* GetProcAddressProcc)(HMODULE, LPCSTR);

HMODULE GetLoadedDLLBasePEB(LPCWSTR Name) {
	
	PLIST_ENTRY listHead = &NtCurrentPeb()->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY listEntry = listHead->Flink;

	if (listHead == NULL || listEntry == NULL)
		return NULL;

	while (listEntry != listHead) {
		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (ldrEntry->BaseDllName.Length > 0 && ldrEntry->BaseDllName.Buffer != NULL) {
			if (my_wstricmp(Name, ldrEntry->BaseDllName.Buffer) == 0) {
				return (HMODULE)ldrEntry->DllBase;
			}
		}
		listEntry = listEntry->Flink;
	}
	return nullptr;
}

HMODULE GetKernel32BaseAddress() {
	PPEB PebAddress;

	//PEB offset is always fixed depending or arch
#if defined(_WIN64)
	PebAddress = (PPEB)__readgsqword(0x60);
#else
	PebAddress = (PPEB)__readfsdword(0x30);
#endif

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)PebAddress->Ldr;
	//First one is the current module
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderModuleList.Flink;
	//Second will be ntdll.dll
	pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;
	//And the third will be the Kernel32.dll
	pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

	return (HMODULE)pDataTableEntry->DllBase;
}

FARPROC GetProcAddressPEB(const char* procName)
{
	PPEB PebAddress;
	PPEB_LDR_DATA pLdr;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry;
	PVOID pModuleBase;
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD dwExportDirRVA;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	USHORT usOrdinalTableIndex;
	PDWORD pdwFunctionNameBase;
	char* pFunctionName;
	DWORD dwNumFunctions;

	//PEB offset is always fixed depending or arch
#if defined(_WIN64)
	PebAddress = (PPEB)__readgsqword(0x60);
#else
	PebAddress = (PPEB)__readfsdword(0x30);
#endif

	pLdr = (PPEB_LDR_DATA)PebAddress->Ldr;
	//First one is the current module
	pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderModuleList.Flink;
	//Second will be ntdll.dll
	pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;
	//And the third will be the Kernel32.dll
	pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;


	if (pDataTableEntry->DllBase != NULL)
	{
		pModuleBase = pDataTableEntry->DllBase; //Kernel32 base address, we need this for using GetProcAddress
		pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
		dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
		pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);
		dwNumFunctions = pExportDir->NumberOfNames;
		pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);
		for (size_t i = 0; i < dwNumFunctions; i++)
		{
			pFunctionName = (char*)(*pdwFunctionNameBase + (ULONG_PTR)pModuleBase);
			if (my_strcmp(procName, pFunctionName) == 0)
			{
				usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
				return (FARPROC)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));
			}
			pdwFunctionNameBase++;
		}
	}

	// All modules have been exhausted and the function was not found.
	return NULL;
}

FARPROC GetProc(const char* module, const char* func, Pointers* ctx) {
	wchar_t arr[256];
	charToWChar(module, arr, 256);
	HMODULE hMod = GetLoadedDLLBasePEB(arr);
	if (hMod == nullptr)
		hMod = ctx->pLoadLibraryA(module);

	if (hMod == nullptr)
		return nullptr;

	if (ctx->pGetProcAddress == nullptr)
		return nullptr;

	return ctx->pGetProcAddress(hMod, func);
}

LPVOID GetHeapAddress() {
	PPEB PebAddress = nullptr;
#if defined(_WIN64)
	PebAddress = (PPEB)__readgsqword(0x60);
#else
	PebAddress = (PPEB)__readfsdword(0x30);
#endif

	return PebAddress->ProcessHeap;
}

BOOL InitPointers(Pointers* ctx, const char* fileName) {
	// Find kernel32.dll
	PICWARR(kernel32w, "KERNEL32.DLL");
	HMODULE hKernel32 = GetLoadedDLLBasePEB(kernel32w);
	if (hKernel32 == NULL)
		return FALSE;

	// Resolve GetProcAddress first - we need it to find everything else
	PICARR(sGetProcAddress, "GetProcAddress");
	ctx->pGetProcAddress = (Pointers::fnGetProcAddress)GetProcAddressPEB(sGetProcAddress);
	if (ctx->pGetProcAddress == NULL)
		return FALSE;

	// Now use GetProcAddress to resolve the rest
	PICARR(sLoadLibraryA, "LoadLibraryA");
	ctx->pLoadLibraryA = (Pointers::fnLoadLibraryA)ctx->pGetProcAddress(hKernel32, sLoadLibraryA);
	if (ctx->pLoadLibraryA == NULL)
		return FALSE;

	PICARR(sHeapAlloc, "HeapAlloc");
	ctx->pHeapAlloc = (Pointers::fnHeapAlloc)ctx->pGetProcAddress(hKernel32, sHeapAlloc);
	if (ctx->pHeapAlloc == NULL)
		return FALSE;

	PICARR(sHeapFree, "HeapFree");
	ctx->pHeapFree = (Pointers::fnHeapFree)ctx->pGetProcAddress(hKernel32, sHeapFree);
	if (ctx->pHeapFree == NULL)
		return FALSE;

	// Cache the process heap handle
	ctx->hHeap = GetHeapAddress();
	if (ctx->hHeap == NULL)
		return FALSE;

	PICARR(sCreateFileA, "CreateFileA");
	ctx->pCreateFileA = (Pointers::fnCreateFileA)ctx->pGetProcAddress(hKernel32, sCreateFileA);
	if (ctx->pCreateFileA == NULL)
		return FALSE;

	PICARR(sSetFilePointerEx, "SetFilePointerEx");
	ctx->pSetFilePointerEx = (Pointers::fnSetFilePointerEx)ctx->pGetProcAddress(hKernel32, sSetFilePointerEx);
	if (ctx->pSetFilePointerEx == NULL)
		return FALSE;
	
	PICARR(sWriteFile, "WriteFile");
	ctx->pWriteFile = (Pointers::fnWriteFile)ctx->pGetProcAddress(hKernel32, sWriteFile);
	if (ctx->pWriteFile == NULL)
		return FALSE;

	PICARR(sCloseHandle, "CloseHandle");
	ctx->pCloseHandle = (Pointers::fnCloseHandle)ctx->pGetProcAddress(hKernel32, sCloseHandle);
	if (ctx->pCloseHandle == NULL)
		return FALSE;

	DFR_CACHE(KERNEL32, GetTempPathA, ctx);
	char filePath[260];
	DWORD len = GetTempPathA(260, filePath);

	// Append filename
	for (size_t i = 0; fileName[i] != '\0'; i++)
		filePath[len + i] = fileName[i];
	filePath[len + my_strlen(fileName)] = '\0';

	ctx->hOutFile = OpenOrCreateFileForAppend(ctx, filePath);
	if (ctx->hOutFile == NULL)
		return FALSE;

	return TRUE;
}

LPVOID MyHeapAlloc(SIZE_T size, Pointers* ctx) {
	if (ctx == NULL || size == 0)
		return NULL;

	return ctx->pHeapAlloc(ctx->hHeap, HEAP_ZERO_MEMORY, size);
}

BOOL MyHeapFree(LPVOID ptr, Pointers* ctx) {
	if (ctx == NULL || ptr == NULL)
		return FALSE;

	return ctx->pHeapFree(ctx->hHeap, 0, ptr);
}