#pragma once

#include "Native.h"

typedef struct _VX_TABLE_ENTRY {
	PVOID	Gadget;
	DWORD	SyscallNumber;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY	NtOpenProcess;
	VX_TABLE_ENTRY	NtCreateUserProcess;
	VX_TABLE_ENTRY	NtAllocateVirtualMemory;
	VX_TABLE_ENTRY	NtWriteVirtualMemory;
	VX_TABLE_ENTRY	NtGetContextThread;
	VX_TABLE_ENTRY	NtSetContextThread;
	VX_TABLE_ENTRY	NtProtectVirtualMemory;
	VX_TABLE_ENTRY	NtResumeProcess;
	VX_TABLE_ENTRY	NtClose;
} VX_TABLE, *PVX_TABLE;
