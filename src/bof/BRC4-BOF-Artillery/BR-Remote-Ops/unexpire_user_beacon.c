#include <windows.h>
#include <lmaccess.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

DWORD UnexpireUser(LPCWSTR lpswzServer, LPCWSTR lpswzUserName)
{
	USER_INFO_1017 newFlags = {0};
	NET_API_STATUS status;
	DWORD parmErr = 0;
	LPCWSTR targetServer = lpswzServer;

	if (targetServer == NULL || targetServer[0] == L'\0' || targetServer[0] == L'.')
	{
		targetServer = NULL;
	}

	newFlags.usri1017_acct_expires = TIMEQ_FOREVER;
	status = NETAPI32$NetUserSetInfo(targetServer, lpswzUserName, 1017, (LPBYTE)&newFlags, &parmErr);
	if (status != NERR_Success)
	{
		BeaconPrintf(CALLBACK_ERROR, "NetUserSetInfo failed: 0x%08lx (parm_err=%lu)\n", status, parmErr);
		return status;
	}

	internal_printf("[+] Account set to never expire\n");
	return ERROR_SUCCESS;
}

#ifdef BOF
VOID go(IN PCHAR buffer, IN ULONG length)
{
	datap parser = {0};
	LPCWSTR username = NULL;
	LPCWSTR hostname = NULL;

	if (!bofstart())
	{
		return;
	}

	BeaconDataParse(&parser, buffer, length);
	username = (LPCWSTR)BeaconDataExtract(&parser, NULL);
	hostname = (LPCWSTR)BeaconDataExtract(&parser, NULL);

	if (username == NULL || username[0] == L'\0')
	{
		BeaconPrintf(CALLBACK_ERROR, "Usage: bof-unexpire-user --- <username> [hostname]\n");
		goto go_end;
	}

	if (hostname == NULL || hostname[0] == L'\0' || hostname[0] == L'.')
	{
		internal_printf("[+] Enabling local user: '%S'\n", username);
	}
	else
	{
		internal_printf("[+] Enabling user: '%S\\%S'\n", hostname, username);
	}
	UnexpireUser(hostname, username);

go_end:
	printoutput(TRUE);
	bofstop();
}
#endif
