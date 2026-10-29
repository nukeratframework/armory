#define _WIN32_WINNT 0x0600
#include <windows.h>
#include "../Kerbeus/_include/beacon.h"

DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegConnectRegistryA(LPCSTR lpMachineName, HKEY hKey, PHKEY phkResult);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyExA(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);

static int streq(const char *a, const char *b) {
	if (a == NULL || b == NULL) {
		return 0;
	}
	while (*a != '\0' && *b != '\0' && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static HKEY ParseHive(const char *hive) {
	if (hive == NULL || hive[0] == '\0') {
		return NULL;
	}
	if (streq(hive, "HKCR")) {
		return HKEY_CLASSES_ROOT;
	}
	if (streq(hive, "HKCU")) {
		return HKEY_CURRENT_USER;
	}
	if (streq(hive, "HKLM")) {
		return HKEY_LOCAL_MACHINE;
	}
	if (streq(hive, "HKU")) {
		return HKEY_USERS;
	}
	if (streq(hive, "HKCC")) {
		return HKEY_CURRENT_CONFIG;
	}
	return NULL;
}

static DWORD DeleteRegKey(char *hostname, HKEY hive, char *path, char *key) {
	DWORD dwresult = ERROR_SUCCESS;
	HKEY rootkey = NULL;
	HKEY remoteKey = NULL;

	if (hostname != NULL) {
		dwresult = ADVAPI32$RegConnectRegistryA(hostname, hive, &remoteKey);
		if (dwresult != ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "[-] Error RegConnectRegistryA %lX\n", dwresult);
			goto delete_regkey_end;
		}
	}

	dwresult = ADVAPI32$RegOpenKeyExA((hostname != NULL) ? remoteKey : hive, NULL, 0, KEY_READ | KEY_SET_VALUE, &rootkey);
	if (dwresult != ERROR_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR, "[-] Error RegOpenKeyExA: %lX\n", dwresult);
		goto delete_regkey_end;
	}

	if (key != NULL) {
		dwresult = ADVAPI32$RegDeleteKeyValueA(rootkey, path, key);
		if (dwresult != ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "[-] Error RegDeleteKeyValueA: %lX\n", dwresult);
			goto delete_regkey_end;
		}
	} else {
		dwresult = ADVAPI32$RegDeleteKeyExA(rootkey, path, 0, 0);
		if (dwresult != ERROR_SUCCESS) {
			BeaconPrintf(CALLBACK_ERROR, "[-] Error RegDeleteKeyExA: %lX\n", dwresult);
			goto delete_regkey_end;
		}
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Success\n");

delete_regkey_end:
	if (remoteKey != NULL) {
		ADVAPI32$RegCloseKey(remoteKey);
	}
	if (rootkey != NULL) {
		ADVAPI32$RegCloseKey(rootkey);
	}
	return dwresult;
}

VOID go(PCHAR args, ULONG length) {
	datap parser;
	char *hostname = NULL;
	char *hiveName = NULL;
	char *path = NULL;
	char *key = NULL;
	HKEY hive = NULL;
	const char *hiveLabel = NULL;

	BeaconDataParse(&parser, args, length);
	hostname = BeaconDataExtract(&parser, NULL);
	hiveName = BeaconDataExtract(&parser, NULL);
	path = BeaconDataExtract(&parser, NULL);
	key = BeaconDataExtract(&parser, NULL);

	if (hiveName == NULL || path == NULL || hiveName[0] == '\0' || path[0] == '\0') {
		BeaconPrintf(CALLBACK_ERROR, "[!] Usage: bof-reg-del --- [hostname] <Hive> <Path> [ValueName]\n");
		BeaconPrintf(CALLBACK_ERROR, "[!] Hive: HKCR, HKCU, HKLM, HKU, HKCC. Use localhost for local.\n");
		return;
	}

	if (hostname != NULL && (hostname[0] == '\0' || streq(hostname, "localhost"))) {
		hostname = NULL;
	}
	if (key != NULL && key[0] == '\0') {
		key = NULL;
	}

	hive = ParseHive(hiveName);
	if (hive == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[-] Invalid hive. Use HKCR, HKCU, HKLM, HKU or HKCC.\n");
		return;
	}

	if (streq(hiveName, "HKCR")) {
		hiveLabel = "HKEY_CLASSES_ROOT";
	} else if (streq(hiveName, "HKCU")) {
		hiveLabel = "HKEY_CURRENT_USER";
	} else if (streq(hiveName, "HKLM")) {
		hiveLabel = "HKEY_LOCAL_MACHINE";
	} else if (streq(hiveName, "HKU")) {
		hiveLabel = "HKEY_USERS";
	} else {
		hiveLabel = "HKEY_CURRENT_CONFIG";
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[*] HKEY : %s\n", hiveName);
	if (key != NULL) {
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Deleting: %s\\%s\\%s => %s\n",
			(hostname != NULL) ? hostname : "localhost", hiveLabel, path, key);
	} else {
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Deleting: %s\\%s\\%s\n",
			(hostname != NULL) ? hostname : "localhost", hiveLabel, path);
	}

	DeleteRegKey(hostname, hive, path, key);
}
