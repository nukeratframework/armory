/*
 * Token2Cert BOF Definitions
 * Token Stealing + Certificate Enrollment + PKINIT + UnPAC
 */

#ifndef _BOFDEFS_H_
#define _BOFDEFS_H_

#include <windows.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <winldap.h>
#include <winber.h>
#include <dsgetdc.h>
#include <lm.h>
#include <wincrypt.h>

#include "beacon.h"

#ifdef BOF

/* ============================================================================
 * DFR - Dynamic Function Resolution for BOF
 * ============================================================================ */

/* Kernel32 */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ProcessIdToSessionId(DWORD, DWORD*);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);

/* Advapi32 - Token Functions */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptExportKey(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*);

/* WtsApi32 - Session Functions */
DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSEnumerateSessionsW(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSQuerySessionInformationW(HANDLE, DWORD, WTS_INFO_CLASS, LPWSTR*, DWORD*);
DECLSPEC_IMPORT void WINAPI WTSAPI32$WTSFreeMemory(PVOID);

/* Crypt32 */
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptEncodeObjectEx(DWORD, LPCSTR, const void*, DWORD, PCRYPT_ENCODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptDecodeObjectEx(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptBinaryToStringA(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext(DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertAddCertificateContextToStore(HCERTSTORE, PCCERT_CONTEXT, DWORD, PCCERT_CONTEXT*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertSetCertificateContextProperty(PCCERT_CONTEXT, DWORD, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$PFXExportCertStoreEx(HCERTSTORE, CRYPT_DATA_BLOB*, LPCWSTR, void*, DWORD);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$PFXImportCertStore(CRYPT_DATA_BLOB*, LPCWSTR, DWORD);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT, DWORD, void*, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE*, DWORD*, BOOL*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptSignMessage(PCRYPT_SIGN_MESSAGE_PARA, BOOL, DWORD, const BYTE*[], DWORD[], BYTE*, DWORD*);
DECLSPEC_IMPORT HCRYPTMSG WINAPI CRYPT32$CryptMsgOpenToEncode(DWORD, DWORD, DWORD, const void*, LPSTR, PCMSG_STREAM_INFO);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgUpdate(HCRYPTMSG, const BYTE*, DWORD, BOOL);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgGetParam(HCRYPTMSG, DWORD, DWORD, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgClose(HCRYPTMSG);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptSignAndEncodeCertificate(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, DWORD, DWORD, LPCSTR, const void*, PCRYPT_ALGORITHM_IDENTIFIER, const void*, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertStrToNameA(DWORD, LPCSTR, DWORD, void*, BYTE*, DWORD*, LPCSTR*);

/* COM - OLE32/OLEAUT32 */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPVOID, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateGuid(GUID*);
DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void WINAPI OLEAUT32$SysFreeString(BSTR);

/* Winsock */
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT struct hostent* WSAAPI WS2_32$gethostbyname(const char*);
DECLSPEC_IMPORT unsigned short WSAAPI WS2_32$htons(unsigned short);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$htonl(unsigned long);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$ntohl(unsigned long);

/* NetAPI */
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

/* LDAP */
DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_set_optionW(LDAP*, int, const void*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT struct berval** LDAPAPI WLDAP32$ldap_get_values_lenW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP*);

/* MSVCRT */
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$atoi(const char*);

#else /* Non-BOF compilation */

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wldap32.lib")

#define KERNEL32$CreateToolhelp32Snapshot   CreateToolhelp32Snapshot
#define KERNEL32$Process32FirstW            Process32FirstW
#define KERNEL32$Process32NextW             Process32NextW
#define KERNEL32$ProcessIdToSessionId       ProcessIdToSessionId
#define KERNEL32$OpenProcess                OpenProcess
#define KERNEL32$CloseHandle                CloseHandle
#define KERNEL32$GetLastError               GetLastError
#define KERNEL32$LocalAlloc                 LocalAlloc
#define KERNEL32$LocalFree                  LocalFree
#define KERNEL32$MultiByteToWideChar        MultiByteToWideChar
#define KERNEL32$WideCharToMultiByte        WideCharToMultiByte
#define KERNEL32$GetSystemTime              GetSystemTime
#define KERNEL32$LoadLibraryA               LoadLibraryA
#define KERNEL32$GetProcAddress             GetProcAddress
#define KERNEL32$FreeLibrary                FreeLibrary

#define ADVAPI32$OpenProcessToken           OpenProcessToken
#define ADVAPI32$DuplicateTokenEx           DuplicateTokenEx
#define ADVAPI32$ImpersonateLoggedOnUser    ImpersonateLoggedOnUser
#define ADVAPI32$RevertToSelf               RevertToSelf
#define ADVAPI32$GetTokenInformation        GetTokenInformation
#define ADVAPI32$LookupAccountSidW          LookupAccountSidW
#define ADVAPI32$ConvertSidToStringSidW     ConvertSidToStringSidW
#define ADVAPI32$CryptAcquireContextW       CryptAcquireContextW
#define ADVAPI32$CryptReleaseContext        CryptReleaseContext
#define ADVAPI32$CryptGenKey                CryptGenKey
#define ADVAPI32$CryptDestroyKey            CryptDestroyKey
#define ADVAPI32$CryptGenRandom             CryptGenRandom
#define ADVAPI32$CryptCreateHash            CryptCreateHash
#define ADVAPI32$CryptHashData              CryptHashData
#define ADVAPI32$CryptGetHashParam          CryptGetHashParam
#define ADVAPI32$CryptDestroyHash           CryptDestroyHash
#define ADVAPI32$CryptExportKey             CryptExportKey

#define WTSAPI32$WTSEnumerateSessionsW      WTSEnumerateSessionsW
#define WTSAPI32$WTSQuerySessionInformationW WTSQuerySessionInformationW
#define WTSAPI32$WTSFreeMemory              WTSFreeMemory

#define CRYPT32$CryptBinaryToStringA        CryptBinaryToStringA
#define CRYPT32$CryptStringToBinaryA        CryptStringToBinaryA
#define CRYPT32$CertOpenStore               CertOpenStore
#define CRYPT32$CertCloseStore              CertCloseStore
#define CRYPT32$PFXExportCertStoreEx        PFXExportCertStoreEx
#define CRYPT32$PFXImportCertStore          PFXImportCertStore
#define CRYPT32$CertEnumCertificatesInStore CertEnumCertificatesInStore
#define CRYPT32$CryptSignAndEncodeCertificate CryptSignAndEncodeCertificate

#define OLE32$CoInitializeEx                CoInitializeEx
#define OLE32$CoUninitialize                CoUninitialize
#define OLE32$CoCreateInstance              CoCreateInstance
#define OLE32$CoCreateGuid                  CoCreateGuid
#define OLEAUT32$SysAllocString             SysAllocString
#define OLEAUT32$SysFreeString              SysFreeString

#define WS2_32$WSAStartup                   WSAStartup
#define WS2_32$WSACleanup                   WSACleanup
#define WS2_32$socket                       socket
#define WS2_32$connect                      connect
#define WS2_32$send                         send
#define WS2_32$recv                         recv
#define WS2_32$closesocket                  closesocket
#define WS2_32$gethostbyname                gethostbyname
#define WS2_32$htons                        htons
#define WS2_32$htonl                        htonl
#define WS2_32$ntohl                        ntohl

#define NETAPI32$DsGetDcNameW               DsGetDcNameW
#define NETAPI32$NetApiBufferFree           NetApiBufferFree

#define WLDAP32$ldap_initW                  ldap_initW
#define WLDAP32$ldap_set_optionW            ldap_set_optionW
#define WLDAP32$ldap_bind_sW                ldap_bind_sW
#define WLDAP32$ldap_search_sW              ldap_search_sW
#define WLDAP32$ldap_first_entry            ldap_first_entry
#define WLDAP32$ldap_get_values_lenW        ldap_get_values_lenW
#define WLDAP32$ldap_value_free_len         ldap_value_free_len
#define WLDAP32$ldap_msgfree                ldap_msgfree
#define WLDAP32$ldap_unbind                 ldap_unbind

#define MSVCRT$malloc                       malloc
#define MSVCRT$free                         free
#define MSVCRT$memset                       memset
#define MSVCRT$memcpy                       memcpy
#define MSVCRT$memcmp                       memcmp
#define MSVCRT$strlen                       strlen
#define MSVCRT$wcslen                       wcslen
#define MSVCRT$strcmp                       strcmp
#define MSVCRT$wcscmp                       wcscmp
#define MSVCRT$_wcsicmp                     _wcsicmp
#define MSVCRT$wcscpy                       wcscpy
#define MSVCRT$strcpy                       strcpy
#define MSVCRT$sprintf                      sprintf
#define MSVCRT$swprintf                     swprintf
#define MSVCRT$_snprintf                    _snprintf
#define MSVCRT$atoi                         atoi

#endif /* BOF */

/* Helper Macros */
#define SAFE_FREE(p) if(p) { MSVCRT$free(p); p = NULL; }

#endif /* _BOFDEFS_H_ */
