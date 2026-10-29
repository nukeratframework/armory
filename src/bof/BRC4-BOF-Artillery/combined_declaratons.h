#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <oleauto.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <combaseapi.h>
#include <taskschd.h>
#include <sddl.h>
#include <iads.h>
#include <wincrypt.h>
#include <ntstatus.h>
#include <winternl.h>
#include <wincred.h>
#include <winreg.h>
#include <security.h>
#include <string.h>
#include <tlhelp32.h>
#include <processsnapshot.h>
#include <winsock.h>
#include <winsock2.h>
#include <dsgetdc.h>
#include <proofofpossessioncookieinfo.h>
#include <wtsapi32.h>
#include <tdh.h>
#include <DbgHelp.h>
#include <fltuser.h>
#include <oaidl.h>
#include <objbase.h>

typedef _Return_type_success_(return == ERROR_SUCCESS) ULONG TDHSTATUS;
#define TDHAPI TDHSTATUS __stdcall

typedef enum _MINIDUMP_CALLBACK_TYPE {
  ModuleCallback,
  ThreadCallback,
  ThreadExCallback,
  IncludeThreadCallback,
  IncludeModuleCallback,
  MemoryCallback,
  CancelCallback,
  WriteKernelMinidumpCallback,
  KernelMinidumpStatusCallback,
  RemoveMemoryCallback,
  IncludeVmRegionCallback,
  IoStartCallback,
  IoWriteAllCallback,
  IoFinishCallback,
  ReadMemoryFailureCallback,
  SecondaryFlagsCallback,
  IsProcessSnapshotCallback,
  VmStartCallback,
  VmQueryCallback,
  VmPreReadCallback,
  VmPostReadCallback
} MINIDUMP_CALLBACK_TYPE, *PMINIDUMP_CALLBACK_TYPE;

typedef enum {
	NameUnknown = 0,
	NameFullyQualifiedDN = 1,
	NameSamCompatible = 2,
	NameDisplay = 3,
	NameUniqueId = 6,
	NameCanonical = 7,
	NameUserPrincipal = 8,
	NameCanonicalEx = 9,
	NameServicePrincipal = 10,
	NameDnsDomain = 12,
	NameGivenName = 13,
	NameSurname = 14
} EXTENDED_NAME_FORMAT, *PEXTENDED_NAME_FORMAT;

typedef struct _OutlookContactRecord {
	BSTR Name;
	BSTR PrimarySmtpAddress;
	BSTR JobTitle;
	BSTR Department;
	BSTR OfficeLocation;
	BSTR City;
	BSTR MobileTelephoneNumber;
	BSTR StreetAddress;
	BSTR PostalCode;
	BSTR StateOrProvince;
} OutlookContactRecord, *POutlookContactRecord;

typedef enum _OlAddressEntryUserType {
	olExchangeUserAddressEntry = 0,
	olExchangeDistributionListAddressEntry = 1,
	olExchangePublicFolderAddressEntry = 2,
	olExchangeAgentAddressEntry = 3,
	olExchangeOrganizationAddressEntry = 4,
	olExchangeRemoteUserAddressEntry = 5,
	olOutlookContactAddressEntry = 10,
	olOutlookDistributionListAddressEntry = 11,
	olLdapAddressEntry = 20,
	olSmtpAddressEntry = 30,
	olOtherAddressEntry = 40
} OlAddressEntryUserType, *POlAddressEntryUserType;

typedef struct _CRYPT_FILE_META {
    CHAR *fileName;
    CHAR *cryptionkey;
    CHAR *extension;
    WCHAR **dispatch;
    BOOL dwThreadRelease;
    BOOL actionType;
} CRYPT_FILE_META, *PCRYPT_FILE_META;

typedef struct _PVOID_STRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} PVOID_STRING, *PPVOID_STRING;

typedef struct _DOMAIN_CONTROLLER_INFOA {
  LPSTR DomainControllerName;
  LPSTR DomainControllerAddress;
  ULONG DomainControllerAddressType;
  GUID  DomainGuid;
  LPSTR DomainName;
  LPSTR DnsForestName;
  ULONG Flags;
  LPSTR DcSiteName;
  LPSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOA, *PDOMAIN_CONTROLLER_INFOA;

typedef struct ProofOfPossessionCookieInfo {
  LPWSTR name;
  LPWSTR data;
  DWORD  flags;
  LPWSTR p3pHeader;
} ProofOfPossessionCookieInfo, *PProofOfPossessionCookieInfo;

typedef struct _WTS_PROCESS_INFOA {
  DWORD SessionId;
  DWORD ProcessId;
  LPSTR pProcessName;
  PSID  pUserSid;
} WTS_PROCESS_INFOA, *PWTS_PROCESS_INFOA;

typedef struct _PROVIDER_ENUMERATION_INFO {
  ULONG               NumberOfProviders;
  ULONG               Reserved;
  TRACE_PROVIDER_INFO TraceProviderInfoArray[ANYSIZE_ARRAY];
} PROVIDER_ENUMERATION_INFO, *PPROVIDER_ENUMERATION_INFO;

DECLSPEC_IMPORT LONG Advapi32$RegCloseKey(HKEY hKey);
DECLSPEC_IMPORT WINBOOL Advapi32$ImpersonateLoggedOnUser(HANDLE hToken);
DECLSPEC_IMPORT WINBOOL Advapi32$GetAce(PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);
DECLSPEC_IMPORT WINBOOL Advapi32$ConvertSidToStringSidW(PSID Sid,LPWSTR *StringSid);
DECLSPEC_IMPORT NTSTATUS Advapi32$SystemFunction032(PPVOID_STRING source, PPVOID_STRING key);
DECLSPEC_IMPORT LONG Advapi32$RegDeleteKeyValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName);
DECLSPEC_IMPORT LONG Advapi32$RegConnectRegistryA(LPCSTR lpMachineName,HKEY hKey,PHKEY phkResult);
DECLSPEC_IMPORT BOOL Advapi32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT LONG Advapi32$RegDeleteKeyExA(HKEY hKey,LPCSTR lpSubKey,REGSAM samDesired,DWORD Reserved);
DECLSPEC_IMPORT BOOL Advapi32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT LONG Advapi32$RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult);
DECLSPEC_IMPORT WINBOOL Advapi32$InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD dwRevision);
DECLSPEC_IMPORT LONG Advapi32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LSTATUS Advapi32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT WINBOOL Advapi32$CredMarshalCredentialW(CRED_MARSHAL_TYPE CredType,PVOID Credential,LPWSTR *MarshaledCredential);
DECLSPEC_IMPORT LSTATUS Advapi32$RegSaveKeyExA(HKEY hKey, LPCSTR lpFile, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD Flag);
DECLSPEC_IMPORT WINBOOL Advapi32$GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID *pOwner, LPBOOL lpbOwnerDefaulted);
DECLSPEC_IMPORT LSTATUS Advapi32$RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
DECLSPEC_IMPORT LSTATUS Advapi32$RegGetValueA(HKEY hkey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);
DECLSPEC_IMPORT WINBOOL Advapi32$SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, WINBOOL bDaclPresent, PACL pDacl, WINBOOL bDaclDefaulted);
DECLSPEC_IMPORT WINBOOL Advapi32$GetAclInformation(PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);
DECLSPEC_IMPORT WINBOOL Advapi32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);
DECLSPEC_IMPORT WINBOOL Advapi32$LogonUserW(LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
DECLSPEC_IMPORT BOOL Advapi32$InitiateSystemShutdownExA(LPSTR lpMachineName, LPSTR lpMessage, DWORD dwTimeout, BOOL bForceAppsClosed, BOOL bRebootAfterShutdown, DWORD dwReason);
DECLSPEC_IMPORT WINBOOL Advapi32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT WINBOOL Advapi32$LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
DECLSPEC_IMPORT BOOL Advapi32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT WINBOOL Advapi32$ConvertSecurityDescriptorToStringSecurityDescriptorW(PSECURITY_DESCRIPTOR SecurityDescriptor,DWORD RequestedStringSDRevision,SECURITY_INFORMATION SecurityInformation,LPWSTR *StringSecurityDescriptor,PULONG StringSecurityDescriptorLen);
DECLSPEC_IMPORT LSTATUS Advapi32$RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);

DECLSPEC_IMPORT HRESULT Certcli$CACloseCA(IN LPVOID hCA);
DECLSPEC_IMPORT LPCWSTR Certcli$CAGetDN(IN LPVOID hCAInfo);
DECLSPEC_IMPORT DWORD Certcli$CACountCAs(IN LPVOID hCAInfo);
DECLSPEC_IMPORT DWORD Certcli$CACountCertTypes(IN LPVOID hCertType);
DECLSPEC_IMPORT HRESULT Certcli$CACloseCertType(IN LPVOID hCertType);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCAFlags(IN LPVOID hCAInfo, OUT DWORD  *pdwFlags);
DECLSPEC_IMPORT HRESULT Certcli$CAEnumNextCA(IN LPVOID hPrevCA, OUT LPVOID * phCAInfo);
DECLSPEC_IMPORT HRESULT Certcli$CAEnumCertTypes(IN DWORD dwFlags, OUT LPVOID * phCertType);
DECLSPEC_IMPORT HRESULT Certcli$CAFreeCAProperty(IN LPVOID hCAInfo, IN PZPWSTR awszPropertyValue);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCACertificate(IN LPVOID hCAInfo, OUT PCCERT_CONTEXT *ppCert);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCASecurity(IN LPVOID hCAInfo, OUT PSECURITY_DESCRIPTOR * ppSD);
DECLSPEC_IMPORT HRESULT Certcli$CAEnumNextCertType(IN LPVOID hPrevCertType, OUT LPVOID * phCertType);
DECLSPEC_IMPORT HRESULT Certcli$CAFreeCertTypeProperty(IN LPVOID hCertType, IN PZPWSTR awszPropertyValue);
DECLSPEC_IMPORT HRESULT Certcli$CACertTypeGetSecurity(IN LPVOID hCertType, OUT PSECURITY_DESCRIPTOR * ppSD);
DECLSPEC_IMPORT HRESULT Certcli$CAEnumFirstCA(IN LPCWSTR wszScope, IN DWORD dwFlags, OUT LPVOID * phCAInfo);
DECLSPEC_IMPORT HRESULT Certcli$CAEnumCertTypesForCA(IN LPVOID hCAInfo, IN DWORD dwFlags, OUT LPVOID * phCertType);
DECLSPEC_IMPORT HRESULT Certcli$CAFreeCertTypeExtensions(IN LPVOID hCertType, IN PCERT_EXTENSIONS pCertExtensions);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCertTypeFlagsEx(IN LPVOID hCertType, IN DWORD dwOption, OUT DWORD * pdwFlags);
DECLSPEC_IMPORT HRESULT Certcli$CAGetAccessRights(IN LPVOID hCAInfo, IN DWORD dwContext, OUT DWORD *pdwAccessRights);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCAExpiration(IN LPVOID hCAInfo, OUT DWORD * pdwExpiration, OUT DWORD * pdwUnits);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCertTypeAccessRights(IN LPVOID hCertType, IN DWORD dwContext, OUT DWORD *pdwAccessRights);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCAProperty(IN LPVOID hCAInfo, IN LPCWSTR wszPropertyName, OUT PZPWSTR *pawszPropertyValue);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCertTypePropertyEx(IN LPVOID hCertType, IN LPCWSTR wszPropertyName, OUT LPVOID *pPropertyValue);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCertTypeProperty(IN LPVOID hCertType, IN LPCWSTR wszPropertyName, OUT PZPWSTR *pawszPropertyValue);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCertTypeExpiration(IN LPVOID hCertType, OUT OPTIONAL FILETIME * pftExpiration, OUT OPTIONAL FILETIME * pftOverlap);
DECLSPEC_IMPORT HRESULT Certcli$CAGetCertTypeExtensionsEx(IN LPVOID hCertType, IN DWORD dwFlags, IN LPVOID pParam, OUT PCERT_EXTENSIONS * ppCertExtensions);
DECLSPEC_IMPORT HRESULT Certcli$caTranslateFileTimePeriodToPeriodUnits(IN FILETIME const *pftGMT, IN BOOL Flags, OUT DWORD *pcPeriodUnits, OUT LPVOID*prgPeriodUnits);

DECLSPEC_IMPORT WINBOOL Crypt32$CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
DECLSPEC_IMPORT WINBOOL Crypt32$CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT VOID Crypt32$CertFreeCertificateChain(PCCERT_CHAIN_CONTEXT pChainContext);
DECLSPEC_IMPORT WINBOOL Crypt32$CertDeleteCertificateFromStore(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT PCCRYPT_OID_INFO Crypt32$CryptFindOIDInfo(DWORD dwKeyType, void *pvKey, DWORD dwGroupId);
DECLSPEC_IMPORT HCERTSTORE Crypt32$PFXImportCertStore(CRYPT_DATA_BLOB *pPFX, LPCWSTR szPassword, DWORD dwFlags);
DECLSPEC_IMPORT PCCERT_CONTEXT Crypt32$CertEnumCertificatesInStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext);
DECLSPEC_IMPORT BOOL Crypt32$CryptBinaryToStringW(const BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPWSTR pszString, DWORD *pcchString);
DECLSPEC_IMPORT WINBOOL Crypt32$CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void *pvData, DWORD *pcbData);
DECLSPEC_IMPORT PCCERT_CONTEXT Crypt32$CertCreateCertificateContext(DWORD dwCertEncodingType, const BYTE *pbCertEncoded, DWORD cbCertEncoded);
DECLSPEC_IMPORT DWORD Crypt32$CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, LPWSTR pszNameString, DWORD cchNameString);
DECLSPEC_IMPORT HCERTSTORE Crypt32$CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void *pvPara);
DECLSPEC_IMPORT WINBOOL Crypt32$CertAddCertificateContextToStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pCertContext, DWORD dwAddDisposition, PCCERT_CONTEXT *ppStoreContext);
DECLSPEC_IMPORT BOOL Crypt32$CryptEncodeObjectEx(DWORD dwCertEncodingType, LPCSTR lpszStructType, const void *pvStructInfo, DWORD dwFlags, PCRYPT_ENCODE_PARA pEncodePara, void *pvEncoded, DWORD *pcbEncoded);
DECLSPEC_IMPORT WINBOOL Crypt32$CertGetCertificateChain(HCERTCHAINENGINE hChainEngine, PCCERT_CONTEXT pCertContext, LPFILETIME pTime, HCERTSTORE hAdditionalStore, PCERT_CHAIN_PARA pChainPara, DWORD dwFlags, LPVOID pvReserved, PCCERT_CHAIN_CONTEXT *ppChainContext);

DECLSPEC_IMPORT BOOL Dbghelp$MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, ULONG_PTR, PVOID ExceptionParam, PVOID UserStreamParam, PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

DECLSPEC_IMPORT HRESULT Fltlib$FilterFindFirst(FILTER_INFORMATION_CLASS dwInformationClass, LPVOID lpBuffer, DWORD dwBufferSize, LPDWORD lpBytesReturned, LPHANDLE lpFilterFind); HRESULT Fltlib$FilterFindNext(HANDLE hFilterFind, FILTER_INFORMATION_CLASS dwInformationClass, LPVOID lpBuffer, DWORD dwBufferSize, LPDWORD lpBytesReturned);

DECLSPEC_IMPORT VOID Kernel32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD Kernel32$GetLastError(); 
DECLSPEC_IMPORT HANDLE Kernel32$GetProcessHeap();
DECLSPEC_IMPORT HANDLE Kernel32$GetCurrentProcess();
DECLSPEC_IMPORT DWORD Kernel32$GetProcessId(HANDLE);
DECLSPEC_IMPORT HLOCAL Kernel32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT BOOL Kernel32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL Kernel32$FindClose(HANDLE hFindFile);
DECLSPEC_IMPORT BOOL Kernel32$DeleteFileA(LPCSTR lpFileName);
DECLSPEC_IMPORT HMODULE Kernel32$LoadLibraryA(LPCSTR lpModuleName);
DECLSPEC_IMPORT VOID Kernel32$GetLocalTime(LPSYSTEMTIME lpSystemTime); 
DECLSPEC_IMPORT HMODULE Kernel32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT HLOCAL Kernel32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT VOID Kernel32$GetSystemTime(LPSYSTEMTIME lpSystemTime);
DECLSPEC_IMPORT VOID Kernel32$GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
DECLSPEC_IMPORT BOOL Kernel32$GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize); 
DECLSPEC_IMPORT LPWSTR Kernel32$lstrcatW (LPWSTR lpString1, LPCWSTR lpString2);
DECLSPEC_IMPORT BOOL Kernel32$TerminateProcess(HANDLE hProcess, UINT uExitCode);
DECLSPEC_IMPORT BOOL Kernel32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT DWORD Kernel32$GetFileSize(HANDLE  hFile, LPDWORD lpFileSizeHigh);
DECLSPEC_IMPORT BOOL Kernel32$GetExitCodeProcess(HANDLE hProcess, PDWORD uExitCode);
DECLSPEC_IMPORT BOOL Kernel32$GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
DECLSPEC_IMPORT FARPROC Kernel32$GetProcAddress(HMODULE hModule, LPCSTR  lpProcName);
DECLSPEC_IMPORT BOOL Kernel32$WaitNamedPipeA(LPCSTR lpNamedPipeName, DWORD nTimeOut);
DECLSPEC_IMPORT WINBOOL Kernel32$Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT WINBOOL Kernel32$Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT LPVOID Kernel32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT LPVOID Kernel32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT DWORD Kernel32$WaitForMultipleObjects(DWORD, const HANDLE*, BOOL, DWORD);
DECLSPEC_IMPORT DWORD Kernel32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DECLSPEC_IMPORT DWORD Kernel32$PssFreeSnapshot(HANDLE ProcessHandle, HPSS SnapshotHandle);
DECLSPEC_IMPORT HANDLE Kernel32$CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID);
DECLSPEC_IMPORT int Kernel32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT LPWSTR Kernel32$lstrcpynW (LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength);
DECLSPEC_IMPORT BOOL Kernel32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT HANDLE Kernel32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
DECLSPEC_IMPORT LPVOID Kernel32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
DECLSPEC_IMPORT int Kernel32$FileTimeToSystemTime(CONST FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime); 
DECLSPEC_IMPORT BOOL Kernel32$SystemTimeToFileTime(CONST SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime); 
DECLSPEC_IMPORT HANDLE Kernel32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL Kernel32$FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
DECLSPEC_IMPORT HANDLE Kernel32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT LPVOID Kernel32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect); 
DECLSPEC_IMPORT SIZE_T Kernel32$VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
DECLSPEC_IMPORT BOOL Kernel32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT DWORD Kernel32$PssCaptureSnapshot(HANDLE ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, DWORD ThreadContextFlags, HPSS* SnapshotHandle);
DECLSPEC_IMPORT BOOL Kernel32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T  *lpNumberOfBytesWritten);
DECLSPEC_IMPORT BOOL Kernel32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD  nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT int Kernel32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar); 
DECLSPEC_IMPORT BOOL Kernel32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT int Kernel32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar); 
DECLSPEC_IMPORT HANDLE Kernel32$CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId); 
DECLSPEC_IMPORT HANDLE Kernel32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

DECLSPEC_IMPORT HRESULT MicrosoftAccountTokenProvider$GetCookieInfoForUri(LPCWSTR uri, DWORD *cookieInfoCount, ProofOfPossessionCookieInfo **cookieInfo);

DECLSPEC_IMPORT int Msvcrt$tolower(int c);
DECLSPEC_IMPORT int Msvcrt$isdigit(int c);
DECLSPEC_IMPORT int Msvcrt$isxdigit(int c);
DECLSPEC_IMPORT size_t Msvcrt$wcslen(WCHAR*);
DECLSPEC_IMPORT int Msvcrt$iswprint( wint_t c);
DECLSPEC_IMPORT void Msvcrt$free(void *memblock);
DECLSPEC_IMPORT char* Msvcrt$_strdup(const char* str);
DECLSPEC_IMPORT size_t Msvcrt$strlen(const char *str); 
DECLSPEC_IMPORT void* Msvcrt$realloc(void *ptr, size_t size);
DECLSPEC_IMPORT char* Msvcrt$strcat(char* dest, const char* src);
DECLSPEC_IMPORT int Msvcrt$strcmp(const char *str1, const char *str2);
DECLSPEC_IMPORT int Msvcrt$wcscmp(const char *str1, const char *str2);
DECLSPEC_IMPORT char* Msvcrt$strtok(char* str, const char* delimiters);
DECLSPEC_IMPORT int Msvcrt$sprintf(char* buffer, const char* format, ...);
DECLSPEC_IMPORT wchar_t* Msvcrt$wcsrchr(const wchar_t *_Str, wchar_t _Ch);
DECLSPEC_IMPORT char* Msvcrt$strncpy(char* dest, const char* src, size_t n);
DECLSPEC_IMPORT wchar_t* Msvcrt$wcstok(wchar_t * _Str,const wchar_t * _Delim);
DECLSPEC_IMPORT char* Msvcrt$strstr(const char* haystack, const char* needle);
DECLSPEC_IMPORT int Msvcrt$sscanf_s(const char *_Src,const char *_Format,...);
DECLSPEC_IMPORT int Msvcrt$_wcsicmp(const wchar_t *str1, const wchar_t *str2);
DECLSPEC_IMPORT wchar_t* Msvcrt$wcscpy(wchar_t * __dst, const wchar_t * __src);
DECLSPEC_IMPORT int Msvcrt$strncmp(const char* str1, const char* str2, size_t n);
DECLSPEC_IMPORT char* Msvcrt$strcpy(char *strDestination, const char *strSource);
DECLSPEC_IMPORT int Msvcrt$_strnicmp(char *string1, char *string2, size_t count);
DECLSPEC_IMPORT int Msvcrt$_swprintf(wchar_t *buffer, const wchar_t *format, ...);
DECLSPEC_IMPORT void  Msvcrt$calloc(size_t _NumOfElements, size_t _SizeOfElements);
DECLSPEC_IMPORT unsigned long Msvcrt$strtoul(char *strSource, char **endptr, int base);
DECLSPEC_IMPORT int Msvcrt$vsnprintf(char* d, size_t n, const char* format, va_list arg);
DECLSPEC_IMPORT int Msvcrt$memcmp(   const void *buffer1, const void *buffer2, size_t count);
DECLSPEC_IMPORT errno_t Msvcrt$strcat_s(char *_Dst, rsize_t _SizeInBytes, const char * _Src);
DECLSPEC_IMPORT int Msvcrt$sprintf_s(char *_DstBuf, size_t _DstSize, const char *_Format, ...);
DECLSPEC_IMPORT int Msvcrt$_snwprintf(wchar_t *buffer, size_t count, const wchar_t *format, ...);
DECLSPEC_IMPORT wchar_t* Msvcrt$wcsncat(wchar_t* destination, const wchar_t* source, size_t num);
DECLSPEC_IMPORT int Msvcrt$swprintf_s(wchar_t *__stream, size_t __count, const wchar_t *__format, ...);
DECLSPEC_IMPORT void* Msvcrt$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount); 

DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetApiBufferFree(LPVOID Buffer);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetApiBufferFree(LPVOID Buffer);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetUseDel(LMSTR uncname, LMSTR use_name, DWORD force_cond);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetUseAdd(LMSTR uncname, DWORD level, LPBYTE buf, LPDWORD parm_err);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetGroupAddUser(LPCWSTR servername, LPCWSTR GroupName, LPCWSTR username);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetGroupAddUser(LPCWSTR servername, LPCWSTR GroupName, LPCWSTR username);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetUserAdd(LPCWSTR servername, DWORD level, LPBYTE buf, LPDWORD parm_err);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetUserSetInfo(LPCWSTR servername,LPCWSTR username,DWORD level,LPBYTE buf,LPDWORD parm_err);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetLocalGroupAddMembers(LPCWSTR servername, LPCWSTR groupname, DWORD level, LPBYTE buf, DWORD totalentrie);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetLocalGroupAddMembers(LPCWSTR servername, LPCWSTR groupname, DWORD level, LPBYTE buf, DWORD totalentrie);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$DsGetDcNameA(LPCSTR ComputerName, LPCSTR DomainName, GUID* DomainGuid, LPCSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFOA* DomainControllerInfo); 
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION Netapi32$NetShareEnum(LMSTR servername, DWORD level, LPBYTE *bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries, LPDWORD resume_handle);

DECLSPEC_IMPORT NTSTATUS Ntdll$NtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);
DECLSPEC_IMPORT NTSTATUS Ntdll$NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS Ntdll$NtQueryObject(HANDLE ObjectHandle, ULONG ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS Ntdll$NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS Ntdll$NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);

DECLSPEC_IMPORT void Ole32$CoUninitialize();
DECLSPEC_IMPORT void Ole32$CoTaskMemFree(LPVOID pv);
DECLSPEC_IMPORT void Ole32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void Ole32$VariantClear(VARIANTARG *pvarg);
DECLSPEC_IMPORT HRESULT Ole32$CLSIDFromProgID(LPCOLESTR, LPCLSID);
DECLSPEC_IMPORT HRESULT Ole32$IIDFromString(LPCOLESTR lpsz, LPIID lpiid);
DECLSPEC_IMPORT HRESULT Ole32$CLSIDFromString(LPCOLESTR lpsz, LPCLSID pclsid);
DECLSPEC_IMPORT HRESULT Ole32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT int Ole32$StringFromGUID2(REFGUID rguid, LPOLESTR lpsz, int cchMax);
DECLSPEC_IMPORT HRESULT Ole32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);

DECLSPEC_IMPORT UINT Oleaut32$SysStringLen(BSTR pbstr);
DECLSPEC_IMPORT void OleAut32$SysFreeString(BSTR bstrString);
DECLSPEC_IMPORT BSTR OleAut32$SysAllocString(const OLECHAR *psz);
DECLSPEC_IMPORT HRESULT Oleaut32$VariantClear(VARIANTARG *pvarg);

DECLSPEC_IMPORT DWORD Psapi$GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);

DECLSPEC_IMPORT SECURITY_STATUS Secur32$DeleteSecurityContext(PCtxtHandle phContext);
DECLSPEC_IMPORT SECURITY_STATUS Secur32$FreeCredentialsHandle(PCredHandle phCredential);
DECLSPEC_IMPORT BOOL Secur32$GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize);
DECLSPEC_IMPORT BOOLEAN Secur32$GetComputerObjectNameW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize);
DECLSPEC_IMPORT SECURITY_STATUS Secur32$AcquireCredentialsHandleA(LPCTSTR, LPCTSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS Secur32$InitializeSecurityContextA(PCredHandle, PCtxtHandle, SEC_CHAR *, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS Secur32$AcceptSecurityContext(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry);

DECLSPEC_IMPORT TDHSTATUS Tdh$TdhEnumerateProviders(PPROVIDER_ENUMERATION_INFO pBuffer, ULONG *pBufferSize); 

DECLSPEC_IMPORT DWORD Version$GetFileVersionInfoSizeA(LPCSTR lptstrFilenamea ,LPDWORD lpdwHandle);
DECLSPEC_IMPORT WINBOOL Version$VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);
DECLSPEC_IMPORT WINBOOL Version$GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);

DECLSPEC_IMPORT int WSAAPI Ws2_32$WSACleanup();
DECLSPEC_IMPORT int WSAAPI Ws2_32$WSAGetLastError();
DECLSPEC_IMPORT int WSAAPI Ws2_32$closesocket(SOCKET sock);
DECLSPEC_IMPORT void WSAAPI Ws2_32$freeaddrinfo(struct addrinfo* ai);
DECLSPEC_IMPORT int WSAAPI Ws2_32$recv(SOCKET sock, char* buf, int len, int flags);
DECLSPEC_IMPORT unsigned int WSAAPI Ws2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT int WSAAPI Ws2_32$send(SOCKET sock, const char* buf, int len, int flags);
DECLSPEC_IMPORT int WSAAPI Ws2_32$connect(SOCKET sock, const SOCKADDR* name, int namelen);
DECLSPEC_IMPORT int WSAAPI Ws2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData); 
DECLSPEC_IMPORT int WSAAPI Ws2_32$getaddrinfo(char* host, char* port, const struct addrinfo* hints, struct addrinfo** result);

DECLSPEC_IMPORT HANDLE Wtsapi32$WTSCloseServer(HANDLE hServer);
DECLSPEC_IMPORT HANDLE Wtsapi32$WTSOpenServerA(LPSTR pServerName);
DECLSPEC_IMPORT BOOL Wtsapi32$WTSEnumerateProcessesA(HANDLE hServer, DWORD Reserved, DWORD Version, PWTS_PROCESS_INFOA *ppProcessInfo, DWORD *pCount);
