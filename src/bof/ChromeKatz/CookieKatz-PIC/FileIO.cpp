#include <wtypes.h>
#include "GetProcAddress.h"
#include "my_cstring.h"

BOOL CloseFileHandle(Pointers* ctx) {
    if (ctx == NULL || ctx->hOutFile == NULL || ctx->hOutFile == INVALID_HANDLE_VALUE)
        return FALSE;

    return ctx->pCloseHandle(ctx->hOutFile);
}

HANDLE OpenOrCreateFileForAppend(Pointers* ctx, LPCSTR filePath) {
    if (ctx == NULL || filePath == NULL)
        return INVALID_HANDLE_VALUE;

    // OPEN_ALWAYS: Opens file if it exists, creates it if it doesn't
    HANDLE hFile = ctx->pCreateFileA(
        filePath,
        GENERIC_WRITE,          // Write access
        FILE_SHARE_READ,                      // No sharing
        NULL,                   // Default security
        OPEN_ALWAYS,            // Open existing or create new
        FILE_ATTRIBUTE_NORMAL,  // Normal file
        NULL                    // No template
    );

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE)
        return nullptr;

    LARGE_INTEGER dist;
    dist.QuadPart = 0;
    if (!ctx->pSetFilePointerEx(hFile, dist, NULL, FILE_END)) {
        return nullptr;
    }

    return hFile;
}

BOOL WriteLineToFile(const char* str, Pointers* ctx) {
    if (ctx == NULL || ctx->hOutFile == NULL || str == NULL)
        return FALSE;

    DWORD written = 0;
    ctx->pWriteFile(ctx->hOutFile, str, (DWORD)my_strlen(str), &written, NULL);
    BYTE nl[2] = { 0x0D, 0x0A };
    ctx->pWriteFile(ctx->hOutFile, nl, 2, &written, NULL);
    return TRUE;
}

BOOL WriteToFile(const char* str, Pointers* ctx) {
    if (ctx == NULL || ctx->hOutFile == NULL || str == NULL)
        return FALSE;

    DWORD written = 0;
    ctx->pWriteFile(ctx->hOutFile, str, (DWORD)my_strlen(str), &written, NULL);
    return TRUE;
}
/// <summary>
/// WriteHexToFile((const unsigned char*)&ptr, sizeof(void*), ctx);
/// WriteHexToFile((const unsigned char*)&value, sizeof(DWORD), ctx);
/// </summary>
/// <param name="bytes"></param>
/// <param name="len"></param>
/// <param name="ctx"></param>
BOOL WriteHexToFile(const unsigned char* bytes, int len, Pointers* ctx) {
    if (ctx == NULL || ctx->hOutFile == NULL || bytes == NULL)
        return FALSE;

    char hexStr[2];
    DWORD written = 0;
    for (int i = len - 1; i >= 0; i--) {
        unsigned char hi = (bytes[i] >> 4) & 0x0F;
        unsigned char lo = bytes[i] & 0x0F;
        hexStr[0] = hi < 10 ? '0' + hi : 'A' + (hi - 10);
        hexStr[1] = lo < 10 ? '0' + lo : 'A' + (lo - 10);
        ctx->pWriteFile(ctx->hOutFile, hexStr, 2, &written, NULL);
    }

    return TRUE;
}

BOOL WriteHexLineToFile(const unsigned char* bytes, int len, Pointers* ctx) {
    if (ctx == NULL || ctx->hOutFile == NULL || bytes == NULL)
        return FALSE;

    char hexStr[2];
    DWORD written = 0;
    for (int i = len - 1; i >= 0; i--) {
        unsigned char hi = (bytes[i] >> 4) & 0x0F;
        unsigned char lo = bytes[i] & 0x0F;
        hexStr[0] = hi < 10 ? '0' + hi : 'A' + (hi - 10);
        hexStr[1] = lo < 10 ? '0' + lo : 'A' + (lo - 10);
        ctx->pWriteFile(ctx->hOutFile, hexStr, 2, &written, NULL);
    }

    BYTE nl[] = { 0x0D, 0x0A };
    ctx->pWriteFile(ctx->hOutFile, nl, 2, &written, NULL);

    return TRUE;
}

BOOL WriteToFileW(const wchar_t* wstr, Pointers* ctx) {
    if (ctx == NULL || ctx->hOutFile == NULL || wstr == NULL)
        return FALSE;

    if (wstr == NULL)
        return FALSE;

    // Convert wide chars to narrow and write one at a time
    DWORD written = 0;
    while (*wstr) {
        char c = (char)(unsigned char)*wstr;
        ctx->pWriteFile(ctx->hOutFile, &c, 1, &written, NULL);
        wstr++;
    }

    return TRUE;
}