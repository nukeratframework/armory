#pragma once
#include <wtypes.h>
#include "GetProcAddress.h"

BOOL CloseFileHandle(Pointers* ctx);
BOOL WriteLineToFile(const char* str, Pointers* ctx);
BOOL WriteToFile(const char* str, Pointers* ctx);
HANDLE OpenOrCreateFileForAppend(Pointers* ctx, LPCSTR filePath);
BOOL WriteHexToFile(const unsigned char* bytes, int len, Pointers* ctx);
BOOL WriteHexLineToFile(const unsigned char* bytes, int len, Pointers* ctx);
BOOL WriteToFileW(const wchar_t* wstr, Pointers* ctx);