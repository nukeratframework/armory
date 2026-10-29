#pragma once
#include <wtypes.h>
#include "GetProcAddress.h"

BOOL FindLargestSection(uintptr_t moduleAddr, uintptr_t& resultAddress, Pointers* ctx);
void ConvertToByteArray(uintptr_t value, BYTE* byteArray, size_t size);
void PatchPattern(BYTE* pattern, BYTE baseAddrPattern[], size_t offset);
BOOL FindPattern(const BYTE* pattern, size_t patternSize, uintptr_t* cookieMonsterInstances, size_t& szCookieMonster, Pointers* ctx);
void WalkCookieMap(uintptr_t cookieMapAddress, Pointers* ctx);