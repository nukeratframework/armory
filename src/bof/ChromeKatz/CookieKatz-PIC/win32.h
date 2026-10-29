#pragma once
#include "Helper.h"
#include "GetProcAddress.h"

/*
* Returns callable function of requested type with given name
* Example:
*   auto getNativeSystemInfo = QUICK_DFR(KERNEL32, GetNativeSystemInfo, this);
*   SYSTEM_INFO sysinf;
*   getNativeSystemInfo(&sysinf);
*/
#define DFR_CACHE(module, function, ctx) DFR_CACHE_(UNIQUE_NAME(module), UNIQUE_NAME(function), module, function, ctx);
#define DFR_CACHE_(tmpmodulename, tmpfunctionname, module, function, ctx) \
    PICARR(tmpmodulename, #module);            \
    PICARR(tmpfunctionname, #function);        \
    auto module##$##function = reinterpret_cast<decltype(&function)>(GetProc(tmpmodulename, tmpfunctionname, ctx)); \
    auto function = module##$##function;