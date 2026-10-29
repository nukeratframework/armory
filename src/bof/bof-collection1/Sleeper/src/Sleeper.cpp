#define _WIN32_WINNT 0x06000000 // For Mingw

#include <windows.h>

extern "C" {
    #include "beacon.h"
}

#define BOF_REDECLARE(mod, func) extern "C" __declspec(dllimport) decltype(func) mod ## $ ## func 
#define BOF_LOCAL(mod, func) decltype(func) * func = mod ## $ ## func

BOF_REDECLARE(KERNEL32, SetThreadExecutionState);

static int iequals(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + 32);
        if (ca != cb)
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static int parse_numeric(const char *text)
{
    int value = 0;
    int seen = 0;
    const char *p = text;

    if (!p || !*p)
        return -1;

    while (*p >= '0' && *p <= '9') {
        value = value * 10 + (*p - '0');
        seen = 1;
        p++;
    }
    if (!seen || *p != '\0')
        return -1;
    return value;
}

static int parse_sleeper_command(const char *mode)
{
    if (!mode)
        return -1;
    if (iequals(mode, "on"))
        return 1;
    if (iequals(mode, "off"))
        return 0;
    if (iequals(mode, "force"))
        return 65;
    return parse_numeric(mode);
}

extern "C" void go(char* args, int alen) {
    BOF_LOCAL(KERNEL32, SetThreadExecutionState);
    int res;
    datap  parser;
    int command;
    char *mode;

    BeaconDataParse(&parser, args, alen);
    mode = BeaconDataExtract(&parser, NULL);
    command = parse_sleeper_command(mode);
    if (command < 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid mode (use on, off, force, or 0/1/65)\n");
        return;
    }
    command |= ES_CONTINUOUS;

    res = SetThreadExecutionState( command );
    BeaconPrintf(CALLBACK_OUTPUT, "Set the SetThreadExecutionState to 0x%x (previous setting was 0x%x)\n", command, res);
}
