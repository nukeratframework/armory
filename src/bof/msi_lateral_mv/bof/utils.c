// utils.c
#include <windows.h>
#include "beacon.h"

typedef struct {
    PWSTR domain;
    PWSTR username;
    PWSTR password;
    PWSTR hostname;
    PWSTR drivername;
    PWSTR dllpath;
    BOOL isRemote;
    BOOL isValid;
} ParsedArgs;

static BOOL is_arg_set(PWSTR value) {
    return value && value[0] != L'\0' && MSVCRT$_wcsicmp(value, L"-") != 0;
}

static LPCWSTR mj_path_find_file_name_w(LPCWSTR pszPath) {
    LPCWSTR file = pszPath;
    LPCWSTR slash;

    if (!pszPath || !pszPath[0]) {
        return pszPath;
    }

    slash = pszPath;
    while (*slash) {
        if (*slash == L'\\' || *slash == L'/') {
            file = slash + 1;
        }
        slash++;
    }
    return file;
}

static BOOL mj_path_remove_file_spec_w(LPWSTR pszPath) {
    size_t len;
    size_t i;

    if (!pszPath || !pszPath[0]) {
        return FALSE;
    }

    len = MSVCRT$wcslen(pszPath);
    for (i = len; i > 0; i--) {
        if (pszPath[i - 1] == L'\\' || pszPath[i - 1] == L'/') {
            if (i == 1) {
                pszPath[1] = L'\0';
            } else {
                pszPath[i - 1] = L'\0';
            }
            return TRUE;
        }
    }
    return FALSE;
}

void PrintUsage()
{
    BeaconPrintf(CALLBACK_OUTPUT, "\nUsage:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  msi_lateral_mv local <drivername> <dllpath>                                : Local, current user\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  msi_lateral_mv local <user> <pass> <drivername> <dllpath>                  : Local, alternate user\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  msi_lateral_mv local <domain> <user> <pass> <drivername> <dllpath>         : Local, domain user\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  msi_lateral_mv remote <host> <drivername> <dllpath>                        : Remote, current user\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  msi_lateral_mv remote <user> <pass> <host> <drivername> <dllpath>          : Remote, alternate user\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  msi_lateral_mv remote <domain> <user> <pass> <host> <drivername> <dllpath> : Remote, domain user\n");
}

ParsedArgs ParseBOFArguments(datap* parser, int* pDataLength)
{
    ParsedArgs args = {0};
    
    // Check if we have any data
    if (*pDataLength < 4) {  // Need at least the mode string
        BeaconPrintf(CALLBACK_ERROR, "No arguments provided\n");
        PrintUsage();
        return args;
    }
    
    // Extract mode (local/remote)
    PWSTR mode = (PWSTR)BeaconDataExtract(parser, NULL);
    
    if (!mode) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid mode\n");
        PrintUsage();
        return args;
    }
    
    // Determine if local or remote
    if (MSVCRT$_wcsicmp(mode, L"local") == 0) {
        args.isRemote = FALSE;
    }
    else if (MSVCRT$_wcsicmp(mode, L"remote") == 0) {
        args.isRemote = TRUE;
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Invalid mode: %ls. Use 'local' or 'remote'\n", mode);
        PrintUsage();
        return args;
    }
    
    // Extract remaining arguments
    PWSTR arg1 = (PWSTR)BeaconDataExtract(parser, NULL);
    PWSTR arg2 = (PWSTR)BeaconDataExtract(parser, NULL);  
    PWSTR arg3 = (PWSTR)BeaconDataExtract(parser, NULL);
    PWSTR arg4 = (PWSTR)BeaconDataExtract(parser, NULL);
    PWSTR arg5 = (PWSTR)BeaconDataExtract(parser, NULL);
    PWSTR arg6 = (PWSTR)BeaconDataExtract(parser, NULL);
    
    if (!args.isRemote) {
        // Local mode
        if (is_arg_set(arg1) && is_arg_set(arg2) && !is_arg_set(arg3)) {
            // local <drivername> <dllpath>
            args.drivername = arg1;
            args.dllpath = arg2;
            args.isValid = TRUE;
        }
        else if (is_arg_set(arg1) && is_arg_set(arg2) && is_arg_set(arg3) && is_arg_set(arg4) && !is_arg_set(arg5)) {
            // local <user> <pass> <drivername> <dllpath>
            args.username = arg1;
            args.password = arg2;
            args.drivername = arg3;
            args.dllpath = arg4;
            args.isValid = TRUE;
        }
        else if (is_arg_set(arg1) && is_arg_set(arg2) && is_arg_set(arg3) && is_arg_set(arg4) && is_arg_set(arg5) && !is_arg_set(arg6)) {
            // local <domain> <user> <pass> <drivername> <dllpath>
            args.domain = arg1;
            args.username = arg2;
            args.password = arg3;
            args.drivername = arg4;
            args.dllpath = arg5;
            args.isValid = TRUE;
        }
        else if (!is_arg_set(arg1) && !is_arg_set(arg2) && !is_arg_set(arg3) && !is_arg_set(arg4) && is_arg_set(arg5) && is_arg_set(arg6)) {
            // armory padded: local - - - - <drivername> <dllpath>
            args.drivername = arg5;
            args.dllpath = arg6;
            args.isValid = TRUE;
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for local mode\n");
            PrintUsage();
        }
    }
    else {
        // Remote mode
        if (is_arg_set(arg1) && is_arg_set(arg2) && is_arg_set(arg3) && !is_arg_set(arg4)) {
            // remote <host> <drivername> <dllpath>
            args.hostname = arg1;
            args.drivername = arg2;
            args.dllpath = arg3;
            args.isValid = TRUE;
        }
        else if (is_arg_set(arg1) && is_arg_set(arg2) && is_arg_set(arg3) && is_arg_set(arg4) && is_arg_set(arg5) && !is_arg_set(arg6)) {
            // remote <user> <pass> <host> <drivername> <dllpath>
            args.username = arg1;
            args.password = arg2;
            args.hostname = arg3;
            args.drivername = arg4;
            args.dllpath = arg5;
            args.isValid = TRUE;
        }
        else if (is_arg_set(arg1) && is_arg_set(arg2) && is_arg_set(arg3) && is_arg_set(arg4) && is_arg_set(arg5) && is_arg_set(arg6)) {
            // remote <domain> <user> <pass> <host> <drivername> <dllpath>
            args.domain = arg1;
            args.username = arg2;
            args.password = arg3;
            args.hostname = arg4;
            args.drivername = arg5;
            args.dllpath = arg6;
            args.isValid = TRUE;
        }
        else if (!is_arg_set(arg1) && !is_arg_set(arg2) && !is_arg_set(arg3) && is_arg_set(arg4) && is_arg_set(arg5) && is_arg_set(arg6)) {
            // armory padded: remote - - - <host> <drivername> <dllpath>
            args.hostname = arg4;
            args.drivername = arg5;
            args.dllpath = arg6;
            args.isValid = TRUE;
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Invalid arguments for remote mode\n");
            PrintUsage();
        }
    }
    
    return args;
}


DWORD GetEnvironmentSizeW(WCHAR* pchEnvironment)
{
    // We need a double null terminated envrionment
    WCHAR* cur = pchEnvironment;
    do {
        while (*cur != L'\0')
            cur++;
        cur++;
    } while (*cur != L'\0');  

    return (DWORD)(cur - pchEnvironment + 1);
}

