#pragma once

#include <windows.h>

static char mj_tolower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return (char)(c + 32);
    }
    return c;
}

static int mj_module_matches(const char *fullPath, const char *pattern) {
    size_t flen = 0;
    size_t mlen = 0;
    size_t i = 0;
    const char *suffix = NULL;

    if (!fullPath || !pattern || !pattern[0]) {
        return 0;
    }

    while (fullPath[flen]) {
        flen++;
    }
    while (pattern[mlen]) {
        mlen++;
    }
    if (mlen > flen) {
        return 0;
    }

    suffix = fullPath + flen - mlen;
    for (i = 0; i < mlen; i++) {
        if (mj_tolower(suffix[i]) != mj_tolower(pattern[i])) {
            return 0;
        }
    }
    return 1;
}

static ULONG_PTR mj_parse_offset(const char *s) {
    ULONG_PTR value = 0;
    int i = 0;

    if (!s || !s[0]) {
        return 0;
    }

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        i = 2;
    }

    for (; s[i]; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            value = (value << 4) | (ULONG_PTR)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            value = (value << 4) | (ULONG_PTR)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            value = (value << 4) | (ULONG_PTR)(c - 'A' + 10);
        } else {
            break;
        }
    }

    return value;
}
