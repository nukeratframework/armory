#pragma once
extern "C" {

    inline int my_strcmp(const char* a, const char* b) {
        while (*a && (*a == *b)) {
            ++a;
            ++b;
        }
        return static_cast<unsigned char>(*a) - static_cast<unsigned char>(*b);
    }

    inline int my_wstricmp(const wchar_t* s1, const wchar_t* s2) {
        while (*s1 && *s2) {
            wchar_t c1 = *s1;
            wchar_t c2 = *s2;

            if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
            if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

            if (c1 != c2) return c1 - c2;

            s1++;
            s2++;
        }
        return *s1 - *s2;
    }

    inline size_t my_strlen(const char* str) {
        size_t len = 0;
        while (str[len]) ++len;
        return len;
    }

    inline LPCWSTR charToWChar(const char* str, wchar_t* wStr, int maxLen) {
        int len = 0;
        while (str[len] != '\0' && len < maxLen - 1) {
            wStr[len] = (wchar_t)(unsigned char)str[len];
            len++;
        }

        wStr[len] = L'\0';

        return wStr;
    }

    inline void* my_memcpy(void* dest, const void* src, size_t n) {
        unsigned char* d = (unsigned char*)dest;
        const unsigned char* s = (const unsigned char*)src;
        for (size_t i = 0; i < n; ++i)
            d[i] = s[i];
        return dest;
    }
}