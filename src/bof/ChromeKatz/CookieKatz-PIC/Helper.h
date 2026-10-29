#pragma once

#define CONCAT(a, b) CONCAT_INNER(a, b)
#define CONCAT_INNER(a, b) a ## b

#ifdef UNIQUE_NAME
#undef UNIQUE_NAME
#define UNIQUE_NAME(base) CONCAT(base, __COUNTER__)
#endif

#define PICWARR(NAME, STR) PICWARR_(UNIQUE_NAME(NAME), NAME, STR);
#define PICWARR_(tempname, NAME, STR) \
    constexpr wchar_t tempname[] = L##STR; \
    const wchar_t* NAME = reinterpret_cast<const wchar_t*>(tempname);

#define PICARR(NAME, STR) PICARR_(UNIQUE_NAME(NAME), NAME, STR);
#define PICARR_(tempname, NAME, STR) \
    constexpr BYTE tempname[] = STR; \
    const char* NAME = reinterpret_cast<const char*>(tempname);
