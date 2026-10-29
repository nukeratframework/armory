#include <windows.h>

void coffee(char** argv, int argc, WCHAR** dispatch);
#ifdef BOF_BEACON_COMPAT
#define BADGERAPI
#else
#define BADGERAPI DECLSPEC_IMPORT
#endif
BADGERAPI int BadgerDispatch(WCHAR** dispatch, const char *__format, ...);
BADGERAPI int BadgerDispatchW(WCHAR** dispatch, const WCHAR*__format, ...);
BADGERAPI size_t BadgerStrlen(CHAR* buf);
BADGERAPI size_t BadgerWcslen(WCHAR* buf);
BADGERAPI void *BadgerMemcpy(void *dest, const void *src, size_t len) ;
BADGERAPI void *BadgerMemset(void *dest, int val, size_t len);
BADGERAPI int BadgerStrcmp(const char *p1, const char *p2);
BADGERAPI int BadgerWcscmp(const wchar_t *s1, const wchar_t *s2);
BADGERAPI int BadgerAtoi(char* string);
BADGERAPI PVOID BadgerAlloc(SIZE_T length);
BADGERAPI VOID BadgerFree(PVOID *memptr);
BADGERAPI BOOL BadgerSetdebug();
BADGERAPI ULONG BadgerGetBufferSize(PVOID buffer);
BADGERAPI UINT_PTR BadgerSpoofStackFrame(UINT_PTR pWinAPI, int argc, ...);
BADGERAPI VOID BadgerSetHTTPBuffer(PVOID buffer);
BADGERAPI VOID BadgerSetToken(HANDLE hToken);
BADGERAPI BOOL BadgerAddPrivilege(CHAR* privilegeName);

WCHAR** g_dispatch __attribute__((section(".data"))) = 0;
