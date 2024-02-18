#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  nReason, LPVOID lpReserved) {
    switch (nReason) {
    case DLL_PROCESS_ATTACH:
        //int MessageBox(
        //    [in, optional] HWND    hWnd,
        //    [in, optional] LPCTSTR lpText,
        //    [in, optional] LPCTSTR lpCaption,
        //    [in]           UINT    uType
        //);
        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox
        MessageBox(NULL, L"Successfully injected DLL into process!", L"DLL Injection", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}