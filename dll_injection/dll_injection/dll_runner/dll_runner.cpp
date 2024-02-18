#include <windows.h>

int main(int argc, char* argv[]) {
    // Load the DLL
    //HMODULE LoadLibraryA(
    //    [in] LPCSTR lpLibFileName
    //);
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
    HMODULE hModule = LoadLibraryA(argv[1]); // first argument is dll path - (path/to/inject_me.dll)
    if (hModule == NULL) {
        // Handle error
        return 1;
    }

    //BOOL FreeLibrary(
    //    [in] HMODULE hLibModule
    //);
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary
    BOOL freed = FreeLibrary(hModule);
    if (!freed) {
        return 1;
    }

    return 0;
}