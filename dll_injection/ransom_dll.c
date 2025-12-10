#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Ransom DLL attached to process", "Warning", MB_ICONEXCLAMATION);
        break;
    case DLL_PROCESS_DETACH:
        MessageBoxA(NULL, "Ransom DLL detached from process", "Warning", MB_ICONEXCLAMATION);
        break;
    case DLL_THREAD_ATTACH:
        MessageBoxA(NULL, "Ransom DLL attached to thread", "Warning", MB_ICONEXCLAMATION);
        break;
    case DLL_THREAD_DETACH:
        MessageBoxA(NULL, "Ransom DLL detached from thread", "Warning", MB_ICONEXCLAMATION);
        break;
    }
    return TRUE;
}