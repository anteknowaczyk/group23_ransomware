#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD get_pid_from_list(const char *names[], size_t count)
{
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

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
    return 0; // No process found
}

int main(int argc, char **argv)
{
    // List of process names to target
    const char *processes[] = {
        "notepad.exe",
        "calc.exe",
        "explorer.exe"
    };

    if (argc != 2)
    {
        printf("Use: %s <dll path>\n", argv[0]);
        return 1;
    }

    // Get dll path and pid
    const char *path = argv[1];
    DWORD pid = get_pid_from_allowed_list(processes, sizeof(processes) / sizeof(processes[0]));

    if (pid)
        return pid;
    else
        printf("No allowed process running.\n");
        return 0;

    // Get process handle
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (h_process == NULL)
    {
        printf("\nFailed to get the process handle - %d\n", GetLastError());
        return 1;
    }

    // Allocate memory
    LPVOID mem_alloc = VirtualAllocEx(h_process, NULL, strlen(path) + 1, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);

    if (mem_alloc == NULL)
    {
        printf("Failed to allocate memory in process - %d\n", GetLastError());
        return 1;
    }

    // Write dll into memory
    WriteProcessMemory(h_process, mem_alloc, path, strlen(path) + 1, NULL);

    // Get handle to kernel32.dll
    HMODULE h_kernel32 = GetModuleHandleW(L"kernel32.dll");

    if (h_kernel32 == NULL)
    {
        printf("Failed to get the kernel32 handle - %d\n", GetLastError());
        return 1;
    }

    // Create thread executing the dll
    FARPROC load_library_addr = GetProcAddress(h_kernel32, "LoadLibraryA");
    HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_addr, mem_alloc, 0, NULL);

    if (h_thread == NULL)
    {
        printf("Failed to create thread in process - %d\n", GetLastError());
        return 1;
    }

    // Wait and close
    WaitForSingleObject(h_thread, INFINITE);
    CloseHandle(h_process);

    return 0;
}