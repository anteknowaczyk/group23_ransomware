#include <windows.h>
#include <stdio.h>

static int main(int argc, char **argv)
{
    // Get dll path and pid
    PCSTR path = argv[1];
    DWORD pid = atoi(argv[2]);

    // Get process handle
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (h_process == NULL)
    {
        printf("Failed to get the process handle - %d\n", GetLastError());
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