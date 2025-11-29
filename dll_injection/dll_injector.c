#include <windows.h>

/* Define the data structures from winternl.h and ntdll.lib to make the code platform-independent */

typedef struct _LSA_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_MODULE
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, *PCURDIR;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBase;
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID *KernelCallbackTable;
    PVOID EventLogSection;
    PVOID EventLog;
    PVOID FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[0x2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID *ReadOnlyServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    BYTE Spare2[0x4];
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID **ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    ULONG OSBuildNumber;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG GdiHandleBuffer[0x22];
    ULONG PostProcessInitRoutine;
    ULONG TlsExpansionBitmap;
    BYTE TlsExpansionBitmapBits[0x80];
    ULONG SessionId;
} PEB, *PPEB;

/* End data structures */

/*
    Fill a block of memory at destination with zeros.
*/
inline void zeroize(DWORD64 destination, SIZE_T size)
{
    PULONG dest = (PULONG)destination;
    SIZE_T count = size / sizeof(ULONG);

    while (count > 0)
    {
        *dest = 0;
        dest++;
        count--;
    }
}

/*
    Convert a wide character string at destination into regular ASCII.
*/
inline SIZE_T wchar_to_ascii(PCHAR destination, PWCHAR source, SIZE_T max)
{
    if (!destination || !source || max == 0)
    {
        return 0;
    }

    SIZE_T i;
    for (i = 0; i < max - 1; i++) // reserve space for null terminator
    {
        if (source[i] == L'\0') // end of source string
        {
            destination[i] = '\0';
            return i;
        }

        // Copy low byte, ignore high byte
        destination[i] = (char)(source[i] & 0xFF);
    }

    // Ensure null-termination
    destination[i] = '\0';
    return i;
}

/*
    Compare two strings until reaching '\0'.
*/
inline BOOL string_compare_a(LPCSTR str1, LPCSTR str2)
{
    while (*str1 && (*str1 == *str2))
    {
        str1++;
        str2++;

        if (*str1 == '\0')
            return TRUE;
    }
    return FALSE;
}

/*
    Low level version of GetModuleHandleA function. Manually read through PEB table to get the system call
    independently of the host process.
    See:https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
*/
inline DWORD64 get_module_handle_a(char *lpModuleName)
{
    // Get the pointer to the PEB
    // See: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
    PPEB peb = (PPEB)__readgsqword(0x60);

    PLDR_MODULE module = NULL;
    CHAR wDllName[64] = {0};
    // Get the head of the doubly-linked list containing the loaded modules.
    PLIST_ENTRY head = &peb->LoaderData->InMemoryOrderModuleList;
    // Get the first module in the list.
    PLIST_ENTRY next = head->Flink;
    // Add the offset to the InMemoryOrderLinks
    module = (PLDR_MODULE)((PBYTE)next - 0x10);

    // Traverse the list and find the address with the matching name
    while (next != head)
    {
        // Get next module
        module = (PLDR_MODULE)((PBYTE)next - 0x10);
        if (module->BaseDllName.Buffer != NULL)
        {
            // Retrieve the name and convert to ASCII
            zeroize((DWORD64)wDllName, sizeof(wDllName));
            wchar_to_ascii(wDllName, module->BaseDllName.Buffer, 0x40);
            if (string_compare_a(lpModuleName, wDllName))
                return (DWORD64)module->BaseAddress;
        }
        next = next->Flink;
    }
    return 0;
}

void ReflexiveLoad()
{
    // Calculate the address of current instuction
    DWORD64 loader_image_addr;
    loader_image_addr = (DWORD64)__buildin_extract_return_addr(__builtin_return_address(0));

    // Calculate the ReflexiveLoader NT headers address
    PIMAGE_NT_HEADERS32 nt_headers_addr;
    while (1 == 1)
    {
        // Verfiy if memory at loader_image_addr is a valid DOS header.
        // See: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format MS-DOS Stub and Signature

        if (((PIMAGE_DOS_HEADER)loader_image_addr)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            // Use the e_lfanew offset to get the NT headers address and verify.
            nt_headers_addr = (PIMAGE_NT_HEADERS)(loader_image_addr + ((PIMAGE_DOS_HEADER)loader_image_addr)->e_lfanew);
            if (nt_headers_addr->Signature == IMAGE_NT_SIGNATURE)
            {
                break;
            }
        }
        // Bruteforce the PE base address.
        loader_image_addr--;
    }

    // Allocate memory for loading DLL
    // System function names:
    char KERNEL32_DLL[] = {'\x4b', '\x45', '\x52', '\x4e', '\x45', '\x4c', '\x33', '\x32', '\x2e', '\x44', '\x4c', '\x4c', 0};
    char VirtualAlloc[] = {'\x56', '\x69', '\x72', '\x74', '\x75', '\x61', '\x6c', '\x41', '\x6c', '\x6c', '\x6f', '\x63', 0};
    char GetProcAddress[] = {'\x47', '\x65', '\x74', '\x50', '\x72', '\x6f', '\x63', '\x41', '\x64', '\x64', '\x72', '\x65', '\x73', '\x73', 0};
    char LoadLibraryA[] = {'\x4c', '\x6f', '\x61', '\x64', '\x4c', '\x69', '\x62', '\x72', '\x61', '\x72', '\x79', '\x41', 0};

    // Get module handle of kernel32.dll
    DWORD64 kernel32 = get_module_handle_a(KERNEL32_DLL);
    // Load addresses of kernel32.dll calls:
    // virtualAlloc
    // pGetProcAddress
    // pLoadLibraryA
}
