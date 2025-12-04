#include <windows.h>

/* Define the data structures from winternl.h and ntdll.lib to make the code platform-independent */

// See: https://learn.microsoft.com/en-us/windows/win32/api/lsalookup/ns-lsalookup-lsa_unicode_string
typedef struct _LSA_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

// See: http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FLDR_MODULE.html
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

// See: http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FPEB_LDR_DATA.html
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// See: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/curdir.htm
typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, *PCURDIR;

// See: https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-string
typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} ANSI_STRING, *PANSI_STRING;

// See: http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FRTL_DRIVE_LETTER_CURDIR.html
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

// See: http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FRTL_USER_PROCESS_PARAMETERS.html
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

// See: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FPEB.html
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

/* Low-level, function pointer types for required functions */
typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);

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
inline DWORD64 get_module_handle_a(char *lp_module_name)
{
    // Get the pointer to the PEB
    // See: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
    PPEB peb = (PPEB)__readgsqword(0x60);

    PLDR_MODULE module = NULL;
    CHAR dll_name[64] = {0};
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
            // Compare the name with the required function
            // Zeroize a memory space, convert the name to ascii and compare
            zeroize((DWORD64)dll_name, sizeof(dll_name));
            wchar_to_ascii(dll_name, module->BaseDllName.Buffer, 0x40);
            if (string_compare_a(lp_module_name, dll_name))
                return (DWORD64)module->BaseAddress;
        }
        next = next->Flink;
    }
    return 0;
}

/*
    Low level version of GetProcessAddress function. Manually run through the export table to find
    the matching matching name. Return the function address.
    See: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress

*/
inline DWORD64 get_process_address(DWORD64 module_base, LPCSTR lp_proc_name)
{
    PIMAGE_DOS_HEADER dos = NULL;
    PIMAGE_NT_HEADERS nt = NULL;
    PIMAGE_FILE_HEADER file = NULL;
    PIMAGE_OPTIONAL_HEADER opt = NULL;

    // TODO:Parse the PE headers

    // Retrieve the export table
    // See: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only Export Directory Table
    IMAGE_EXPORT_DIRECTORY *export_table = (PIMAGE_EXPORT_DIRECTORY)(module_base + opt->DataDirectory[0].VirtualAddress);
    PDWORD addresses_of_names = (PDWORD)((LPBYTE)module_base + export_table->AddressOfNames);
    PDWORD addresses_of_functions = (PDWORD)((LPBYTE)module_base + export_table->AddressOfFunctions);
    PDWORD addresses_of_name_ordinals = (PDWORD)((LPBYTE)module_base + export_table->AddressOfNameOrdinals);

    PBYTE p_function_name = NULL;
    // Iterate through the table to find the matching name
    for (DWORD x = 0; x < export_table->NumberOfNames; x++)
    {
        p_function_name = addresses_of_functions[x] + (PBYTE)module_base;
        if (string_compare_a((PCHAR)p_function_name, lp_proc_name))
        {
            return ((DWORD64)module_base + addresses_of_functions[x]);
        }
    }
    return 0;
}

inline DWORD64 copy_memory(PBYTE target, PBYTE source, SIZE_T len)
{
    while (len > 0)
    {
        *target++ = *source++;
    }
    return target;
}

void ReflexiveLoad()
{
    // Step 1: Calculate the address of own image
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

    // Step 2: handle kernel exports to retrieve necessary functions
    // System function names:
    char KERNEL32_DLL[] = {'\x4b', '\x45', '\x52', '\x4e', '\x45', '\x4c', '\x33', '\x32', '\x2e', '\x44', '\x4c', '\x4c', 0};
    char VirtualAlloc[] = {'\x56', '\x69', '\x72', '\x74', '\x75', '\x61', '\x6c', '\x41', '\x6c', '\x6c', '\x6f', '\x63', 0};
    char GetProcAddress[] = {'\x47', '\x65', '\x74', '\x50', '\x72', '\x6f', '\x63', '\x41', '\x64', '\x64', '\x72', '\x65', '\x73', '\x73', 0};
    char LoadLibraryA[] = {'\x4c', '\x6f', '\x61', '\x64', '\x4c', '\x69', '\x62', '\x72', '\x61', '\x72', '\x79', '\x41', 0};

    // Get module handle of kernel32.dll
    DWORD64 kernel32 = get_module_handle_a(KERNEL32_DLL);
    // Load addresses of kernel32.dll calls

    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    VIRTUALALLOC virtual_alloc = (VIRTUALALLOC)get_process_address(kernel32, VirtualAlloc);

    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    GETPROCADDRESS get_proc_address = (GETPROCADDRESS)get_process_address(kernel32, GetProcAddress);

    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
    LOADLIBRARYA p_load_library_a = (LOADLIBRARYA)get_process_address(kernel32, LoadLibraryA);

    // Now we have access to system functions from kernel32

    // Step 3: allocate memory for the dll
    DWORD64 dll_base = (DWORD64)virtual_alloc(NULL, nt_headers_addr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // Step 4: copy headers
    copy_memory(dll_base, loader_image_addr, nt_headers_addr->OptionalHeader.SizeOfHeaders);

    // Step 5: copy dll sections
    DWORD virtual_addr;
    DWORD data_addr;
    PIMAGE_SECTION_HEADER section_header_addr = IMAGE_FIRST_SECTION(nt_headers_addr);

    for (; section_header_addr->VirtualAddress != (DWORD)NULL; section_header_addr++)
    {
        virtual_addr = dll_base + section_header_addr->VirtualAddress;
        data_addr = loader_image_addr + section_header_addr->PointerToRawData;

        copy_memory(virtual_addr, data_addr, section_header_addr->SizeOfRawData);
    }

    // Step 6: resolve imports

    // Step 7: call the dll
}
