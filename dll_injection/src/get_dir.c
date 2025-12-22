#include <windows.h>

void get_dir(char *buffer, size_t size)
{
    DWORD len = GetModuleFileNameA(NULL, buffer, (DWORD)size);
    if (len == 0 || len == size) return;

    // Remove exe filename
    char *last = strrchr(buffer, '\\');
    if (last) *last = '\0';
}