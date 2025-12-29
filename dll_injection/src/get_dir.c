#include <windows.h>
#include <string.h>

void get_dir(char *buffer, size_t size)
{
    if (!buffer || size == 0)
        return;

    DWORD len = GetModuleFileNameA(NULL, buffer, (DWORD)size);

    if (len == 0 || len >= size) {
        buffer[0] = '\0';
        return;
    }

    char *last = strrchr(buffer, '\\');
    if (last)
        *last = '\0';
}
