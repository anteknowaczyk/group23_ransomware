#include <windows.h>
#include <stdlib.h>
#include <string.h>

static HMODULE get_own_module(void)
{
    HMODULE hModule = NULL;

    /* Get module containing this function */
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)&get_own_module,
            &hModule))
    {
        return NULL;
    }

    return hModule;
}

int get_relative_path(char* outPath, size_t outSize, const char* filename)
{
    if (!filename || !outPath || outSize == 0)
        return 1;

    HMODULE hModule = get_own_module();  // DLL or EXE automatically

    DWORD size = MAX_PATH;
    char* path = malloc(size);
    if (!path)
        return 1;

    DWORD len;
    for (;;)
    {
        len = GetModuleFileNameA(hModule, path, size);
        if (len == 0)
        {
            free(path);
            return 1;
        }
        if (len < size)
            break;

        size *= 2;
        char* tmp = realloc(path, size);
        if (!tmp)
        {
            free(path);
            return 1;
        }
        path = tmp;
    }

    path[len] = '\0';

    char* lastSlash = strrchr(path, '\\');
    if (!lastSlash)
    {
        free(path);
        return 1;
    }
    *(lastSlash + 1) = '\0';

    if (strlen(path) + strlen(filename) + 1 > outSize)
    {
        free(path);
        return 1;
    }

    strcpy(outPath, path);
    strcat(outPath, filename);

    free(path);
    return 0;
}
