/*  This files contains the helper function for resolving relative paths on LUCA runtime. Before DLL-injection code runs from 
    the Injectors location, after the injection from the target processes location. */
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* Return the handle to the binary form which the code runs from */
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

/* Calculate the full path to a file located in the same directory as the DLL. Write it to buffer. */
int get_relative_path(char* outPath, size_t outSize, const char* filename)
{
    // Validate input
    if (!filename || !outPath || outSize == 0)
        return -1;

    // Get own module
    HMODULE hModule = get_own_module();

    DWORD size = MAX_PATH;
    char* path = malloc(size);
    if (!path)
        return -1;

    DWORD len;
    /* Get the module file path. If the buffer is too small double it */
    for (;;)
    {
        len = GetModuleFileNameA(hModule, path, size);
        if (len == 0)
        {
            free(path);
            return -1;
        }
        if (len < size)
            break;

        size *= 2;
        char* tmp = realloc(path, size);
        if (!tmp)
        {
            free(path);
            return -1;
        }
        path = tmp;
    }

    // Null terminate the path
    path[len] = '\0';

    // Strip the executable name - leaves just the dircetory
    char* lastSlash = strrchr(path, '\\');
    if (!lastSlash)
    {
        free(path);
        return -1;
    }
    *(lastSlash + 1) = '\0';

    if (strlen(path) + strlen(filename) + 1 > outSize)
    {
        free(path);
        return -1;
    }

    // Construc the final path
    strcpy(outPath, path);
    strcat(outPath, filename);

    free(path);
    return 0;
}
