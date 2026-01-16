/*  This file contains the helper functions for writing and reading data from the Registery. */
#include <stdio.h>
#include <windows.h>
#include <string.h>

typedef struct {
    const char *reg_path;
} storage_context_t;

/* Write binary data to the registry */
int store_value(storage_context_t *ctx, const char *name, const unsigned char *data, size_t len) {
    if (!ctx || !name || !data) return -1;

    HKEY hKey;
    LONG res = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        ctx->reg_path,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );
    if (res != ERROR_SUCCESS) return -1;

    res = RegSetValueExA(
        hKey,
        name,
        0,
        REG_BINARY,
        data,
        (DWORD)len
    );

    RegCloseKey(hKey);
    return res == ERROR_SUCCESS ? 0 : -1;
}

/* Read binary data from the registry */
int load_value(storage_context_t *ctx, const char *name, unsigned char *buffer, size_t buffer_len) {
    if (!ctx || !name || !buffer) return -1;

    HKEY hKey;
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER, ctx->reg_path, 0, KEY_READ, &hKey);
    if (res != ERROR_SUCCESS) return -1;

    DWORD type = 0;
    DWORD size = (DWORD)buffer_len;

    res = RegQueryValueExA(
        hKey,
        name,
        NULL,
        &type,
        buffer,
        &size
    );

    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS) return -1;
    if (type != REG_BINARY) return -1;
    if (size != buffer_len) return -1;

    return 0;
}

/* Write QWORD (8 bytes) to the registry */
int store_qword(storage_context_t *ctx, const char *name, ULONGLONG value)
{
    if (!ctx || !name) return -1;

    HKEY hKey;
    if (RegCreateKeyExA(
            HKEY_CURRENT_USER,
            ctx->reg_path,
            0, NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            NULL,
            &hKey,
            NULL
        ) != ERROR_SUCCESS)
        return -1;

    LONG res = RegSetValueExA(
        hKey,
        name,
        0,
        REG_QWORD,
        (BYTE *)&value,
        sizeof(value)
    );

    RegCloseKey(hKey);
    return res == ERROR_SUCCESS ? 0 : -1;
}

/* Read QWORD (8 bytes) from registery */
int load_qword(storage_context_t *ctx, const char *name, ULONGLONG *value)
{
    if (!ctx || !name || !value) return -1;

    HKEY hKey;
    if (RegOpenKeyExA(
            HKEY_CURRENT_USER,
            ctx->reg_path,
            0,
            KEY_READ,
            &hKey
        ) != ERROR_SUCCESS)
        return -1;

    DWORD type = 0;
    DWORD size = sizeof(*value);

    LONG res = RegQueryValueExA(
        hKey,
        name,
        NULL,
        &type,
        (BYTE *)value,
        &size
    );

    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS) return -1;
    if (type != REG_QWORD) return -1;
    if (size != sizeof(*value)) return -1;

    return 0;
}

