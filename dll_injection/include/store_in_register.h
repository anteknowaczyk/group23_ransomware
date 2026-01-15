#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdio.h>

typedef struct {
    const char *reg_path;
} storage_context_t;

int store_value(storage_context_t *ctx, const char *name, const unsigned char *data, size_t len);

int load_value(storage_context_t *ctx, const char *name, unsigned char *buffer, size_t buffer_len);

int store_qword(storage_context_t *ctx, const char *name, ULONGLONG value);

int load_qword(storage_context_t *ctx, const char *name, ULONGLONG *value);

#ifdef __cplusplus
}
#endif