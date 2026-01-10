#pragma once

#include <windows.h>
#include <stddef.h>
    
#ifdef __cplusplus
extern "C" {
#endif

int get_relative_path(char* outPath, DWORD outSize, const char* filename);

#ifdef __cplusplus
}
#endif