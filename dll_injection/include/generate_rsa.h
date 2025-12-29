#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void handle_error(const char *msg);

int generate_rsa_keys(const char *output_dir);

#ifdef __cplusplus
}
#endif