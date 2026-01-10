#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int attack_crypto(const char *input_file);

void crypto_cleanup(void);

#ifdef __cplusplus
}
#endif