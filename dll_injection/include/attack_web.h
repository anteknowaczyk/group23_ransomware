#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// send encrypted key to attacker's server
int send_key_to_attacker(void);

int get_decryption_key_from_attacker(void);

#ifdef __cplusplus
}
#endif
