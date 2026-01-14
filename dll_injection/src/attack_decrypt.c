#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <mbedtls/aes.h>

#define AES_KEY_SIZE 16       // 128-bit AES
#define IV_SIZE 16            // same as in your encrypt function
#define BUFFER_SIZE 4096      // same buffer size

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int read_aes_key(const char *key_file, unsigned char *key, size_t key_size) {
    FILE *f = fopen(key_file, "rb");
    if (!f) return -1;

    size_t n = fread(key, 1, key_size, f);
    fclose(f);

    return n == key_size ? 0 : -1;
}

void decrypt_file(const char *source, const char *target, const unsigned char *key) {
    FILE *in = fopen(source, "rb");
    if (!in)
        handle_error("Cannot open input file");

    FILE *out = fopen(target, "wb");
    if (!out)
        handle_error("Cannot open output file");

    unsigned char iv[IV_SIZE];
    unsigned char nonce_counter[IV_SIZE];
    unsigned char stream_block[16] = {0};
    size_t nc_off = 0;

    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE)
        handle_error("Failed to read IV");

    memcpy(nonce_counter, iv, IV_SIZE);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0)
        handle_error("AES key setup failed");

    unsigned char buffer[BUFFER_SIZE];
    size_t n;

    while ((n = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        if (mbedtls_aes_crypt_ctr(&aes, n, &nc_off, nonce_counter, stream_block, buffer, buffer) != 0)
            handle_error("AES-CTR decryption failed");

        if (fwrite(buffer, 1, n, out) != n)
            handle_error("Failed to write decrypted data");
    }

    mbedtls_aes_free(&aes);
    fclose(in);
    fclose(out);
}

void decrypt_all_myenc_files_in_dir(const char *files_dir, const unsigned char *key) {
    DIR *dir = opendir(files_dir);
    if (!dir)
        handle_error("Cannot open directory");

    struct dirent *entry;
    char source_path[1024];
    char target_path[1024];
    const char *extension = ".malenc";
    size_t ext_len = strlen(extension);

    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        size_t name_len = strlen(entry->d_name);

        // Only process files ending with ".myenc"
        if (name_len <= ext_len || strcmp(entry->d_name + name_len - ext_len, extension) != 0)
            continue;

        // Build full source path
        snprintf(source_path, sizeof(source_path), "%s/%s", files_dir, entry->d_name);

        // Build target path by stripping ".myenc"
        snprintf(target_path, sizeof(target_path), "%s/%.*s", files_dir, (int)(name_len - ext_len), entry->d_name);

        decrypt_file(source_path, target_path, key);
        printf("Decrypted: %s -> %s\n", source_path, target_path);
    }

    closedir(dir);
}

/* Example usage */
int attack_decrypt() {
    unsigned char key[AES_KEY_SIZE];

    if (read_aes_key("decryption_key.bin", key, AES_KEY_SIZE) != 0)
        return -1;

    decrypt_all_myenc_files_in_dir("encrypted_files", key);

    return 0;
}
