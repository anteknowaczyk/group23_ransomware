#include "get_relative_path.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"

/* AES 128 */
#define KEY_SIZE    16
#define IV_SIZE     16
#define BUFFER_SIZE 4096

/* Public variables for mbedtls crypto */

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

/* Handle errors */
static void handle_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* Initialize mbedtls state */
static void rng_init(void) {
    static bool initialized = false;
    const char *pers = "file_decryptor";

    if (initialized) return;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers)) != 0)
        handle_error("RNG init failed");

    initialized = true;
}

/* Cleanup the mbedtls state */
static void rng_free(void) {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

/* Decrypt and load the AES key using the locally stored private key */
static void load_aes_key_rsa(const char *aes_key_file, const char *privkey_file, unsigned char *aes_key) {
    rng_init();

    // Open encrypted AES key file
    FILE *f = fopen(aes_key_file, "rb");
    if (!f) handle_error("Cannot open AES key file");

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    /* Parse private RSA key */
    if (mbedtls_pk_parse_keyfile(
        &pk,
        privkey_file,
        NULL,                    // no password
        mbedtls_ctr_drbg_random, 
        &ctr_drbg                
    ) != 0) {
        handle_error("Failed to load private key");
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA))
        handle_error("Private key is not RSA");

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    size_t rsa_len = mbedtls_pk_get_len(&pk);

    unsigned char *cipher = malloc(rsa_len);
    if (!cipher) handle_error("malloc failed");

    if (fread(cipher, 1, rsa_len, f) != rsa_len)
        handle_error("Failed to read encrypted AES key");

    fclose(f);

    size_t olen = 0;

    /* Decrypt AES key*/
    if (mbedtls_rsa_pkcs1_decrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, &olen, cipher, aes_key, KEY_SIZE) != 0) {
        handle_error("RSA PKCS#1 decryption failed");
    }

    if (olen != KEY_SIZE)
        handle_error("Decrypted AES key has unexpected length");

    /* Cleanup */
    free(cipher);
    mbedtls_pk_free(&pk);
}

/* Decrypt file */
void decrypt_file_aes_ctr(const char *source, const char *target, const unsigned char *key) {
    /* Open files */
    FILE *in = fopen(source, "rb");
    if (!in) handle_error("Cannot open input file");

    FILE *out = fopen(target, "wb");
    if (!out) handle_error("Cannot open output file");

    /* Read the IV from the beginning of the file */
    unsigned char iv[IV_SIZE];
    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE)
        handle_error("Failed to read IV");

    /* Crypto setup */
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0)
        handle_error("Failed to set AES key");

    unsigned char buffer[BUFFER_SIZE];
    unsigned char stream_block[16] = {0};
    size_t nc_off = 0;
    size_t n;

    /* Decrypt */
    while ((n = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        mbedtls_aes_crypt_ctr(&aes, n, &nc_off, iv, stream_block, buffer, buffer);
        fwrite(buffer, 1, n, out);
    }

    /* Cleanup */
    mbedtls_aes_free(&aes);
    fclose(in);
    fclose(out);
}

int strip_enc_path(const char *input, char *output, size_t output_size)
{
    size_t len = strlen(input);

    if (len < 4 || strcmp(input + len - 7, ".malenc") != 0) {
        return -1; /* not an .malenc file */
    }

    if (len - 4 >= output_size) {
        return -1;
    }

    memcpy(output, input, len - 4);
    output[len - 4] = '\0';

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <encrypted_file>", argv[0]);
        return 1;
    }
    // Get private key path and aes path
    char private_rsa[MAX_PATH];
    if (get_relative_path(private_rsa, sizeof(private_rsa), "private_key.pem") != 0) {
        return 1;
    }

    char aes[MAX_PATH];
    if (get_relative_path(aes, sizeof(aes), "aes_key.bin") != 0) {
        return 1;
    }

    unsigned char aes_key[KEY_SIZE];

    load_aes_key_rsa(aes, private_rsa, aes_key);

    // Get output path
    char output_file[MAX_PATH];

    if (strip_enc_path(argv[1], output_file, sizeof(output_file)) != 0) {
        return -1;
    }

    decrypt_file_aes_ctr(argv[1], output_file, aes_key);

    memset(aes_key, 0, sizeof(aes_key));
    rng_free();

    printf("File decrypted successfully.\n");
    return 0;
}
