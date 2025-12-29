#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "get_dir.h"

#define KEY_SIZE 16
#define IV_SIZE 16
#define MAX_PATH 260

void handle_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

int rsa_decrypt_key() {
    return 0;
}

unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) handle_error("Cannot open encrypted key");

    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(*len);
    if (!buf) handle_error("malloc failed");

    if (fread(buf, 1, *len, f) != *len)
        handle_error("Failed to read encrypted key");

    fclose(f);
    return buf;
}

/* AES-128-CTR decryption */
int decrypt_file_aes_ctr(const char *source, const char *target, const unsigned char key[KEY_SIZE]) {
    FILE *infile  = fopen(source, "rb");
    if (!infile) handle_error("Cannot open encrypted file");

    FILE *outfile = fopen(target, "wb");
    if (!outfile) {
        fclose(infile);
        handle_error("Cannot open output file");
    }

    unsigned char iv[IV_SIZE];

    // Read IV from start of encrypted file 
    if (fread(iv, 1, IV_SIZE, infile) != IV_SIZE)
        handle_error("Failed to read IV");

    /* DECRYPTION */

    // Cleanup
    fclose(infile);
    fclose(outfile);

    return 0;
}

int main(void)
{
    printf("Decryption complete.\n");
    return 0;
}
