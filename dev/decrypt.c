#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/evp.h>

#define KEY_SIZE 16
#define IV_SIZE 16

void handle_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* Load AES key from .bin file */
void load_key(const char *path, unsigned char key[KEY_SIZE])
{
    FILE *f = fopen(path, "rb");
    if (!f) handle_error("Failed to open key file");

    if (fread(key, 1, KEY_SIZE, f) != KEY_SIZE)
        handle_error("Failed to read key");

    fclose(f);
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

    // Setup decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handle_error("EVP_DecryptInit_ex failed");

    /* DECRYPTION */
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    size_t nread;
    while ((nread = fread(inbuf, 1, sizeof(inbuf), infile)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, (int)nread))
            handle_error("EVP_DecryptUpdate failed");

        if (fwrite(outbuf, 1, outlen, outfile) != (size_t)outlen)
            handle_error("Failed to write plaintext");
    }

    // Finalize
    if (1 != EVP_DecryptFinal_ex(ctx, outbuf, &outlen))
        handle_error("EVP_DecryptFinal_ex failed");

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);

    return 0;
}

int main(void)
{
    const char *enc_file  = "C:/Users/20231367/OneDrive - TU Eindhoven/Documents/Y3Q2/2IC80 Lab on Offensive Security/dll_injection/important.enc";
    const char *out_file  = "C:/Users/20231367/OneDrive - TU Eindhoven/Documents/Y3Q2/2IC80 Lab on Offensive Security/dll_injection/important_decrypted.pdf";
    const char *key_file  = "C:/Users/20231367/OneDrive - TU Eindhoven/Documents/Y3Q2/2IC80 Lab on Offensive Security/dll_injection/aes_key.bin";

    unsigned char key[KEY_SIZE];

    load_key(key_file, key);

    decrypt_file_aes_ctr(enc_file, out_file, key);

    printf("Decryption complete.\n");
    return 0;
}
