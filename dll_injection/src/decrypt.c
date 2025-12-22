#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "get_dir.h"

#define KEY_SIZE 16
#define IV_SIZE 16
#define MAX_PATH 260

void handle_error(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/* Load AES key from .bin file */
EVP_PKEY *load_private_key(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) handle_error("Cannot open private key");

    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!pkey) handle_error("Failed to load private key");
    return pkey;
}

int rsa_decrypt_key(EVP_PKEY *privkey, const unsigned char *enc_key, size_t enc_key_len, unsigned char *out_key, size_t out_key_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) return 0;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        return 0;

    size_t len = out_key_len;
    if (EVP_PKEY_decrypt(ctx, out_key, &len, enc_key, enc_key_len) <= 0)
        return 0;

    EVP_PKEY_CTX_free(ctx);

    return (len == out_key_len); // must be exactly 16 bytes
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
    char exe_dir[MAX_PATH];
    get_dir(exe_dir, sizeof(exe_dir));

    char enc_file[MAX_PATH];
    snprintf(enc_file, sizeof(enc_file), "%s\\%s", exe_dir, "important.enc");

    char out_file[MAX_PATH];
    snprintf(out_file, sizeof(out_file), "%s\\%s", exe_dir, "important_decrypted.pdf");

    char enc_key_file[MAX_PATH];
    snprintf(enc_key_file, sizeof(enc_key_file), "%s\\%s", exe_dir, "aes_key.enc");

    char priv_key_file[MAX_PATH];
    snprintf(priv_key_file, sizeof(priv_key_file), "%s\\%s", exe_dir, "private_key.pem");

    unsigned char aes_key[KEY_SIZE];

    // Load private key
    EVP_PKEY *privkey = load_private_key(priv_key_file);

    // Read encrypted AES key
    size_t enc_key_len;
    unsigned char *enc_key = read_file(enc_key_file, &enc_key_len);

    // Decrypt AES key
    if (!rsa_decrypt_key(privkey, enc_key, enc_key_len, aes_key, KEY_SIZE))
        handle_error("AES key decryption failed");

    free(enc_key);
    EVP_PKEY_free(privkey);

    // Decrypt file
    decrypt_file_aes_ctr(enc_file, out_file, aes_key);

    printf("Decryption complete.\n");
    return 0;
}
