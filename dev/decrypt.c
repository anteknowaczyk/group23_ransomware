#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>

void handle_error(void)
{
    fprintf(stderr, "Error\n");
    exit(1);
}

int decrypt_file_aes(const char *source, const char *target, unsigned char *p_key, unsigned char *p_iv)
{
    FILE *infile = NULL;
    FILE *outfile = NULL;

    // Open files
    infile = fopen(infile, "rb");
    if (!infile)
    {
        handle_error();
    }
    outfile = fopen(outfile, "rb");
    if (!outfile)
    {
        handle_error();
    }
    // TODO: check input size 0 ?

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handle_error();
    }

    // Initialize AES-128-CTR
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
    {
        handle_error();
    }

    /* DECRYPTION */

    unsigned char inbuff[4096];
    unsigned char outbuff[4096 + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    while (true)
    {
        int inbyte = fread(inbuff, 1, sizeof(inbuff), infile);
        if (inbyte <= 0)
            break;

        if (1 != EVP_DecryptUpdate(ctx, outbuff, &outlen, inbuff, inbyte))
        {
            handle_error();
        }
        fwrite(outbuff, 1, outlen, outfile);
    }

    // Finalize. There is no padding due to CTR mode (outlen = 0)
    if (1 != EVP_EncryptFinal_ex(ctx, outbuff, &outlen))
    {
        handle_error();
    }
    fwrite(outbuff, 1, outlen, outfile);

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

int main()
{
    const char *src = "";
    const char *trg = "";
    unsigned char key[16];
    unsigned char iv[16];

    // key = { }
    // iv = { }

    decypt_file_aes(src, trg, key, iv);
}