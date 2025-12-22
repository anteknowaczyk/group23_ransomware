#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>

#include "get_dir.h"

#define MAX_PATH 260

/* Generate RSA-2048 key pair and save to files */
int main(void)
{
    char exe_dir[MAX_PATH];
    get_dir(exe_dir, sizeof(exe_dir)); // make sure this function is defined

    EVP_PKEY *pkey = NULL;

    // Create context for RSA key generation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // Set RSA key size to 2048 bits
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // Generate key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // Write private key to file
    char priv_key_path[MAX_PATH];
    snprintf(priv_key_path, sizeof(priv_key_path), "%s\\private_key.pem", exe_dir);
    FILE *priv = fopen(priv_key_path, "wb");
    if (!priv)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(priv);

    // Write public key to file
    char pub_key_path[MAX_PATH];
    snprintf(pub_key_path, sizeof(pub_key_path), "%s\\public_key.pem", exe_dir);
    FILE *pub = fopen(pub_key_path, "wb");
    if (!pub)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    PEM_write_PUBKEY(pub, pkey);
    fclose(pub);

    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return 1;
}
