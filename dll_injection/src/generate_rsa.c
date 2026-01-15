#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pem.h"

#define KEY_SIZE 1024
#define EXPONENT 65537

int main(void)
{
    int ret;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_keygen";

    // Initialize contexts
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("Failed to seed RNG: -0x%04x\n", -ret);
        return 1;
    }

    // Setup pk context for RSA
    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
        printf("Failed to setup PK context: -0x%04x\n", -ret);
        return 1;
    }

    // Generate RSA keypair
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT);
    if (ret != 0) {
        printf("Failed to generate RSA key: -0x%04x\n", -ret);
        return 1;
    }

    // Write private key to PEM file
    FILE *f = fopen("private_key.pem", "wb");
    if (!f) {
        printf("Cannot open private_key.pem for writing\n");
        return 1;
    }

    unsigned char buf[16000]; // sufficient buffer for 1024-bit key
    memset(buf, 0, sizeof(buf));

    if ((ret = mbedtls_pk_write_key_pem(&pk, buf, sizeof(buf))) != 0) {
        printf("Failed to write private key PEM: -0x%04x\n", -ret);
        fclose(f);
        return 1;
    }

    fwrite(buf, 1, strlen((char*)buf), f);
    fclose(f);

    // Write public key to PEM file
    f = fopen("public_key.pem", "wb");
    if (!f) {
        printf("Cannot open public_key.pem for writing\n");
        return 1;
    }

    memset(buf, 0, sizeof(buf));
    if ((ret = mbedtls_pk_write_pubkey_pem(&pk, buf, sizeof(buf))) != 0) {
        printf("Failed to write public key PEM: -0x%04x\n", -ret);
        fclose(f);
        return 1;
    }

    fwrite(buf, 1, strlen((char*)buf), f);
    fclose(f);

    printf("RSA keypair generated successfully.\n");
    printf("Private key: private_key.pem\n");
    printf("Public key:  public_key.pem\n");

    // Cleanup
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}
