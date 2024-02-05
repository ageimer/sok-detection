#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bearssl_rsa.h>
#define RSA1024
#define OAEP
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    // copying the private key
    const br_rsa_private_key key = {
        NLEN*8,
        input+=(NLEN+DLEN), PLEN,
        input+=PLEN, QLEN,
        input+=QLEN, DPLEN,
        input+=DPLEN, DQLEN,
        input+=DQLEN, QINVLEN
    };

    uint8_t* cipher = input+QINVLEN;

#ifdef DEBUG
    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(cipher, NLEN);
#endif

    // OAEP decryption (in-place in ciphertext)
    size_t outl = NLEN;
    int ret = br_rsa_i31_oaep_decrypt(&br_sha1_vtable, NULL, 0, &key, cipher, &outl);
    
#ifdef DEBUG
    printf("\nret = %d (1 on success)", ret);
    printf("\ndecrypted:\t");
    printhex(cipher, outl);
    printf("\n");
#endif

}

extern void InitTarget(uint8_t* input)
{}
