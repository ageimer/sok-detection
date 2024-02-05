#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bearssl_rsa.h>
#define RSA1024
#define OAEP
#include "../../common.h"

int main() {
    // annotating secrets
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_P, PLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_Q, QLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_DP, DPLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_DQ, DQLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_QINV, QINVLEN);
    abacus_make_symbolic(5,
        (void*[]){RSA_P, RSA_Q, RSA_DP, RSA_DQ, RSA_QINV},
        (uint32_t[]){PLEN, QLEN, DPLEN, DQLEN, QINVLEN});
    
    // copying the private key
    const br_rsa_private_key key = {
        NLEN*8,
        (unsigned char *)RSA_P, PLEN,
        (unsigned char *)RSA_Q, QLEN,
        (unsigned char *)RSA_DP, DPLEN,
        (unsigned char *)RSA_DQ, DQLEN,
        (unsigned char *)RSA_QINV, QINVLEN
    };

#ifdef DEBUG
    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, NLEN);
#endif

    // OAEP decryption (in-place in ciphertext)
    size_t outl = NLEN;
    int ret = br_rsa_i31_oaep_decrypt(&br_sha1_vtable, NULL, 0, &key, ciphertext, &outl);
    
#ifdef DEBUG
    printf("\nret = %d (1 on success)", ret);
    printf("\ndecrypted:\t");
    printhex(ciphertext, outl);
    printf("\n");
#endif

    return 0;
} 
