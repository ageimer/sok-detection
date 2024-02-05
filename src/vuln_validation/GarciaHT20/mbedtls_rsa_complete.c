#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#define RSA1024
#include "../../common.h"

int main() {

    // annotating secrets
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_P, sizeof RSA_P);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_Q, sizeof RSA_Q);
    abacus_make_symbolic(2,
        (void*[]){RSA_P, RSA_Q},
        (uint32_t[]){sizeof RSA_P, sizeof RSA_Q});

    mbedtls_rsa_context ctx;

    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);

    // copying and verifying the private and public key, omitting the private exponent
    // the CRT parameters and the private exponent will be recomputed, triggering the vulnerability
    mbedtls_rsa_import_raw( &ctx, RSA_N, sizeof RSA_N,
                            RSA_P, sizeof RSA_P,
                            RSA_Q, sizeof RSA_Q,
                            NULL, 0,
                            RSA_E, sizeof RSA_E );

       int ret = mbedtls_rsa_complete(&ctx); 
    
#ifdef DEBUG
   printf("ret (0 on success): %d\n", ret);
#endif
    
	mbedtls_rsa_free(&ctx);

    return 0;
} 

