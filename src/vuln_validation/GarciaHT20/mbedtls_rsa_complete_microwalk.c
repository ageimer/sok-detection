#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#define RSA1024
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    mbedtls_rsa_context ctx;

    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);

    // copying and verifying the private and public key, omitting the private exponent
    // the CRT parameters and the private exponent will be recomputed, triggering the vulnerability
    mbedtls_rsa_import_raw( &ctx, input, NLEN,
                            input+NLEN+DLEN, PLEN,
                            input+NLEN+DLEN+PLEN, QLEN,
                            NULL, 0,
                            RSA_E, sizeof RSA_E );

    int ret = mbedtls_rsa_complete(&ctx); 
    
#ifdef DEBUG
   printf("ret (0 on success): %d\n", ret);
#endif
    
	mbedtls_rsa_free(&ctx);

} 

extern void InitTarget(uint8_t* input)
{}
