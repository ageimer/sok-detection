#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#define RSA1024
#define PKCS1_V15
#include "../../common.h"

int main() {
    mbedtls_rsa_context ctx;
    mbedtls_entropy_context ent_ctx;
    mbedtls_ctr_drbg_context rng_ctx;
    uint8_t* seed = "rsa_decrypt";

    // annotating secrets
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_P, PLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_Q, QLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_D, DLEN);
    abacus_make_symbolic(3,
        (void*[]){RSA_P, RSA_Q, RSA_D},
        (uint32_t[]){PLEN, QLEN, DLEN});

    mbedtls_rsa_init(&ctx);
    
    // copying and verifying the private and public key
    mbedtls_rsa_import_raw(&ctx, RSA_N, NLEN,
                            RSA_P, PLEN,
                            RSA_Q, QLEN,
                            RSA_D, DLEN,
                            RSA_E, ELEN);
    mbedtls_rsa_complete( &ctx ); 

    // PRNG initialization and seeding
    mbedtls_entropy_init(&ent_ctx);
    mbedtls_ctr_drbg_init(&rng_ctx);
    mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &ent_ctx, seed, strlen(seed));

    // PKCS#1 v1.5 decryption, PRNG is used for blinding and is required by MbedTLS
    uint8_t dec_out[NLEN] = { 0x00 };
    size_t outl;
    int ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(&ctx, mbedtls_ctr_drbg_random, &rng_ctx, &outl, ciphertext, dec_out, NLEN);
    
#ifdef DEBUG
    printf("\nret = %d (0 on success)", ret);
    printf("\noriginal:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, NLEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, outl);
    printf("\n");
#endif

	mbedtls_rsa_free(&ctx);
    mbedtls_ctr_drbg_free(&rng_ctx);
    mbedtls_entropy_free(&ent_ctx);

    return 0;
} 
