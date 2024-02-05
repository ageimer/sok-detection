#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#define RSA1024
#define OAEP
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    mbedtls_rsa_context ctx;
    mbedtls_entropy_context ent_ctx;
    mbedtls_ctr_drbg_context rng_ctx;
    uint8_t* seed = "rsa_decrypt";

    mbedtls_rsa_init(&ctx);
    // set padding for OAEP
    mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    // copying and verifying the private and public key
    mbedtls_rsa_import_raw(&ctx, input, NLEN,
                            input+NLEN+DLEN, PLEN,
                            input+NLEN+DLEN+PLEN, QLEN,
                            input+NLEN, DLEN,
                            RSA_E, ELEN);

    uint8_t* cipher = input+NLEN+DLEN+PLEN+QLEN+DPLEN+DQLEN+QINVLEN;
    
    // copying and verifying the private and public key
    mbedtls_rsa_complete(&ctx); 

    // PRNG initialization and seeding
    mbedtls_entropy_init(&ent_ctx);
    mbedtls_ctr_drbg_init(&rng_ctx);
    mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &ent_ctx, seed, strlen(seed));

    // OAEP decryption, PRNG is used for blinding and is required by MbedTLS
    uint8_t dec_out[NLEN] = { 0x00 };
    size_t outl;
    int ret = mbedtls_rsa_rsaes_oaep_decrypt(&ctx, mbedtls_ctr_drbg_random, &rng_ctx, NULL, 0, &outl, cipher, dec_out, NLEN);
    
#ifdef DEBUG
    printf("\nret = %d (0 on success)", ret);
    printf("\noriginal:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(cipher, NLEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, outl);
    printf("\n");
#endif

	mbedtls_rsa_free(&ctx);
    mbedtls_entropy_free(&ent_ctx);
    mbedtls_ctr_drbg_free(&rng_ctx);
}

extern void InitTarget(uint8_t* input)
{}
