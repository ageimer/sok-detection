#include <stdio.h>
#include <stdint.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#define KEY16
#define IV12
#define PLAINTEXT32
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    mbedtls_gcm_context ctx;
    uint8_t tag[16];
    size_t outl;
    uint8_t ciphertext[DATALEN];

    mbedtls_gcm_init(&ctx);

    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, input, KEYLEN*8);
    // starting encryption with no additionnal data
    mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, iv, IVLEN);
    // encrypting one block
    mbedtls_gcm_update(&ctx, plaintext, DATALEN, ciphertext, DATALEN, &outl);
    // finish and compute tag
    mbedtls_gcm_finish(&ctx, ciphertext, DATALEN, &outl, tag, 16);
    
#ifdef DEBUG
    uint8_t dec_out[DATALEN] = { 0x00 };
     
    mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, iv, IVLEN);
    mbedtls_gcm_update(&ctx, ciphertext, DATALEN, dec_out, DATALEN, &outl);
    
    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, DATALEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

	mbedtls_gcm_free(&ctx);

}

extern void InitTarget(uint8_t* input)
{}
