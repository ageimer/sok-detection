#include <stdio.h>
#include <string.h>
#include <mbedtls/chachapoly.h>
#define KEY32
#define IV12
#define PLAINTEXT128
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    mbedtls_chachapoly_context ctx;
    uint8_t tag_enc[16];
    uint8_t ciphertext[DATALEN];
    
    mbedtls_chachapoly_init(&ctx);

    mbedtls_chachapoly_setkey(&ctx, input);
    // starting encryption with no additionnal data
    mbedtls_chachapoly_starts(&ctx, iv, MBEDTLS_CHACHAPOLY_ENCRYPT);
    // encrypting 
    mbedtls_chachapoly_update(&ctx, DATALEN, plaintext, ciphertext);
    // finishing encryption and computing MAC
    mbedtls_chachapoly_finish(&ctx, tag_enc);
    
#ifdef DEBUG
    uint8_t dec_out[DATALEN] = { 0x00 };
    uint8_t tag_dec[16];
     
    mbedtls_chachapoly_starts(&ctx, iv, MBEDTLS_CHACHAPOLY_DECRYPT);
    mbedtls_chachapoly_update(&ctx, DATALEN, ciphertext, dec_out);
    mbedtls_chachapoly_finish(&ctx, tag_dec);

    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, DATALEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

	mbedtls_chachapoly_free(&ctx);

}

extern void InitTarget(uint8_t* input)
{}
