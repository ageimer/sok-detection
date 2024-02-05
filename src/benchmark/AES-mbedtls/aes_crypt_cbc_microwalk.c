#include <stdio.h>
#include <string.h>
#include <mbedtls/aes.h>
#define KEY16
#define IV16
#define PLAINTEXT32
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    uint8_t iv[IVLEN] = { 0x07 };
    uint8_t ciphertext[DATALEN];
    mbedtls_aes_context ctx;

    mbedtls_aes_init(&ctx);
    
    mbedtls_aes_setkey_enc(&ctx, input, KEYLEN*8);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, DATALEN, iv, plaintext, ciphertext);

#ifdef DEBUG
    uint8_t dec_out[DATALEN] = { 0x00 };
    uint8_t iv_dec[IVLEN] = { 0x07 };
     
    mbedtls_aes_setkey_dec(&ctx, input, KEYLEN*8 );
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, DATALEN, iv_dec, ciphertext, dec_out);
    
    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, DATALEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

	mbedtls_aes_free(&ctx);

} 

extern void InitTarget(uint8_t* input)
{}

