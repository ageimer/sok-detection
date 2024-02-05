#include <stdio.h>
#include <string.h>
#include <mbedtls/aes.h>
#define KEY16
#define IV16
#define PLAINTEXT32
#include "../../common.h"

static uint8_t ciphertext[DATALEN];

int main() {
    mbedtls_aes_context ctx;

    mbedtls_aes_init(&ctx);
    
    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});

    mbedtls_aes_setkey_enc(&ctx, skey, KEYLEN*8);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, DATALEN, iv, plaintext, ciphertext);

#ifdef DEBUG
    uint8_t dec_out[DATALEN] = { 0x00 };
    uint8_t iv[IVLEN] = { 0x07 };
     
    mbedtls_aes_setkey_dec(&ctx, skey, KEYLEN*8 );
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, DATALEN, iv, ciphertext, dec_out);
    
    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, DATALEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

	mbedtls_aes_free(&ctx);

    return 0;
} 

