#include <stdio.h>
#include <stdint.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#define KEY16
#define IV12
#define PLAINTEXT32
#include "../../common.h"

static uint8_t ciphertext[DATALEN];

int main() {
    mbedtls_gcm_context ctx;
    uint8_t tag[16];
    size_t outl;
    
    mbedtls_gcm_init(&ctx);

    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});

    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, skey, KEYLEN*8);
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

    return 0;
} 
