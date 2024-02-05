#include "bearssl.h"
#include <stdint.h>
#include <stdio.h>
#define KEY16
#define IV16 
#define PLAINTEXT32 
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    uint8_t iv[IVLEN] = { 0x07 };

    br_aes_ct_cbcenc_keys ctx;

    br_aes_ct_cbcenc_init(&ctx, input, (size_t) KEYLEN); 

#ifdef DEBUG
    printf("original:\t");
    printhex(plaintext, DATALEN);
#endif
   
    br_aes_ct_cbcenc_run(&ctx, iv, plaintext, (size_t) DATALEN);

#ifdef DEBUG
    br_aes_ct_cbcdec_keys dec_ctx;
    uint8_t iv_dec[IVLEN] = { 0x07 };

    printf("\nencrypted:\t");
    printhex(plaintext, DATALEN);

    br_aes_ct_cbcdec_init(&dec_ctx, input, (size_t) KEYLEN); 
    br_aes_ct_cbcdec_run(&dec_ctx, iv_dec, plaintext, (size_t) DATALEN);

    printf("\ndecrypted:\t");
    printhex(plaintext, DATALEN);
    printf("\n");
#endif
   
}

extern void InitTarget(uint8_t* input)
{}
