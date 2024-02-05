#include "bearssl.h"
#include <stdint.h>
#include <stdio.h>
#define KEY16
#define IV16 
#define PLAINTEXT32 
#include "../../common.h"

int main() {  
    br_aes_big_cbcenc_keys ctx;

    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});

    br_aes_big_cbcenc_init(&ctx, skey, (size_t) KEYLEN); 

#ifdef DEBUG
    printf("original:\t");
    printhex(plaintext, DATALEN);
#endif
   
    br_aes_big_cbcenc_run(&ctx, iv, plaintext, (size_t) DATALEN);

#ifdef DEBUG
    br_aes_big_cbcdec_keys dec_ctx;
    uint8_t iv[IVLEN] = { 0x07 };

    printf("\nencrypted:\t");
    printhex(plaintext, DATALEN);

    br_aes_big_cbcdec_init(&dec_ctx, skey, (size_t) KEYLEN); 
    br_aes_big_cbcdec_run(&dec_ctx, iv, plaintext, (size_t) DATALEN);

    printf("\ndecrypted:\t");
    printhex(plaintext, DATALEN);
    printf("\n");
#endif
    
    return 0;
}
