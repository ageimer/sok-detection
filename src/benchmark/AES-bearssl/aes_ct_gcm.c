#include "bearssl.h"
#include <stdint.h>
#include <stdio.h>
#define KEY16
#define IV12 
#define PLAINTEXT32 
#include "../../common.h"

int main() {  
    br_aes_ct_ctr_keys ctx;
    br_gcm_context gcm_ctx;
    uint8_t tag[16];
    
    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});

    br_aes_ct_ctr_init(&ctx, skey, (size_t) KEYLEN);
    br_gcm_init(&gcm_ctx, &ctx.vtable, br_ghash_ctmul);
    br_gcm_reset(&gcm_ctx, iv, (size_t) IVLEN);
    
#ifdef DEBUG
    printf("original:\t");
    printhex(plaintext, DATALEN);
#endif
   
    br_gcm_flip(&gcm_ctx); // finish AAD injection, start encryption
    br_gcm_run(&gcm_ctx, 1, plaintext, (size_t) DATALEN);
    br_gcm_get_tag(&gcm_ctx, tag);
 
#ifdef DEBUG
    uint8_t iv[IVLEN] = { 0x07 };

    printf("\nencrypted:\t");
    printhex(plaintext, DATALEN);

    br_gcm_reset(&gcm_ctx, iv, (size_t) IVLEN);
    br_gcm_run(&gcm_ctx, 0, plaintext, (size_t) DATALEN); 

    printf("\ndecrypted:\t");
    printhex(plaintext, DATALEN);
    printf("\n");
#endif
    
    return 0;
}
