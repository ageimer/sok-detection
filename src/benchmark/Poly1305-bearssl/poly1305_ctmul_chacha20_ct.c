#include "bearssl.h"
#include <stdint.h>
#include <stdio.h>
#define KEY32
#define IV12
#define PLAINTEXT128 // 2*block_size
#include "../../common.h"

int main() {
    uint8_t aad[1] = { 0x42 };
    uint8_t tag_enc[16];
    
    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});

#ifdef DEBUG
    printf("\noriginal:\t");
    printhex(plaintext, DATALEN);
#endif

    br_poly1305_ctmul_run(skey, iv, plaintext, DATALEN, aad, 0, tag_enc, br_chacha20_ct_run, 1);

#ifdef DEBUG
    uint8_t iv[IVLEN] = { 0x07 };
    uint8_t tag_dec[16];

    printf("\nencrypted:\t");
    printhex(plaintext, DATALEN);

    br_poly1305_ctmul_run(skey, iv, plaintext, DATALEN, aad, 0, tag_dec, br_chacha20_ct_run, 0);

    printf("\ndecrypted:\t");
    printhex(plaintext, DATALEN);
    printf("\n");
#endif
    
    return 0;
}
