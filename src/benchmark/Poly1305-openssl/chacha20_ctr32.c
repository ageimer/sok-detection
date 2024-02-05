#include <stdio.h>
#include <stdint.h>
#define KEY32
#define IV16            // from chacha.h: ChaCha20_ctr32 takes a 16 bytes counter
#define PLAINTEXT128
#include "../../common.h"

// this function isn't exposed by OpenSSL's API by default
void ChaCha20_ctr32(unsigned char *out, const unsigned char *inp,
                    size_t len, const unsigned int key[8],
                    const unsigned int counter[4]);

static uint8_t ciphertext[DATALEN];

int main() {
    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});

    ChaCha20_ctr32(ciphertext, plaintext, DATALEN, skey, iv);
    
#ifdef DEBUG
    uint8_t dec_out[DATALEN];

    ChaCha20_ctr32(dec_out, ciphertext, DATALEN, skey, iv);

    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, DATALEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

    return 0;
} 

