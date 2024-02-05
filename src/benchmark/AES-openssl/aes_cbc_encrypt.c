#include <stdio.h>
#include <stdint.h>
#include <openssl/aes.h>
#define KEY16
#define IV16
#define PLAINTEXT32
#include "../../common.h"

static uint8_t ciphertext[DATALEN];

int main() {
    AES_KEY enc_key, dec_key;

    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});

    AES_set_encrypt_key(skey, KEYLEN*8, &enc_key);
    AES_cbc_encrypt(plaintext, ciphertext, (size_t) DATALEN, &enc_key, iv, 1);      

#ifdef DEBUG
    uint8_t dec_out[DATALEN];
    uint8_t iv[IVLEN] = { 0x07 };

    AES_set_decrypt_key(skey, KEYLEN*8, &dec_key);
    AES_cbc_encrypt(ciphertext, dec_out, (size_t) DATALEN, &dec_key, iv, 0);      

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

