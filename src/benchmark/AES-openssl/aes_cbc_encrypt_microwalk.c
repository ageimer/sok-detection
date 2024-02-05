#include <stdio.h>
#include <stdint.h>
#include <openssl/aes.h>
#define KEY16
#define IV16
#define PLAINTEXT32
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    AES_KEY enc_key, dec_key;
    uint8_t iv[IVLEN] = { 0x07 };
    uint8_t ciphertext[DATALEN];

    AES_set_encrypt_key(input, KEYLEN*8, &enc_key);
    AES_cbc_encrypt(plaintext, ciphertext, (size_t) DATALEN, &enc_key, iv, 1);      

#ifdef DEBUG
    uint8_t dec_out[DATALEN];
    uint8_t iv_dec[IVLEN] = { 0x07 };

    AES_set_decrypt_key(input, KEYLEN*8, &dec_key);
    AES_cbc_encrypt(ciphertext, dec_out, (size_t) DATALEN, &dec_key, iv_dec, 0);      

    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, DATALEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

} 

extern void InitTarget(uint8_t* input)
{}
