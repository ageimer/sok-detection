#include <stdio.h>
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#define KEY16
#define IV16
#define PLAINTEXT32
#include "../../common.h"

// these functions aren't exposed by the API
extern int vpaes_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
extern int vpaes_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
void vpaes_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

static uint8_t ciphertext[DATALEN];

int main() {
    AES_KEY enc_key, dec_key;

    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                        | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_NO_ADD_ALL_DIGESTS 
                        | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
   
    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});

    vpaes_set_encrypt_key(skey, KEYLEN*8, &enc_key);
    vpaes_cbc_encrypt(plaintext, ciphertext, (size_t) DATALEN, &enc_key, iv, 1);      

#ifdef DEBUG
    uint8_t dec_out[DATALEN];
    uint8_t iv[IVLEN] = { 0x07 };
    
    vpaes_set_decrypt_key(skey, KEYLEN*8, &dec_key);
    vpaes_cbc_encrypt(ciphertext, dec_out, (size_t) DATALEN, &dec_key, iv, 0);      

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
