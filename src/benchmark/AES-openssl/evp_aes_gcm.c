#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#define KEY16
#define IV12
#define PLAINTEXT32
#include "../../common.h"

static uint8_t ciphertext[DATALEN];

int main() {
    EVP_CIPHER_CTX *ctx;
    uint8_t tag[16];

    VALGRIND_MAKE_MEM_UNDEFINED(skey, KEYLEN);
    abacus_make_symbolic(1, (void*[]){skey}, (uint32_t[]){KEYLEN});
    
    // Initializing OpenSSL with only AES loaded
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                        | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_NO_ADD_ALL_DIGESTS 
                        | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    EVP_add_cipher(EVP_aes_128_gcm());

    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);     // no padding needed

    // if modifying the IV length do it here
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, skey, iv);
    // if adding AAD data do it here
    int out_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, DATALEN);
    int tmp_len = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &tmp_len);
    out_len += tmp_len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

#ifdef DEBUG
    uint8_t dec_out[DATALEN];

    EVP_CIPHER_CTX_reset(ctx);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, skey, iv);
    out_len = 0;
    EVP_DecryptUpdate(ctx, dec_out, &out_len, ciphertext, DATALEN);
    tmp_len = 0;
    // tag check could be done here
    EVP_DecryptFinal_ex(ctx, dec_out+out_len, &tmp_len);
    out_len += tmp_len;

    printf("original:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, DATALEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

    EVP_CIPHER_CTX_free(ctx);
    
    return 0;
} 
