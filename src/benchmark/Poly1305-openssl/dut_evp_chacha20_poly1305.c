#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define KEY32
#define IV12
#define PLAINTEXT128 
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

static EVP_CIPHER_CTX *evp_ctx;

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ciphertext[DATALEN];
    uint8_t key[KEYLEN];
    uint8_t ret;
    uint8_t tag[16];

    ret = thrash_cache();

    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);     // no padding needed
    EVP_EncryptInit_ex(evp_ctx, EVP_chacha20_poly1305(), NULL, data, iv);
    int out_len = 0;
    EVP_EncryptUpdate(evp_ctx, ciphertext, &out_len, plaintext, DATALEN);
    int tmp_len = 0;
    EVP_EncryptFinal_ex(evp_ctx, ciphertext + out_len, &tmp_len);
    out_len += tmp_len;
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_reset(evp_ctx);

    ret ^= ciphertext[0];
    /* return some computation output to try to tame a clever optimizing compiler */
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(input_data, c->number_measurements * c->chunk_size);
        
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, skey, c->chunk_size);
        } else {
            // leave random
        }
    }
}

int main() {

    dudect_config_t config = {
        .chunk_size = KEYLEN,
        .number_measurements = NUM_MEAS,
    };
    dudect_ctx_t ctx;

    dudect_init(&ctx, &config);
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                        | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_NO_ADD_ALL_DIGESTS 
                        | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    EVP_add_cipher(EVP_chacha20_poly1305());

    evp_ctx = EVP_CIPHER_CTX_new();

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }
    dudect_free(&ctx);
    return (int)state;
}
