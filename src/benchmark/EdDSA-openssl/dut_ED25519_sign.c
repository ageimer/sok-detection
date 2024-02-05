#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>     // OSSL_PKEY_PARAM_PRIV_KEY
#define ED25519
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

#define KEYLEN sizeof(Ed25519_D)
static EVP_PKEY_CTX *key_ctx;

// this function isn't exposed by OpenSSL's API by default
extern int ossl_ed25519_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
                             const uint8_t public_key[32], const uint8_t private_key[32],
                             OSSL_LIB_CTX *libctx, const char *propq);

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    uint8_t sig[64];
    uint8_t* t = "Ed25519";

    ret = thrash_cache();

    ossl_ed25519_sign(sig, t, sizeof t, data + KEYLEN, data, NULL, NULL);

    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, Ed25519_D, KEYLEN);
            memcpy(input_data + (size_t)i * c->chunk_size + KEYLEN, Ed25519_Q, KEYLEN);
        } else {
            EVP_PKEY *pkey = NULL;
            EVP_PKEY_keygen(key_ctx, &pkey);
            
            size_t out_len = 0;
            EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, input_data + (size_t)i * c->chunk_size, KEYLEN, &out_len);
            EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, input_data + (size_t)i * c->chunk_size + KEYLEN, KEYLEN, &out_len);

            EVP_PKEY_free(pkey);
        }
    }
}

int main() {

    dudect_config_t config = {
        .chunk_size = 2*KEYLEN,  // ossl_ed25519_sign also needs the public key
        .number_measurements = NUM_MEAS,
    };
    dudect_ctx_t ctx;

    dudect_init(&ctx, &config);
    
    key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(key_ctx);
        
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    EVP_PKEY_CTX_free(key_ctx);
    
    dudect_free(&ctx);
    return (int)state;
}
