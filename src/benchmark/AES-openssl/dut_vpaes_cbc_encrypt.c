#include <openssl/aes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define KEY16
#define IV16
#define PLAINTEXT32 
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

// these functions aren't exposed by the API
extern int vpaes_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
void vpaes_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ciphertext[DATALEN];
    uint8_t ret;
    AES_KEY enc_key;

    ret = thrash_cache();
    
    vpaes_set_encrypt_key(data, KEYLEN*8, &enc_key);
    vpaes_cbc_encrypt(plaintext, ciphertext, (size_t) DATALEN, &enc_key, iv, 1);      

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

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }
  dudect_free(&ctx);
  return (int)state;
}
