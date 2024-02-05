#include <mbedtls/chachapoly.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define KEY32
#define IV12
#define PLAINTEXT128 
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ciphertext[DATALEN];
    uint8_t ret;
    mbedtls_chachapoly_context ctx;
    uint8_t tag_enc[16];
    
    ret = thrash_cache();

    mbedtls_chachapoly_init(&ctx);

    mbedtls_chachapoly_setkey(&ctx, data);
    mbedtls_chachapoly_starts(&ctx, iv, MBEDTLS_CHACHAPOLY_ENCRYPT);
    mbedtls_chachapoly_update(&ctx, DATALEN, plaintext, ciphertext);
    mbedtls_chachapoly_finish(&ctx, tag_enc);
    
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
