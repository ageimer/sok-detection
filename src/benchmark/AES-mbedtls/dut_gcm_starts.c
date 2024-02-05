#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define KEY16
#define IV12 
#define PLAINTEXT32 
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ciphertext[DATALEN];
    uint8_t ret;
    uint8_t tag[16];
    size_t outl;
    mbedtls_gcm_context ctx;

    ret = thrash_cache();
    
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, data, KEYLEN*8);
    mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, iv, IVLEN);
    mbedtls_gcm_update(&ctx, plaintext, DATALEN, ciphertext, DATALEN, &outl);
    mbedtls_gcm_finish(&ctx, ciphertext, DATALEN, &outl, tag, 16);

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

  /*
  Call dudect_main() until
   - returns something different than DUDECT_NO_LEAKAGE_EVIDENCE_YET, or
   - you spent too much time testing and give up
  Recommended that you wrap this program with timeout(2) if you don't
  have infinite time.
  For example this will run for 20 mins:
    $ timeout 1200 ./your-executable
  */
  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }
  dudect_free(&ctx);
  return (int)state;
}
