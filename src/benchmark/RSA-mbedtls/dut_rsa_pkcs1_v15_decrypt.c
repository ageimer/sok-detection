#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#define RSA1024
#define PKCS1_V15
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

#define KEYLEN (NLEN+PLEN+QLEN+DLEN+ELEN)

static mbedtls_entropy_context ent_ctx;
static mbedtls_ctr_drbg_context rng_ctx;

uint8_t do_one_computation(uint8_t *data) {
    mbedtls_rsa_context rsa_ctx;
    uint8_t ret;

    ret = thrash_cache();

    mbedtls_rsa_init(&rsa_ctx);
    mbedtls_rsa_import_raw(&rsa_ctx,
                           data, NLEN,
                           data+=NLEN, PLEN,
                           data+=PLEN, QLEN,
                           data+=QLEN, DLEN,
                           data+=DLEN, ELEN);
    mbedtls_rsa_complete(&rsa_ctx); 

    uint8_t dec_out[NLEN] = { 0x00 };
    size_t outl;
    mbedtls_rsa_rsaes_pkcs1_v15_decrypt(&rsa_ctx, mbedtls_ctr_drbg_random, &rng_ctx, &outl, data+=ELEN, dec_out, NLEN);

    mbedtls_rsa_free(&rsa_ctx);
    
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t* idx = (input_data + (size_t)i * c->chunk_size);
        if (classes[i] == 0) {
            memcpy(idx, RSA_N, NLEN);
            memcpy(idx+=NLEN, RSA_P, PLEN);
            memcpy(idx+=PLEN, RSA_Q, QLEN);
            memcpy(idx+=QLEN, RSA_D, DLEN);
            memcpy(idx+=DLEN, RSA_E, ELEN);
            memcpy(idx+=ELEN, ciphertext, NLEN);
        } else {
            mbedtls_rsa_context rsa;
            mbedtls_rsa_init(&rsa);
            mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &rng_ctx, 1024, 65537);
            mbedtls_rsa_export_raw(&rsa,
                                   idx, NLEN,
                                   idx+=NLEN, PLEN,
                                   idx+=PLEN, QLEN,
                                   idx+=QLEN, DLEN,
                                   idx+=DLEN, ELEN);
            mbedtls_rsa_rsaes_pkcs1_v15_encrypt(&rsa, mbedtls_ctr_drbg_random, &rng_ctx, DATALEN, plaintext, idx+=ELEN);
            mbedtls_rsa_free(&rsa);
        }
    }
}

int main() {

  dudect_config_t config = {
     .chunk_size = KEYLEN + NLEN,
     .number_measurements = NUM_MEAS,
  };
  dudect_ctx_t ctx;

  dudect_init(&ctx, &config);

  uint8_t* seed = "rsa_decrypt";
  
  // PRNG initialization and seeding, required by MbedTLS for blinding
  mbedtls_entropy_init(&ent_ctx);
  mbedtls_ctr_drbg_init(&rng_ctx);
  mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &ent_ctx, seed, strlen(seed));

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }
  dudect_free(&ctx);
  return (int)state;
}
