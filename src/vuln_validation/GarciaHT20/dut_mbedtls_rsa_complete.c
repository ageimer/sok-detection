#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#define RSA1024
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

#define KEYLEN sizeof(mbedtls_rsa_context)

static mbedtls_entropy_context ent_ctx;
static mbedtls_ctr_drbg_context rng_ctx;
static mbedtls_rsa_context fixed_key;

uint8_t do_one_computation(uint8_t *data) {
    mbedtls_rsa_context *rsa_ctx = (mbedtls_rsa_context*)data;
    uint8_t ret;

    ret = thrash_cache();

    mbedtls_rsa_complete(rsa_ctx);

    mbedtls_rsa_free(rsa_ctx);
    
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        mbedtls_rsa_context* skey = (mbedtls_rsa_context*)(input_data + (size_t)i * c->chunk_size);
        mbedtls_rsa_init(skey, MBEDTLS_RSA_PKCS_V15, 0);
        if (classes[i] == 0) {
            mbedtls_rsa_copy(skey, &fixed_key);
        } else {
            mbedtls_rsa_context tmp_ctx;
            mbedtls_rsa_init(&tmp_ctx, MBEDTLS_RSA_PKCS_V15, 0);
            mbedtls_rsa_gen_key(&tmp_ctx, mbedtls_ctr_drbg_random, &rng_ctx, 1024, 65537);
            mbedtls_rsa_import(skey, &tmp_ctx.N, &tmp_ctx.P, &tmp_ctx.Q, NULL, &tmp_ctx.E);
            mbedtls_rsa_free(&tmp_ctx);
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

  uint8_t* seed = "rsa_decrypt";
  
  // PRNG initialization and seeding, required by MbedTLS for blinding
  mbedtls_entropy_init(&ent_ctx);
  mbedtls_ctr_drbg_init(&rng_ctx);
  mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &ent_ctx, seed, strlen(seed));

  mbedtls_rsa_init(&fixed_key, MBEDTLS_RSA_PKCS_V15, 0);

  mbedtls_rsa_import_raw( &fixed_key, RSA_N, sizeof RSA_N,
                          RSA_P, sizeof RSA_P,
                          RSA_Q, sizeof RSA_Q,
                          NULL, 0,
                          RSA_E, sizeof RSA_E );
  
  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }
  dudect_free(&ctx);
  return (int)state;
}
