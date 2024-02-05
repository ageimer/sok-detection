#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#define VULNVALID
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

#define KEYLEN sizeof(mbedtls_mpi)

static mbedtls_entropy_context ent_ctx;
static mbedtls_ctr_drbg_context rng_ctx;
static mbedtls_mpi fixed_e, fixed_m;

uint8_t do_one_computation(uint8_t *data) {
    mbedtls_mpi r;
    uint8_t ret;

    mbedtls_mpi *m = (mbedtls_mpi*)data;
    mbedtls_mpi_init(&r);
    
    ret = thrash_cache();

    mbedtls_mpi_inv_mod(&r, &fixed_e, m);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(m);
    
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        mbedtls_mpi* m = (mbedtls_mpi*)(input_data + (size_t)i * c->chunk_size);
        mbedtls_mpi_init(m);

        if (classes[i] == 0) {
            mbedtls_mpi_copy(m, &fixed_m);
        } else {
            do {
                mbedtls_mpi_fill_random(m, sizeof lcm, mbedtls_ctr_drbg_random, &rng_ctx);
            } while (mbedtls_mpi_cmp_int(m, 1) != 0);
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

  mbedtls_mpi_init(&fixed_e);
  mbedtls_mpi_init(&fixed_m);

  mbedtls_mpi_read_binary(&fixed_e, E, sizeof E);
  mbedtls_mpi_read_binary(&fixed_m, lcm, sizeof lcm);

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }
  dudect_free(&ctx);
  return (int)state;
}
