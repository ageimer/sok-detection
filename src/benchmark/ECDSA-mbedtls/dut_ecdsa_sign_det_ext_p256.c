#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/bignum.h>
#define ECDSA_P256
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

static mbedtls_entropy_context ent_ctx;
static mbedtls_ctr_drbg_context rng_ctx;
static mbedtls_ecp_group grp;

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    mbedtls_mpi r, s, d;
    
    ret = thrash_cache();

    mbedtls_mpi_init(&d);
    mbedtls_mpi_read_binary(&d, data, sizeof ECDSA_D);

    // signature generation
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, ECDSA_sha1, sizeof ECDSA_sha1, MBEDTLS_MD_SHA1, mbedtls_ctr_drbg_random, &rng_ctx);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&d);
    
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, ECDSA_D, sizeof ECDSA_D);
        } else {
            mbedtls_mpi d;
            uint8_t buf[c->chunk_size];
            mbedtls_mpi_init(&d);

            mbedtls_ecp_gen_privkey(&grp, &d, mbedtls_ctr_drbg_random, &rng_ctx);
            mbedtls_mpi_write_binary(&d, buf, c->chunk_size);
            memcpy(input_data + (size_t)i * c->chunk_size, buf, c->chunk_size);

            mbedtls_mpi_free(&d);
        }
    }
}

int main() {

    dudect_config_t config = {
        .chunk_size = sizeof ECDSA_D,
        .number_measurements = NUM_MEAS,
    };
    dudect_ctx_t ctx;

    dudect_init(&ctx, &config);
    
    uint8_t* seed = "ecdsa_sign";

    // initializing the EC group used to P-256
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    // PRNG initialization and seeding, required by MbedTLS for blinding
    mbedtls_entropy_init(&ent_ctx);
    mbedtls_ctr_drbg_init(&rng_ctx);
    mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &ent_ctx, seed, strlen(seed));

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    mbedtls_entropy_free(&ent_ctx);
    mbedtls_ctr_drbg_free(&rng_ctx);
    mbedtls_ecp_group_free(&grp);
   
    dudect_free(&ctx);
    return (int)state;
}
