#include <bearssl_ec.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define ECDSA_P256
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

#define KEYLEN sizeof(ECDSA_D)

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    uint8_t sig[64] = { 0 };

    br_ec_private_key key = {
        BR_EC_secp256r1,
        data,
        KEYLEN
    };
    
    ret = thrash_cache();

    int ret_sign = br_ecdsa_i31_sign_raw(&br_ec_p256_m31, &br_sha1_vtable, ECDSA_sha1, &key, sig);

    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    char *seed = "ecdsa_sign";
    br_hmac_drbg_context rng_ctx;
    br_hmac_drbg_init(&rng_ctx, &br_sha1_vtable, seed, sizeof seed); 
        
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, ECDSA_D, c->chunk_size);
        } else {
            int ret = br_ec_keygen(&rng_ctx.vtable, &br_ec_p256_m31, NULL, input_data + (size_t)i * c->chunk_size, BR_EC_secp256r1);
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
