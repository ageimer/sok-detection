#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#define VULNVALID
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

static BIGNUM fixed_operand, fixed_p;

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    BIGNUM p = {(BN_ULONG*)data, 8, 8, 0, 9};

    ret = thrash_cache();
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new();
    BIGNUM *ret_bn = BN_mod_inverse(r, &fixed_operand, &p, ctx);

    BN_CTX_free(ctx);
    BN_free(r);

    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, fixed_p.d, c->chunk_size);
        } else {
            BN_CTX *ctx = BN_CTX_new();
            BIGNUM* rnd = BN_new();
            BIGNUM *r = BN_new();

            // keep generating new inputs until finding one with an inverse, also must be odd
            do {
                BN_rand(rnd, c->chunk_size * 8, -1, true);
            } while (!BN_mod_inverse(r, &fixed_operand, rnd, ctx));

            memcpy(input_data + (size_t)i * c->chunk_size, rnd->d, c->chunk_size);

            BN_CTX_free(ctx);
            BN_free(rnd);
            BN_free(r);
        }
    }
}

int main() {

    dudect_config_t config = {
        .chunk_size = sizeof P,
        .number_measurements = NUM_MEAS,
    };
    dudect_ctx_t ctx;

    dudect_init(&ctx, &config);

    // setting the fixed values
    BN_bin2bn(mont_ctx_operand, sizeof mont_ctx_operand, &fixed_operand);
    BN_bin2bn(P, sizeof P, &fixed_p);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    dudect_free(&ctx);

    return (int)state;
}
