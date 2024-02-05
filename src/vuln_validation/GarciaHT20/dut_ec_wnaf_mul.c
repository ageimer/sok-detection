#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#define ECDSA_P256
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

static EC_POINT* fixed_point;
static BIGNUM fixed_scalar;
static EC_GROUP* group;

// ec_wNAF_mul isn't public otherwise
extern int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar, size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx);

// Since OpenSSL 1.1.0, the BIGNUM struct is opaque, so we need this declaration
typedef struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
} BIGNUM;

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    BIGNUM scalar = {(BN_ULONG*)data, 8, 8, 0, 9};

    ret = thrash_cache();
    
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *r = EC_POINT_new(group); // point resulting from the multiplication
    const EC_POINT *points[1];
    const BIGNUM *scalars[1];

    points[0] = fixed_point;
    scalars[0] = &scalar;

    int ret_mul = ec_wNAF_mul(group, r, &scalar, 0, points, scalars, ctx);

    EC_POINT_free(r);
    BN_CTX_free(ctx);

    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, fixed_scalar.d, c->chunk_size);
        } else {
            EC_KEY* skey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            EC_KEY_generate_key(skey);

            BIGNUM* d = EC_KEY_get0_private_key(skey);
            memcpy(input_data + (size_t)i * c->chunk_size, d->d, c->chunk_size);

            EC_KEY_free(skey);
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

    // Setting the curve to P-256
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    // redefining the cofactor to be null, needed to bypass a redirection in ec_wNAF_mul
    fixed_point = EC_GROUP_get0_generator(group);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BIGNUM *cofactor = BN_new();
    BN_zero(cofactor);
    EC_GROUP_set_generator(group, fixed_point, order, cofactor);

    // setting the fixed values
    BN_bin2bn(ECDSA_D, sizeof ECDSA_D, &fixed_scalar);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    dudect_free(&ctx);
    BN_free(cofactor);
    EC_GROUP_free(group);
    return (int)state;
}
