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

static BIGNUM fixed_key;
static EC_GROUP* group;

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
    ECDSA_SIG* sig;
    EC_KEY* skey;
    BIGNUM d = {(BN_ULONG*)data, 8, 8, 0, 9};

    ret = thrash_cache();
    
    skey = EC_KEY_new();

    // setting the key parameters
    EC_KEY_set_group(skey, group);
    EC_KEY_set_private_key(skey, &d);

    sig = ECDSA_do_sign(ECDSA_sha1, sizeof ECDSA_sha1, skey);

    EC_KEY_free(skey);
    ECDSA_SIG_free(sig);
   
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, fixed_key.d, c->chunk_size);
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
    
    BN_bin2bn(ECDSA_D, sizeof ECDSA_D, &fixed_key);

    // creating an EC_GROUP with P256 as a named curve, then setting its cofactor to 0
    EC_GROUP *p256 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT *generator = EC_GROUP_get0_generator(p256);
    const BIGNUM *order = EC_GROUP_get0_order(p256);
    BIGNUM *cofactor = BN_new();
    BN_zero(cofactor);
    EC_GROUP_set_generator(p256, generator, order, cofactor);     // setting the cofactor

    // exporting those curve parameters
    ECPARAMETERS *params = EC_GROUP_get_ecparameters(p256, NULL);
    // making a new EC_GROUP with explicit parameters
    group = EC_GROUP_new_from_ecparameters(params);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    BN_free(cofactor);
    EC_GROUP_free(group);
    EC_GROUP_free(p256);
    ECPARAMETERS_free(params);
 
    dudect_free(&ctx);
    return (int)state;
}
