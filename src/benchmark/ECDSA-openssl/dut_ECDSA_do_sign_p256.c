#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#define ECDSA_P256
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

// Since OpenSSL 1.1.0, the BIGNUM struct is opaque, so we need this declaration
uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    ECDSA_SIG *sig;
    EC_KEY *skey;

    ret = thrash_cache();

    BIGNUM *d = BN_bin2bn(data, sizeof ECDSA_D, NULL);
    skey = EC_KEY_new_by_curve_name(415);
    EC_KEY_set_private_key(skey, d);
    
    sig = ECDSA_do_sign(ECDSA_sha1, sizeof ECDSA_sha1, skey);

    BN_free(d);
    EC_KEY_free(skey);
    ECDSA_SIG_free(sig);
    
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, ECDSA_D, c->chunk_size);
        } else {
            EC_KEY* skey = EC_KEY_new_by_curve_name(415);
            EC_KEY_generate_key(skey);

            uint8_t buf[c->chunk_size];
            BIGNUM* d = EC_KEY_get0_private_key(skey);
            BN_bn2bin(d, buf);
            
            memcpy(input_data + (size_t)i * c->chunk_size, buf, c->chunk_size);

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
    
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    dudect_free(&ctx);
    return (int)state;
}
