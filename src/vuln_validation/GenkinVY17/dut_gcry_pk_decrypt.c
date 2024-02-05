#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>
#define ED25519
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

static gcry_sexp_t fixed_data;

static const uint8_t point[] = {
    0x57, 0x11, 0x9f, 0xd0, 0xdd, 0x4e, 0x22, 0xd8, 0x86, 0x8e, 0x1c, 0x58, 0xc4,
    0x5c, 0x44, 0x04, 0x5b, 0xef, 0x83, 0x9c, 0x55, 0xb1, 0xd0, 0xb1, 0x24, 0x8c,
    0x50, 0xa3, 0xbc, 0x95, 0x9c, 0x5f
};

void printhex(uint8_t* buf, int len) {
    for(int i = 0; i < len; i++)
        printf("%X ",*(buf+i));
}

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    gcry_sexp_t s_sk = (gcry_sexp_t)(data[0] | (data[1]<<8) | (data[2]<<16) | (data[3]<<24));
    gcry_sexp_t s_plain;

    ret = thrash_cache();
    
    //uint8_t buffer[1024] = {0};
    //gcry_sexp_sprint(s_sk, GCRYSEXP_FMT_DEFAULT, buffer, 1024);
    //printf("%s", buffer);
    gcry_pk_decrypt(&s_plain, fixed_data, s_sk);

    gcry_sexp_release(s_sk);

    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            gcry_sexp_t fixed_key;
            gcry_sexp_build(&fixed_key, NULL,
                            "(private-key"
                            " (ecc"
                            "  (curve \"Curve25519\")"
                            "  (flags djb-tweak)"
                            "  (q %b)"
                            "  (d %b)))",
                            sizeof Ed25519_Q, Ed25519_Q,
                            sizeof Ed25519_D, Ed25519_D);
            memcpy(input_data + (size_t)i * c->chunk_size, &fixed_key, c->chunk_size);
        } else {
            gcry_sexp_t s_params, s_key;
            gcry_sexp_build(&s_params, NULL,
                            "(genkey"
                            " (ecdh"
                            "  (curve \"Curve25519\")"
                            "  (flags djb-tweak)))");
            gcry_pk_genkey(&s_key, s_params);
            memcpy(input_data + (size_t)i * c->chunk_size, &s_key, c->chunk_size);
        }
    }
}

int main() {

    dudect_config_t config = {
        .chunk_size = sizeof(gcry_sexp_t),
        .number_measurements = NUM_MEAS,
    };
    dudect_ctx_t ctx;

    dudect_init(&ctx, &config);

    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    // setting the fixed values
    gcry_sexp_build(&fixed_data, NULL,
                    "(enc-val"
                    " (ecdh"
                    "  (e %b)))",
                   sizeof point, point);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    dudect_free(&ctx);

    return (int)state;
}
