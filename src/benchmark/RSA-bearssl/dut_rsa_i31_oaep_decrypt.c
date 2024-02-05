#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <bearssl_rsa.h>
#define RSA1024
#define OAEP
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

#define KEYLEN (PLEN+QLEN+DPLEN+DQLEN+QINVLEN)

uint8_t do_one_computation(uint8_t *data) {
    br_rsa_private_key skey = {
        8*NLEN,
        data, PLEN,
        data+=PLEN, QLEN,
        data+=QLEN, DPLEN,
        data+=DPLEN, DQLEN,
        data+=DQLEN, QINVLEN
    };
    uint8_t* cipher = data+=QINVLEN;
    uint8_t ret;

    ret = thrash_cache();

    size_t outl = NLEN;
    br_rsa_i31_oaep_decrypt(&br_sha1_vtable, NULL, 0, &skey, cipher, &outl);
    
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    char *seed = "rsa_decrypt";
    br_hmac_drbg_context rng_ctx;
    br_hmac_drbg_init(&rng_ctx, &br_sha1_vtable, seed, sizeof seed); 

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t* idx = input_data + (size_t)i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(idx, RSA_P, PLEN);
            memcpy(idx+=PLEN, RSA_Q, QLEN);
            memcpy(idx+=QLEN, RSA_DP, DPLEN);
            memcpy(idx+=DPLEN, RSA_DQ, DQLEN);
            memcpy(idx+=DQLEN, RSA_QINV, QINVLEN);
            memcpy(idx+=QINVLEN, ciphertext, NLEN);
        } else {
            br_rsa_private_key sk;
            br_rsa_public_key pk;
            uint8_t skbuf[KEYLEN];
            uint8_t pkbuf[BR_RSA_KBUF_PUB_SIZE(8*NLEN)];

            br_rsa_i31_keygen(&rng_ctx.vtable, &sk, skbuf, &pk, pkbuf, 1024, 65537);

            memcpy(idx, sk.p, PLEN);
            memcpy(idx+=PLEN, sk.q, QLEN);
            memcpy(idx+=QLEN, sk.dp, DPLEN);
            memcpy(idx+=DPLEN, sk.dq, DQLEN);
            memcpy(idx+=DQLEN, sk.iq, QINVLEN);
            
            br_rsa_i31_oaep_encrypt(&rng_ctx.vtable, &br_sha1_vtable, NULL, 0, &pk, idx+=QINVLEN, NLEN, plaintext, DATALEN);
        }
    }
}

int main() {

  dudect_config_t config = {
     .chunk_size = KEYLEN+NLEN,
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
