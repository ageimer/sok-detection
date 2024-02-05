#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#define RSA1024
#define PKCS1_V15
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

#define KEYLEN (NLEN+ELEN+DLEN+PLEN+QLEN+DPLEN+DQLEN+QINVLEN)

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;

    ret = thrash_cache();

    RSA* skey = RSA_new();
    
    BIGNUM *n, *e, *d, *p, *q, *dp, *dq, *qinv;
    n = BN_bin2bn(data, NLEN, NULL);
    e = BN_bin2bn(data+=NLEN, ELEN, NULL);
    d = BN_bin2bn(data+=ELEN, DLEN, NULL);
    p = BN_bin2bn(data+=DLEN, PLEN, NULL);
    q = BN_bin2bn(data+=PLEN, QLEN, NULL);
    dp = BN_bin2bn(data+=QLEN, DPLEN, NULL);
    dq = BN_bin2bn(data+=DPLEN, DQLEN, NULL);
    qinv = BN_bin2bn(data+=DQLEN, QINVLEN, NULL);

    // setting the key parameters
    RSA_set0_key(skey, n, e, d);
    RSA_set0_factors(skey, p, q);
    RSA_set0_crt_params(skey, dp, dq, qinv);

    uint8_t dec_out[NLEN];
    RSA_private_decrypt(NLEN, data+=QINVLEN, dec_out, skey, RSA_PKCS1_PADDING);

    RSA_free(skey);
    
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {

    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t* idx = input_data + (size_t)i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(idx, RSA_N, NLEN);
            memcpy(idx+=NLEN, RSA_E, ELEN);
            memcpy(idx+=ELEN, RSA_D, DLEN);
            memcpy(idx+=DLEN, RSA_P, PLEN);
            memcpy(idx+=PLEN, RSA_Q, QLEN);
            memcpy(idx+=QLEN, RSA_DP, DPLEN);
            memcpy(idx+=DPLEN, RSA_DQ, DQLEN);
            memcpy(idx+=DQLEN, RSA_QINV, QINVLEN);
            memcpy(idx+=QINVLEN, ciphertext, NLEN);
        } else {
            RSA *skey = RSA_new();
            BIGNUM *e = BN_bin2bn(RSA_E, ELEN, NULL);
            BIGNUM *n, *d, *p, *q, *dp, *dq, *qinv;
            
            RSA_generate_key_ex(skey, 1024, e, NULL);
            RSA_get0_key(skey, &n, &e, &d);
            RSA_get0_factors(skey, &p, &q);
            RSA_get0_crt_params(skey, &dp, &dq, &qinv);

            BN_bn2bin(n, idx);
            BN_bn2bin(e, idx+=NLEN);
            BN_bn2bin(d, idx+=ELEN);
            BN_bn2bin(p, idx+=DLEN);
            BN_bn2bin(q, idx+=PLEN);
            BN_bn2bin(dp, idx+=QLEN);
            BN_bn2bin(dq, idx+=DPLEN);
            BN_bn2bin(qinv, idx+=DQLEN);
            
            RSA_public_encrypt(DATALEN, plaintext, idx+=QINVLEN, skey, RSA_PKCS1_PADDING);
            RSA_free(skey);
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
