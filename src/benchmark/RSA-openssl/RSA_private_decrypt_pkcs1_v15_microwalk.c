#include <stdio.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#define RSA1024
#define PKCS1_V15
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    RSA *skey = RSA_new();

    // converting the key parameters to OpenSSL bignums
    BIGNUM *n, *e, *d, *p, *q, *dp, *dq, *qinv;
    n = BN_bin2bn(input, NLEN, NULL);
    e = BN_bin2bn(RSA_E, ELEN, NULL);
    d = BN_bin2bn(input+=NLEN, DLEN, NULL);
    p = BN_bin2bn(input+=DLEN, PLEN, NULL);
    q = BN_bin2bn(input+=PLEN, QLEN, NULL);
    dp = BN_bin2bn(input+=QLEN, DPLEN, NULL);
    dq = BN_bin2bn(input+=DPLEN, DQLEN, NULL);
    qinv = BN_bin2bn(input+=DQLEN, QINVLEN, NULL);

    uint8_t* cipher = input+=QINVLEN;
 
    // setting the key parameters
    RSA_set0_key(skey, n, e, d);
    RSA_set0_factors(skey, p, q);
    RSA_set0_crt_params(skey, dp, dq, qinv);

    // PKCS#1 v1.5 decryption 
    uint8_t dec_out[NLEN];
    int ret = RSA_private_decrypt(NLEN, cipher, dec_out, skey, RSA_PKCS1_PADDING);

#ifdef DEBUG
    printf("ret = %d", ret);
    printf("\noriginal:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(cipher, NLEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

} 

extern void InitTarget(uint8_t* input)
{
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                        | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_NO_ADD_ALL_DIGESTS 
                        | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
 
}
