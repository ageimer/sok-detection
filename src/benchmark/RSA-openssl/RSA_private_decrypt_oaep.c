#include <stdio.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#define RSA1024
#define OAEP
#include "../../common.h"

#define sBN sizeof(BN_ULONG)                // size of OpenSSL's bignum limbs

int main() {
    // annotating secrets
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_P, PLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_Q, QLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_D, DLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_DP, DPLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_DQ, DQLEN);
    VALGRIND_MAKE_MEM_UNDEFINED(RSA_QINV, QINVLEN);
    abacus_make_symbolic(
        6,
        (void*[]){RSA_P, RSA_Q, RSA_D, RSA_DP, RSA_DQ, RSA_QINV},
        (uint32_t[]){PLEN, QLEN, DLEN, DPLEN, DQLEN, QINVLEN});

    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                        | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_NO_ADD_ALL_DIGESTS 
                        | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    EVP_add_digest(EVP_sha1());

    RSA *skey = RSA_new();

    // converting the key parameters to OpenSSL bignums
    BIGNUM *n, *e, *d, *p, *q, *dp, *dq, *qinv;
    n = BN_bin2bn(RSA_N, NLEN, NULL);
    e = BN_bin2bn(RSA_E, ELEN, NULL);
    d = BN_bin2bn(RSA_D, DLEN, NULL);
    p = BN_bin2bn(RSA_P, PLEN, NULL);
    q = BN_bin2bn(RSA_Q, QLEN, NULL);
    dp = BN_bin2bn(RSA_DP, DPLEN, NULL);
    dq = BN_bin2bn(RSA_DQ, DQLEN, NULL);
    qinv = BN_bin2bn(RSA_QINV, QINVLEN, NULL);

    // setting the key parameters
    RSA_set0_key(skey, n, e, d);
    RSA_set0_factors(skey, p, q);
    RSA_set0_crt_params(skey, dp, dq, qinv);

    // OAEP decryption 
    uint8_t dec_out[NLEN];
    int ret = RSA_private_decrypt(NLEN, ciphertext, dec_out, skey, RSA_PKCS1_OAEP_PADDING);

#ifdef DEBUG
    printf("ret = %d", ret);
    printf("\noriginal:\t");
    printhex(plaintext, DATALEN);
    printf("\nencrypted:\t");
    printhex(ciphertext, NLEN);
    printf("\ndecrypted:\t");
    printhex(dec_out, DATALEN);
    printf("\n");
#endif

    RSA_free(skey);
    
    return 0;
}
