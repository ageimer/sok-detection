#include <stdio.h>
#include <stdint.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#define ECDSA_P256
#include "../../common.h"

#define sBN sizeof(BN_ULONG)                // size of OpenSSL's bignum limbs

// Since OpenSSL 1.1.0, the BIGNUM struct is opaque, so we need this declaration
typedef struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
} BIGNUM;

extern void RunTarget(uint8_t* input)
{
    EC_KEY* skey;
    ECDSA_SIG* sig;

    // 415 => ID for P256 in OpenSSL
    // see: https://github.com/openssl/openssl/blob/master/include/openssl/obj_mac.h
    skey = EC_KEY_new_by_curve_name(415);

    // converting the key parameters to OpenSSL bignums
    BIGNUM *d;
    d = BN_bin2bn(input, DLEN, NULL);

    // setting the key parameters
    EC_KEY_set_private_key(skey, d);

    // OAEP signature generation 
    sig = ECDSA_do_sign(ECDSA_sha1, sizeof ECDSA_sha1, skey);

#ifdef DEBUG
    // retrieving and setting the public key
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(415);
    EC_POINT *Q = EC_POINT_new(grp);
    EC_POINT_oct2point(grp, Q, input+DLEN, QLEN, NULL);
    EC_KEY_set_public_key(skey, Q);

    // signature verification
    int ret_vrfy = ECDSA_do_verify(ECDSA_sha1, sizeof ECDSA_sha1, sig, skey);

    uint8_t rbuf[32], sbuf[32];
    BN_bn2bin(ECDSA_SIG_get0_r(sig), rbuf);
    BN_bn2bin(ECDSA_SIG_get0_s(sig), sbuf);
    
    printf("R:\t");
    printhex(rbuf, sizeof rbuf);
    printf("\nS:\t");
    printhex(sbuf, sizeof sbuf);
    printf("\nverify (1 on success): %d\n", ret_vrfy); // vrfy: 1 on success

    EC_POINT_free(Q);
    EC_GROUP_free(grp);
#endif

    EC_KEY_free(skey);
    ECDSA_SIG_free(sig);
    BN_free(d);
}

extern void InitTarget(uint8_t* input)
{
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                        | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_NO_ADD_ALL_DIGESTS 
                        | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
 
}
