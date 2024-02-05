#include <stdio.h>
#include <stdint.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#define ECDSA_P256
#include "../../common.h"

// Since OpenSSL 1.1.0, the BIGNUM struct is opaque, so we need this declaration
typedef struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
} BIGNUM;

int main() {
    // normally we'd annotate the secret here, but for this vulnerability,
    // the secret is the nonce k generated within ECDSA_do_sign

    EC_KEY* skey;
    ECDSA_SIG* sig;

    skey = EC_KEY_new();

    // creating an EC_GROUP with P256 as a named curve, then setting its cofactor to 0
    EC_GROUP *p256 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT *generator = EC_GROUP_get0_generator(p256);
    const BIGNUM *order = EC_GROUP_get0_order(p256);
    BIGNUM *cofactor = BN_new();
    BN_zero(cofactor);
    EC_GROUP_set_generator(p256, generator, order, cofactor);

    // exporting those curve parameters, making a new EC_GROUP with explicit parameters
    ECPARAMETERS *params = EC_GROUP_get_ecparameters(p256, NULL);
    EC_GROUP* group = EC_GROUP_new_from_ecparameters(params);

    // converting the key parameter to OpenSSL bignum
    BIGNUM *d;
    d = BN_bin2bn(ECDSA_D, sizeof ECDSA_D, NULL);

    // setting the key parameters
    EC_KEY_set_group(skey, group);
    EC_KEY_set_private_key(skey, d);
    // OpenSSL duplicates the bignum when setting the key so we need to retrieve the new one
    BIGNUM *priv_key = EC_KEY_get0_private_key(skey);

    // ECDSA signature 
    sig = ECDSA_do_sign(ECDSA_sha1, sizeof ECDSA_sha1, skey);

#ifdef DEBUG
    // retrieving and setting the public key
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_oct2point(group, Q, ECDSA_Q, sizeof ECDSA_Q, NULL);
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
#endif

    EC_KEY_free(skey);
    ECDSA_SIG_free(sig);
    BN_free(d);
    BN_free(cofactor);
    EC_GROUP_free(group);
    EC_GROUP_free(p256);
    ECPARAMETERS_free(params);

    return 0;
}
