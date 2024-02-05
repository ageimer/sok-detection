#include <openssl/bn.h>
#include <stdint.h>
#define VULNVALID
#include "../../common.h"

#define sBN sizeof(BN_ULONG)                // size of OpenSSL's bignum limbs

extern void RunTarget(uint8_t* input)
{
     // in rsa_gen.c the second argument of BN_gcd is the secret since it's a bignum holding p-1, the third argument is the public exponent

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *r, *a, *b;
    r = BN_new();
    a = BN_bin2bn(E, sizeof E, NULL);
    b = BN_bin2bn(input, sizeof P_minus_one, NULL);

    int ret = BN_gcd(r, a, b, ctx);
    
    #ifdef DEBUG
    printhex(r->d, r->dmax);
    printf("\nret (1 on success): %d\n", ret); // 1 on success
    #endif

    BN_free(b);
    BN_free(a);
    BN_free(r);
    BN_CTX_free(ctx);

}

extern void InitTarget(uint8_t* input)
{}
