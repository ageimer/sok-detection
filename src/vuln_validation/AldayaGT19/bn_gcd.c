#include <openssl/bn.h>
#include <stdint.h>
#define VULNVALID
#include "../../common.h"

#define sBN sizeof(BN_ULONG)                // size of OpenSSL's bignum limbs

int main() {
     // in rsa_gen.c the second argument of BN_gcd is the secret since it's a bignum holding p-1, the third argument is the public exponent

    VALGRIND_MAKE_MEM_UNDEFINED(P_minus_one, sizeof P_minus_one);
    abacus_make_symbolic(1, (void*[]){P_minus_one}, (uint32_t[]){sizeof P_minus_one});
    
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *r, *a, *b;
    r = BN_new();
    a = BN_bin2bn(E, sizeof E, NULL);
    b = BN_bin2bn(P_minus_one, sizeof P_minus_one, NULL);

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
