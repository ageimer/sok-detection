#include <openssl/bn.h>
#include <stdint.h>
#define VULNVALID
#include "../../common.h"

#define sBN sizeof(BN_ULONG)                // size of OpenSSL's bignum limbs

int main() {
    // The exponent p is the secret here in the case of RSA keygen.
    // p would normally have the BN_FLG_CONSTTIME flag set and thus would use CT functions 
    // since here we're reproducing the usual missing flag vulnerability, we omit it
    // as such, the non-CT BN_mod_exp_mont code path should be taken
    VALGRIND_MAKE_MEM_UNDEFINED(exponent, sizeof exponent);
    abacus_make_symbolic(1, (void*[]){exponent}, (uint32_t[]){sizeof exponent});

    BN_CTX *ctx = BN_CTX_new(); // context used by BN_gcd for temporary variables

    BIGNUM *r, *a, *p, *m;
    r = BN_new();
    a = BN_bin2bn(base, sizeof base, NULL);
    p = BN_bin2bn(exponent, sizeof exponent, NULL);
    m = BN_bin2bn(P, sizeof P, NULL);

    int ret = BN_mod_exp_mont(r, a, p, m, ctx, NULL); 
    
    #ifdef DEBUG
    printhex(r->d, r->dmax);
    printf("\nret: %d\n", ret); // 1 on success
    #endif

    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(r);
    BN_CTX_free(ctx);
}
