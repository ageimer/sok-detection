#include <openssl/bn.h>
#include <stdint.h>
#define VULNVALID
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    // For montgomery setup, the modulus is secret during modular inverse operation
    // m would normally have the BN_FLG_CONSTTIME flag set and thus would use CT functions
    // since here we're reproducing the usual missing flag vulnerability, we omit it
    // as such, the non-CT BN_mod_inverse code path should be taken
 
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *r, *a, *m;
    r = BN_new();
    a = BN_bin2bn(mont_ctx_operand, sizeof mont_ctx_operand, NULL);
    m = BN_bin2bn(input, sizeof P, NULL);
 
    BIGNUM* ret = BN_mod_inverse(r, a, m, ctx);
    
    #ifdef DEBUG
    printhex(r->d, r->dmax);
    printf("\nret (not NULL on success): %p\n", ret); // should not be NULL
    #endif

    BN_free(m);
    BN_free(a);
    BN_free(r);
    BN_CTX_free(ctx);

}

extern void InitTarget(uint8_t* input)
{}
