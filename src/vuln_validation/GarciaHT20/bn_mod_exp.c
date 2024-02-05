#include <openssl/bn.h>
#include <stdint.h>
#define RSA1024
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
    BN_CTX *ctx = BN_CTX_new(); 
    
    BIGNUM *r, *a, *p, *m;
    r = BN_new();
    a = BN_bin2bn(RSA_E, sizeof RSA_E, NULL);
    p = BN_bin2bn(RSA_D, sizeof RSA_D, NULL);
    m = BN_bin2bn(RSA_P, sizeof RSA_P, NULL);

    // The exponent p is the secret here in the case of DSA key handling.
    // p would normally have the BN_FLG_CONSTTIME flag set and thus would use CT functions 
    // since here we're reproducing the usual missing flag vulnerability, we omit it
    // as such, the non-CT BN_mod_exp code path shoudl be taken
    VALGRIND_MAKE_MEM_UNDEFINED(p->d, p->top*sBN);
    abacus_make_symbolic(1, (void*[]){p->d}, (uint32_t[]){p->top*sBN});

    int ret = BN_mod_exp(r, a, p, m, ctx);
    
    #ifdef DEBUG
    printhex(r->d, r->dmax);
    printf("\nret (1 on success): %d\n", ret); // 1 on success
    #endif

    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(r);
    BN_CTX_free(ctx);
}
