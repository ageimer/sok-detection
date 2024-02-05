#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <stdint.h>
#define ECDSA_P256
#include "../../common.h"

// ec_wNAF_mul isn't public otherwise
extern int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar, size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx);

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
    // annotating secrets
    VALGRIND_MAKE_MEM_UNDEFINED(ECDSA_D, sizeof ECDSA_D);
    abacus_make_symbolic(2, (void*[]){ECDSA_D}, (uint32_t[]){sizeof ECDSA_D});

    BN_CTX *ctx = BN_CTX_new();

    // Setting the curve to P-256
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    // redefining the cofactor to be null, needed to bypass a redirection in ec_wNAF_mul
    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BIGNUM *cofactor = BN_new();
    BN_zero(cofactor);
    EC_GROUP_set_generator(group, generator, order, cofactor);
    
    EC_POINT *r = EC_POINT_new(group); // point resulting from the multiplication
    BIGNUM *k;
    const EC_POINT *points[1];
    const BIGNUM *scalars[1];

    k = BN_bin2bn(ECDSA_D, sizeof ECDSA_D, NULL);
    points[0] = generator;
    scalars[0] = k;

    int ret = ec_wNAF_mul(group, r, k, 0, points, scalars, ctx);

    #ifdef DEBUG
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, r, x, y, ctx);
    printhex(x->d, x->dmax);
    printf("\n");
    printhex(y->d, y->dmax);
    printf("\nret (1 on success):%d\n", ret);
    #endif

    BN_free(k);
    EC_POINT_free(r);
    BN_free(cofactor);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
}
