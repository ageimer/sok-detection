#include <stdio.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#define RSA1024
#include "../../common.h"

#define sBN sizeof(BN_ULONG)                // size of OpenSSL's bignum limbs

int main() {
    RSA *skey = RSA_new();
    BIGNUM *e;

    e = BN_bin2bn(RSA_E, sizeof RSA_E, NULL);

    // normally we'd annotate the secret here, but for this vulnerability,
    // the secrets are the two primes generated within RSA_generate_key_ex
    
    int ret = RSA_generate_key_ex(skey, NLEN*8, e, NULL);

#ifdef DEBUG
    printf("ret (1 on success): %d\n", ret);
#endif

    RSA_free(skey);
    
    return 0;
} 

