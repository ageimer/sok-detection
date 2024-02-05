#include <stdio.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#define RSA1024
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    RSA *skey = RSA_new();
    BIGNUM *e;

    e = BN_bin2bn(RSA_E, sizeof RSA_E, NULL);

    int ret = RSA_generate_key_ex(skey, NLEN*8, e, NULL);

#ifdef DEBUG
    printf("ret (1 on success): %d\n", ret);
#endif

    RSA_free(skey);
    
}

extern void InitTarget(uint8_t* input)
{}
