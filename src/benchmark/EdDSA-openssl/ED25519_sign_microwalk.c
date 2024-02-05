#include <stdio.h>
#include <stdint.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#define ED25519
#include "../../common.h"

// this function isn't exposed by OpenSSL's API by default
extern int ossl_ed25519_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
                             const uint8_t public_key[32], const uint8_t private_key[32],
                             OSSL_LIB_CTX *libctx, const char *propq);

extern void RunTarget(uint8_t* input)
{
    uint8_t sig[64];
    uint8_t* t = "Ed25519";
    
    int ret_sign = ossl_ed25519_sign(sig, t, sizeof t, input+DLEN, input, NULL, NULL);
    
#ifdef DEBUG
    printf("sig:\t");
    printhex(sig, sizeof sig);
    printf("\nsign (1 on success): %d", ret_sign);
    printf("\n");
#endif

}

extern void InitTarget(uint8_t* input)
{
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                        | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_NO_ADD_ALL_DIGESTS 
                        | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    EVP_add_digest(EVP_sha512());
}
