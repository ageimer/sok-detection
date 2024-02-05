#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#define KEY32
#define PLAINTEXT128
#include "../../common.h"

// these functions are part of OpenSSL's internal API and aren't exposed by default
#define POLY1305_BLOCK_SIZE  16

typedef struct poly1305_context POLY1305;

typedef void (*poly1305_blocks_f) (void *ctx, const unsigned char *inp,
                                   size_t len, unsigned int padbit);
typedef void (*poly1305_emit_f) (void *ctx, unsigned char mac[16],
                                 const unsigned int nonce[4]);

struct poly1305_context {
    double opaque[24];  /* large enough to hold internal state, declared
                         * 'double' to ensure at least 64-bit invariant
                         * alignment across all platforms and
                         * configurations */
    unsigned int nonce[4];
    unsigned char data[POLY1305_BLOCK_SIZE];
    size_t num;
    struct {
        poly1305_blocks_f blocks;
        poly1305_emit_f emit;
    } func;
};

size_t Poly1305_ctx_size(void);
void Poly1305_Init(POLY1305 *ctx, const unsigned char key[32]);
void Poly1305_Update(POLY1305 *ctx, const unsigned char *inp, size_t len);
void Poly1305_Final(POLY1305 *ctx, unsigned char mac[16]);

extern void RunTarget(uint8_t* input)
{
    POLY1305 ctx;
    uint8_t mac[16];
    uint8_t ciphertext[DATALEN];
    
    Poly1305_Init(&ctx, input);
    Poly1305_Update(&ctx, plaintext, DATALEN);
    Poly1305_Final(&ctx, mac);
    
#ifdef DEBUG
    printf("MAC:\t");
    printhex(mac, 16);
    printf("\n");
#endif

}


extern void InitTarget(uint8_t* input)
{
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                        | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                        | OPENSSL_INIT_NO_ADD_ALL_DIGESTS 
                        | OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
}
