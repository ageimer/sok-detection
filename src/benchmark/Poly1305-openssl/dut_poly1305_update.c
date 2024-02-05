#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define KEY32
#define PLAINTEXT128 
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
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

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    POLY1305 ctx;
    uint8_t mac[16];

    ret = thrash_cache();

    Poly1305_Init(&ctx, data);
    Poly1305_Update(&ctx, plaintext, DATALEN);
    Poly1305_Final(&ctx, mac);
 
    ret ^= mac[0];
    /* return some computation output to try to tame a clever optimizing compiler */
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(input_data, c->number_measurements * c->chunk_size);
        
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memcpy(input_data + (size_t)i * c->chunk_size, skey, c->chunk_size);
        } else {
            // leave random
        }
    }
}

int main() {

  dudect_config_t config = {
     .chunk_size = KEYLEN,
     .number_measurements = NUM_MEAS,
  };
  dudect_ctx_t ctx;

  dudect_init(&ctx, &config);

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }
  dudect_free(&ctx);
  return (int)state;
}
