#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#define VULNVALID
#include "../src/common.h"

//const static uint8_t mont_ctx_operand[] = {0x01, 0x00, 0x00, 0x00, 0x00};

static const uint8_t data[] = {
    0x12, 0x34, 0x98, 0x72, 0xcc, 0x7c, 0x52, 0x11, 0xe1, 0x7e, 0xd1, 0x23, 0x34,
    0xab, 0xd7, 0xa8, 0x6e, 0x0e, 0x2a, 0xf3, 0x95, 0x8e, 0x18, 0x7, 0x53, 0x50,
    0xca, 0xcc, 0x49, 0x16, 0x5b, 0x49, 0xe9, 0x0c, 0x1a, 0xb1, 0xaf, 0x5d, 0x14,
    0x89, 0x97, 0xe0, 0xc4, 0xaa, 0x2f, 0xad, 0x7b, 0xd, 0xda, 0x17, 0x2a, 0x8,
    0x91, 0x2a, 0xfe, 0x98, 0x55, 0x41, 0xff, 0xe8, 0xc6, 0x98, 0xb1, 0xbe
};


int main(int argc, void** argv) {

    uint8_t* output_type = argv[1];
    uint8_t* output_path = argv[2];

    uint8_t out[64];

    if (!strcmp(output_type, "GCD")) {    
        BIGNUM* rnd = BN_new();
        BN_rand(rnd, 64 * 8, -1, false);
        BN_bn2bin(rnd, out);
        BN_free(rnd);
        
    } else if (!strcmp(output_type, "MODINV")) {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM* rnd = BN_new();
        BIGNUM* mont = BN_new();
        BIGNUM *r = BN_new();
        
        BN_bin2bn(mont_ctx_operand, sizeof mont_ctx_operand, mont);
        // keep generating new inputs until finding one with an inverse, also must be odd
        do {
            BN_rand(rnd, 64 * 8, -1, true);
        } while (!BN_mod_inverse(r, mont, rnd, ctx));

        BN_bn2bin(rnd, out);
        
        BN_CTX_free(ctx);
        BN_free(rnd);
        BN_free(mont);
        BN_free(r);

    } else if (!strcmp(output_type, "MODEXP")) {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM* rnd = BN_new();
        BIGNUM *r = BN_new();
        
        // ensure the generated bignum is odd
        BN_rand(rnd, 64 * 8, -1, true);
        BN_bn2bin(rnd, out);
        
        BN_CTX_free(ctx);
        BN_free(rnd);
        BN_free(r);
    } else if (!strcmp(output_type, "LCM")) {
        BIGNUM* rnd = BN_new();
        
        BN_rand(rnd, sizeof lcm * 8, -1, false);

        BN_bn2bin(rnd, out);
        
        BN_free(rnd);
    }

    FILE *f = fopen(output_path, "wb");
    if (f == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    //fwrite(lcm, 1, 128, f);
    fwrite(data, 1, 64, f);

    fclose(f);
    
    return 0;
}
