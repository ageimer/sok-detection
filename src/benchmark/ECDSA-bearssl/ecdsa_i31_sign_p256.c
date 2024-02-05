#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bearssl_ec.h>
#define ECDSA_P256
#include "../../common.h"

int main() {
    VALGRIND_MAKE_MEM_UNDEFINED(ECDSA_D, sizeof ECDSA_D);
    abacus_make_symbolic(1, (void*[]){ECDSA_D}, (uint32_t[]){sizeof ECDSA_D});

    // copying the private key
    br_ec_private_key key = {
        BR_EC_secp256r1,
        ECDSA_D,
        sizeof ECDSA_D
    };
    
    uint8_t sig[64] = { 0 };

    // signature generation
    int ret_sign = br_ecdsa_i31_sign_raw(&br_ec_p256_m31, &br_sha1_vtable, ECDSA_sha1, &key, sig);
    
#ifdef DEBUG
    uint8_t kbuf[BR_EC_KBUF_PUB_MAX_SIZE] = {0};
    br_ec_public_key pk;
    br_ec_compute_pub(&br_ec_p256_m31, &pk, kbuf, &key);

    // signature verification
    int ret_vrfy = br_ecdsa_i31_vrfy_raw(&br_ec_p256_m31, ECDSA_sha1, br_sha1_SIZE, &pk, &sig, 64);

    printf("signature:\t");
    printhex(sig, ret_sign);
    printf("\nsign (64 on success): %d\t verify (1 on success): %d\n", ret_sign, ret_vrfy);
#endif

    return 0;
} 
