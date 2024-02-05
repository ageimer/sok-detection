#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/bignum.h>
#define ECDSA_P256
#include "../../common.h"

#define sMPI sizeof(mbedtls_mpi_uint)       // size of MbedTLS' bignum limbs

int main() {
    mbedtls_entropy_context ent_ctx;
    mbedtls_ctr_drbg_context rng_ctx;
    uint8_t* seed = "ecdsa_sign";
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;

    VALGRIND_MAKE_MEM_UNDEFINED(ECDSA_D, sizeof ECDSA_D);
    abacus_make_symbolic(1, (void*[]){ECDSA_D}, (uint32_t[]){sizeof ECDSA_D});
    
    // initializing the EC group used to P-256
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    // initializing the private key d
    mbedtls_mpi_init(&d);
    mbedtls_mpi_read_binary(&d, ECDSA_D, sizeof ECDSA_D);

    // PRNG initialization and seeding, required by MbedTLS for blinding
    mbedtls_entropy_init(&ent_ctx);
    mbedtls_ctr_drbg_init(&rng_ctx);
    mbedtls_ctr_drbg_seed(&rng_ctx, mbedtls_entropy_func, &ent_ctx, seed, strlen(seed));

    // signature generation
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret_sign = mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, ECDSA_sha1, sizeof ECDSA_sha1, MBEDTLS_MD_SHA1, mbedtls_ctr_drbg_random, &rng_ctx);
    
#ifdef DEBUG
    // retrieving the public key
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_read_binary(&grp, &Q, ECDSA_Q, sizeof ECDSA_Q);

    // signature verification
    int ret_vrfy = mbedtls_ecdsa_verify(&grp, ECDSA_sha1, sizeof ECDSA_sha1, &Q, &r, &s);

    uint8_t rbuf[32], sbuf[32];
    mbedtls_mpi_write_binary(&r, rbuf, sizeof rbuf);
    mbedtls_mpi_write_binary(&s, sbuf, sizeof sbuf);
    
    printf("R:\t");
    printhex(rbuf, sizeof rbuf);
    printf("\nS:\t");
    printhex(sbuf, sizeof sbuf);
    printf("\nsign (0 on success): %d\t verify (0 on success): %d\n", ret_sign, ret_vrfy); // sign: 0, vrfy: 0 on success

    mbedtls_ecp_point_free(&Q);
#endif

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_entropy_free(&ent_ctx);
    mbedtls_ctr_drbg_free(&rng_ctx);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);

    return 0;
} 
