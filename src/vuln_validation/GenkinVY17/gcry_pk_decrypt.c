#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#define ED25519
#include "../../common.h"

// order 4 element, see: https://github.com/gpg/libgcrypt/commit/bf76acbf0da6b0f245e491bec12c0f0a1b5be7c9
static const uint8_t data[] = {
    0x57, 0x11, 0x9f, 0xd0, 0xdd, 0x4e, 0x22, 0xd8, 0x86, 0x8e, 0x1c, 0x58, 0xc4,
    0x5c, 0x44, 0x04, 0x5b, 0xef, 0x83, 0x9c, 0x55, 0xb1, 0xd0, 0xb1, 0x24, 0x8c,
    0x50, 0xa3, 0xbc, 0x95, 0x9c, 0x5f
};

int main_body () {
    gcry_sexp_t s_sk, s_data, s_plain;
    gcry_error_t ret;

    //gcry_mpi_scan(&d, GCRYMPI_FMT_USG, Ed25519_D, sizeof Ed25519_D, &res);
    gcry_sexp_build(&s_sk, NULL,
                    "(private-key"
                    " (ecc"
                    "  (curve \"Curve25519\")"
                    "  (flags djb-tweak)"
                    "  (q %b)"
                    "  (d %b)))",
                    sizeof Ed25519_Q, Ed25519_Q,
                    sizeof Ed25519_D, Ed25519_D);

    gcry_sexp_build(&s_data, NULL,
                    "(enc-val"
                    " (ecdh"
                    "  (e %b)))",
                   sizeof data, data);

    ret = gcry_pk_decrypt(&s_plain, s_data, s_sk);

#ifdef DEBUG
    size_t len;
    char *value = gcry_sexp_nth_data(s_plain, 1, &len);
    printhex(value, len);
    printf("\n");
#endif

    gcry_sexp_release(s_sk);
    gcry_sexp_release(s_data);
    gcry_sexp_release(s_plain);
    
    return 0;
}

int main() {
    //annotating secrets
    VALGRIND_MAKE_MEM_UNDEFINED(Ed25519_D, sizeof Ed25519_D);
    abacus_make_symbolic(1, (void*[]){Ed25519_D}, (uint32_t[]){sizeof Ed25519_D});

    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    return main_body();
} 

