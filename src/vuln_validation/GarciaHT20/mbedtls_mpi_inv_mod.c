#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/bignum.h>
#define VULNVALID
#include "../../common.h"

int main() {
    // annotating secrets
    VALGRIND_MAKE_MEM_UNDEFINED(lcm, sizeof lcm);
    abacus_make_symbolic(1, (void*[]){lcm}, (uint32_t[]){sizeof lcm});

    mbedtls_mpi r, e, m;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&m);
    
    mbedtls_mpi_read_binary(&e, E, sizeof E);
    mbedtls_mpi_read_binary(&m, lcm, sizeof lcm);
    
    int ret = mbedtls_mpi_inv_mod(&r, &e, &m);

#ifdef DEBUG
    printf("ret = %d (0 on success)\n", ret);
#endif

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&m);

    return 0;
} 

