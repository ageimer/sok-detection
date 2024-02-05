#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/bignum.h>
#define VULNVALID
#include "../../common.h"

int main() {
    // annotating secrets
    VALGRIND_MAKE_MEM_UNDEFINED(P_minus_one, sizeof P_minus_one);
    VALGRIND_MAKE_MEM_UNDEFINED(Q_minus_one, sizeof Q_minus_one);
    abacus_make_symbolic(2, (void*[]){P_minus_one, Q_minus_one}, (uint32_t[]){sizeof P_minus_one, sizeof Q_minus_one});
    
    mbedtls_mpi r, a, b;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    mbedtls_mpi_read_binary(&a, P_minus_one, sizeof P_minus_one);
    mbedtls_mpi_read_binary(&b, Q_minus_one, sizeof Q_minus_one);

    int ret = mbedtls_mpi_gcd(&r, &a, &b);

#ifdef DEBUG
    printf("ret (0 on success): %d\n", ret);
#endif
    
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

    return 0;
} 

