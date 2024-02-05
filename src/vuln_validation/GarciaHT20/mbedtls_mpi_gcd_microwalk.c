#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/bignum.h>
#define VULNVALID
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    mbedtls_mpi r, a, b;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);

    mbedtls_mpi_read_binary(&a, input, sizeof P_minus_one);
    mbedtls_mpi_read_binary(&b, Q_minus_one, sizeof Q_minus_one);

    int ret = mbedtls_mpi_gcd(&r, &a, &b);

#ifdef DEBUG
    printf("ret (0 on success): %d\n", ret);
#endif
    
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b);

} 

extern void InitTarget(uint8_t* input)
{}
