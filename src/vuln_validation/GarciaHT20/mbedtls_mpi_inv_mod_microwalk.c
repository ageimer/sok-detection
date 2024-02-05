#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/bignum.h>
#define VULNVALID
#include "../../common.h"

extern void RunTarget(uint8_t* input)
{
    mbedtls_mpi r, e, m;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&m);
    
    mbedtls_mpi_read_binary(&e, E, sizeof E);
    mbedtls_mpi_read_binary(&m, input, sizeof lcm);
    
    int ret = mbedtls_mpi_inv_mod(&r, &e, &m);

#ifdef DEBUG
    printf("ret = %d (0 on success)\n", ret);
#endif

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&m);

} 

extern void InitTarget(uint8_t* input)
{}
