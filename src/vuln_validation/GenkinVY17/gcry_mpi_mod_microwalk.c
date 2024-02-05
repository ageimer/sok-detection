#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#define ED25519
#include "../../common.h"

// Libgcrypt's MPI struct is opaque normally
typedef unsigned long int mpi_limb_t;

struct gcry_mpi {
  int alloced;         /* Array size (# of allocated limbs). */
  int nlimbs;          /* Number of valid limbs. */
  int sign;	           /* Indicates a negative number and is also used
		                  for opaque MPIs to store the length.  */
  unsigned int flags;  /* Bit 0: Array to be allocated in secure memory space.*/
                       /* Bit 2: the limb is a pointer to some m_alloced data.*/
  mpi_limb_t *d;       /* Array with the limbs */
};

#define sMPI sizeof(mpi_limb_t)

// intermediate value computed in montgomery_ladder from an order-4 element
static const uint8_t data[] = {
    0x12, 0x34, 0x98, 0x72, 0xcc, 0x7c, 0x52, 0x11, 0xe1, 0x7e, 0xd1, 0x23, 0x34,
    0xab, 0xd7, 0xa8, 0x6e, 0x0e, 0x2a, 0xf3, 0x95, 0x8e, 0x18, 0x7, 0x53, 0x50,
    0xca, 0xcc, 0x49, 0x16, 0x5b, 0x49, 0xe9, 0x0c, 0x1a, 0xb1, 0xaf, 0x5d, 0x14,
    0x89, 0x97, 0xe0, 0xc4, 0xaa, 0x2f, 0xad, 0x7b, 0xd, 0xda, 0x17, 0x2a, 0x8,
    0x91, 0x2a, 0xfe, 0x98, 0x55, 0x41, 0xff, 0xe8, 0xc6, 0x98, 0xb1, 0xbe
};

// order p of the curve
static const uint8_t c25519_p[] = {
     0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};

extern void RunTarget(uint8_t* input)
{
    gcry_error_t ret;
    gcry_mpi_t m_data, m_p;
    gcry_mpi_t m_res = gcry_mpi_new(0);

    gcry_mpi_scan(&m_data, GCRYMPI_FMT_USG, input, sizeof input, NULL);
    gcry_mpi_scan(&m_p, GCRYMPI_FMT_USG, c25519_p, sizeof c25519_p, NULL);

    gcry_mpi_mod(m_res, m_data, m_p);

    #ifdef DEBUG
    printhex(m_res->d, m_res->nlimbs);
    printf("\n");
    #endif

}

extern void InitTarget(uint8_t* input)
{
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
} 

