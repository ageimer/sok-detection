#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>
#define ED25519
#define DUDECT_IMPLEMENTATION
#include "../../dudect.h"
#include "../../common.h"

static gcry_mpi_t fixed_modulus;

static const uint8_t point[] = {
    0x12, 0x34, 0x98, 0x72, 0xcc, 0x7c, 0x52, 0x11, 0xe1, 0x7e, 0xd1, 0x23, 0x34,
    0xab, 0xd7, 0xa8, 0x6e, 0x0e, 0x2a, 0xf3, 0x95, 0x8e, 0x18, 0x7, 0x53, 0x50,
    0xca, 0xcc, 0x49, 0x16, 0x5b, 0x49, 0xe9, 0x0c, 0x1a, 0xb1, 0xaf, 0x5d, 0x14,
    0x89, 0x97, 0xe0, 0xc4, 0xaa, 0x2f, 0xad, 0x7b, 0xd, 0xda, 0x17, 0x2a, 0x8,
    0x91, 0x2a, 0xfe, 0x98, 0x55, 0x41, 0xff, 0xe8, 0xc6, 0x98, 0xb1, 0xbe
};

static const uint8_t c25519_p[] = {
     0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};

void printhex(unsigned int* buf, int len) {
    for(int i = 0; i < len; i++)
        printf("%X ",*(buf+i));
}

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ret;
    gcry_mpi_t m_data = (gcry_mpi_t)(data[0] | (data[1]<<8) | (data[2]<<16) | (data[3]<<24));
    gcry_mpi_t m_res = gcry_mpi_new(0);
    
    ret = thrash_cache();
    
    gcry_mpi_mod(m_res, m_data, fixed_modulus);
    
    gcry_mpi_release(m_data);
    return ret;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            gcry_mpi_t fixed_data;
            gcry_mpi_scan(&fixed_data, GCRYMPI_FMT_USG, point, sizeof point, NULL);
            memcpy(input_data + (size_t)i * c->chunk_size, &fixed_data, c->chunk_size);
        } else {
            gcry_mpi_t m_data = gcry_mpi_new(0);
            gcry_mpi_randomize(m_data, sizeof point * 8, GCRY_WEAK_RANDOM);
            memcpy(input_data + (size_t)i * c->chunk_size, &m_data, c->chunk_size);
        }
    }
}

int main() {

    dudect_config_t config = {
        .chunk_size = sizeof(gcry_mpi_t),
        .number_measurements = NUM_MEAS,
    };
    dudect_ctx_t ctx;

    dudect_init(&ctx, &config);

    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    // setting the fixed values
    size_t len = 0;
    gcry_mpi_scan(&fixed_modulus, GCRYMPI_FMT_USG, c25519_p, sizeof c25519_p, NULL);
    
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
        state = dudect_main(&ctx);
    }

    dudect_free(&ctx);

    return (int)state;
}
