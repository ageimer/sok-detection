LIBOPENSSL32 = -I../../../$(LIB32)/openssl-1.1.1a/include -L../../../$(LIB32)/openssl-1.1.1a/lib -l:libcrypto.a -l:libssl.a
LIBOPENSSL64 = -I../../../$(LIB64)/openssl-1.1.1a/include -L../../../$(LIB64)/openssl-1.1.1a/lib -l:libcrypto.a -l:libssl.a
LIBMBEDTLS32 = -I../../../$(LIB32)/mbedtls-2.18.1/include -L../../../$(LIB32)/mbedtls-2.18.1/lib -lmbedtls -lmbedcrypto
LIBMBEDTLS64 = -I../../../$(LIB64)/mbedtls-2.18.1/include -L../../../$(LIB64)/mbedtls-2.18.1/lib -lmbedtls -lmbedcrypto

all: ec_wnaf_mul ECDSA_do_sign mbedtls_rsa_complete mbedtls_mpi_gcd mbedtls_mpi_inv_mod

ec_wnaf_mul:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-${SUFFIX} $(LIBOPENSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) -lm $(LIBOPENSSL32)
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_ecdsa.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)

ECDSA_do_sign:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-${SUFFIX} $(LIBOPENSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) -lm $(LIBOPENSSL32)
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_nil.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)

CFLAGS += -DMBEDTLS_ALLOW_PRIVATE_ACCESS

mbedtls_rsa_complete:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBMBEDTLS32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-${SUFFIX} $(LIBMBEDTLS32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) -lm $(LIBMBEDTLS32)
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_rsa_oaep.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBMBEDTLS64)

mbedtls_mpi_gcd:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBMBEDTLS32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-${SUFFIX} $(LIBMBEDTLS32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) -lm $(LIBMBEDTLS32)
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_bn.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBMBEDTLS64)

mbedtls_mpi_inv_mod:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBMBEDTLS32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-${SUFFIX} $(LIBMBEDTLS32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) -lm $(LIBMBEDTLS32)
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_lcm.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBMBEDTLS64)
