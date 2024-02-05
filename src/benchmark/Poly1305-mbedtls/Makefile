LIBMBEDTLS32 = -I../../../$(LIB32)/mbedtls-3.1.0/include -L../../../$(LIB32)/mbedtls-3.1.0/lib -lmbedtls -lmbedcrypto
LIBMBEDTLS64 = -I../../../$(LIB64)/mbedtls-3.1.0/include -L../../../$(LIB64)/mbedtls-3.1.0/lib -lmbedtls -lmbedcrypto

all: mbedtls_chachapoly

mbedtls_chachapoly:
	@echo "> $(CC) $(CFLAGS) $@.c" 
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBMBEDTLS32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-${SUFFIX} $(LIBMBEDTLS32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBMBEDTLS32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_polychacha.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBMBEDTLS64)
