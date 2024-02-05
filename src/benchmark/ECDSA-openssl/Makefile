LIBOPENSSL32 = -I../../../$(LIB32)/openssl-3.0.5/include -L../../../$(LIB32)/openssl-3.0.5/lib -l:libcrypto.a -l:libssl.a
LIBOPENSSL64 = -I../../../$(LIB64)/openssl-3.0.5/include -L../../../$(LIB64)/openssl-3.0.5/lib64 -l:libcrypto.a -l:libssl.a

all: ECDSA_do_sign_p256

ECDSA_do_sign_p256:
	@echo "> $(CC) $(CFLAGS) $@.c" 
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-${SUFFIX} $(LIBOPENSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBOPENSSL32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_ecdsa.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)
