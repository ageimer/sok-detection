LIBOPENSSL32 = -I../../../$(LIB32)/openssl-3.0.5/include -L../../../$(LIB32)/openssl-3.0.5/lib -l:libcrypto.a -l:libssl.a
LIBOPENSSL64 = -I../../../$(LIB64)/openssl-3.0.5/include -L../../../$(LIB64)/openssl-3.0.5/lib64 -l:libcrypto.a -l:libssl.a

all: RSA_private_decrypt_pkcs1_v15 RSA_private_decrypt_oaep

RSA_private_decrypt_pkcs1_v15:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBOPENSSL32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_rsa_pkcs.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)

RSA_private_decrypt_oaep:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBOPENSSL32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_rsa_oaep.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)

