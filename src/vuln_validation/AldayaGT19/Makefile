LIBOPENSSL32 = -I../../../$(LIB32)/openssl-1.0.2k/include -L../../../$(LIB32)/openssl-1.0.2k/lib -l:libcrypto.a -l:libssl.a
LIBOPENSSL64 = -I../../../$(LIB64)/openssl-1.0.2k/include -L../../../$(LIB64)/openssl-1.0.2k/lib -l:libcrypto.a -l:libssl.a

all: RSA_key_generate_ex bn_gcd bn_mod_exp_mont bn_mod_inverse

RSA_key_generate_ex:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
#	@echo "  Generating dudect benchmark"
#	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBOPENSSL32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_nil.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)

bn_gcd:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBOPENSSL32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_bn.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)

bn_mod_exp_mont:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBOPENSSL32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_bn.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)

bn_mod_inverse:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBOPENSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBOPENSSL32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_bn.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX) $(LIBOPENSSL64)

