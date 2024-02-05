LIBBEARSSL32 = -I../../../$(LIB32)/bearssl-0.6/inc -L../../../$(LIB32)/bearssl-0.6 -lbearssl
LIBBEARSSL64 = -I../../../$(LIB64)/bearssl-0.6/inc -L../../../$(LIB64)/bearssl-0.6 -lbearssl

all: rsa_i31_oaep_decrypt

rsa_i31_oaep_decrypt:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBBEARSSL32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBBEARSSL32)
	@echo "  Generating dudect benchmark"
	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX) $(LIBBEARSSL32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_rsa_oaep.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@$(SUFFIX) $(LIBBEARSSL64)

