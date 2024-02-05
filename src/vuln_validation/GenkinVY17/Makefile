LIBGCRYPT32 = -I../../../$(LIB32)/libgcrypt-1.7.6/include -L../../../$(LIB32)/libgcrypt-1.7.6/lib -lgcrypt
LIBGCRYPT64 = -I../../../$(LIB64)/libgcrypt-1.7.6/include -L../../../$(LIB64)/libgcrypt-1.7.6/lib -lgcrypt
LIBGPGERR32 = -I../../../$(LIB32)/libgpg-error-1.45/include -L../../../$(LIB32)/libgpg-error-1.45/lib -lgpg-error
LIBGPGERR64 = -I../../../$(LIB64)/libgpg-error-1.45/include -L../../../$(LIB64)/libgpg-error-1.45/lib -lgpg-error

all: gcry_pk_decrypt gcry_mpi_mod

gcry_pk_decrypt:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBGCRYPT32) $(LIBGPGERR32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBGCRYPT32) $(LIBGPGERR32)
#	@echo "  Generating dudect benchmark"
#	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX)  $(LIBGCRYPT32) $(LIBGPGERR32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_eddsa.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX)  $(LIBGCRYPT64) $(LIBGPGERR64)

gcry_mpi_mod:
	@echo "> $(CC) $(CFLAGS) $@.c"
	@$(CC) $(CFLAGS) -m32 -DGENSUPP ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBGCRYPT32) $(LIBGPGERR32)
	@echo "  Generating valgrind suppression file"
	@../../$(GEN_SUPP) $(DESTDIR)/$@-$(SUFFIX) $(DESTDIR)/$@-$(SUFFIX).supp
	@$(CC) $(CFLAGS) -m32 ../../common.c $@.c -o $(DESTDIR)/$@-$(SUFFIX) $(LIBGCRYPT32) $(LIBGPGERR32)
#	@echo "  Generating dudect benchmark"
#	@$(CC) $(CFLAGS) -m32 -DNUM_MEAS=$(DUDECT_MEAS) ../../common.c dut_$@.c -o $(DESTDIR)/dut_$@-$(SUFFIX)  $(LIBGCRYPT32) $(LIBGPGERR32) -lm
	@echo "  Generating Microwalk benchmark"
	@$(CC) $(CFLAGS) -m64 ../../common.c ../../microwalk_wrapper.c ../../target_bn.c $@_microwalk.c -o $(DESTDIR)/microwalk_$@-$(SUFFIX)  $(LIBGCRYPT64) $(LIBGPGERR64)
