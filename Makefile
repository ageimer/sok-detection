BENCHDIR := src/benchmark
VALIDDIR := src/vuln_validation
BINDIR := build
LIBDIR := lib

# libraries for benchmarks
export LIB64 := $(LIBDIR)/amd64
export LIB32 := $(LIBDIR)/i686
#export BEARSSL := $(LIBDIR)/bearssl-0.6
#export MBEDTLS := $(LIBDIR)/mbedtls-3.1.0
#export OPENSSL := $(LIBDIR)/openssl-3.0.5

# libraries used for vulnerability validation
export OPENSSL102 := $(LIBDIR)/openssl-1.0.2k
export OPENSSL111 := $(LIBDIR)/openssl-1.1.1a
export MBEDTLS218 := $(LIBDIR)/mbedtls-2.18.1
export GCRYPT := $(LIBDIR)/libgcrypt-1.7.6
export GPGERR := $(LIBDIR)/libgpg-error-1.45

# compiler version and optimization level used
GCC_VER := 9
OLEVEL := 2
DEBUG = false
export DUDECT_MEAS := 5000

export CC := gcc-${GCC_VER}
export GEN_MEM_FILE := generate_mem_file.sh
export GEN_SUPP := generate_valgrind_suppressions.sh

ifeq ($(DEBUG),true)
export CFLAGS = -static -fno-inline -fno-split-stack -fno-stack-protector -g -O${OLEVEL} -DDEBUG
else
export CFLAGS = -static -fno-stack-protector -g -O${OLEVEL}
endif

#suffix given to each binaries built
export SUFFIX = GCC${GCC_VER}-O${OLEVEL}

benchmarks := $(addprefix $(BINDIR)/, $(shell cd $(BENCHDIR)/ && ls -d */))
vulnvalid := $(addprefix $(BINDIR)/, $(shell cd $(VALIDDIR)/ && ls -d */))

all: bench vuln

bench: $(benchmarks)

vuln: $(vulnvalid)

$(benchmarks):
	@echo "Building benchmarks in $@"
	@mkdir -p $@
	@cd $(BENCHDIR)/$(subst $(BINDIR)/,,$@) && $(MAKE) DESTDIR=../../../$@

$(vulnvalid):
	@echo "Building validation experiments in $@"
	@mkdir -p $@
	@cd $(VALIDDIR)/$(subst $(BINDIR)/,,$@) && $(MAKE) DESTDIR=../../../$@

lib:
	@echo "Building librairies in $(LIBDIR)"
	@cd $(LIBDIR) && $(MAKE)

clean:
	rm -r $(BINDIR)

.PHONY: lib
