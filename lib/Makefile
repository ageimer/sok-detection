all: lib_bench lib_vuln

lib_bench: bearssl-0.6 mbedtls-3.1.0 openssl-3.0.5

lib_vuln: openssl-1.0.2k openssl-1.1.1a mbedtls-2.18.1 libgpg-error-1.45 libgcrypt-1.7.6

bearssl-0.6:
	@echo "Building BearSSL"
	@tar -xf src/bearssl-0.6.tar.gz -C src
	@cd src && patch -p0 < bearssl_conf_patch.diff
	@cd src/bearssl-0.6 && $(MAKE) CONF=Unix32 BUILD=../../i686/bearssl-0.6
	@cd src/bearssl-0.6 && $(MAKE) CONF=Unix BUILD=../../amd64/bearssl-0.6

mbedtls-3.1.0:
	@echo "Building MbedTLS 3.1.0"
	@tar -xf src/mbedtls-3.1.0.tar.gz -C src
	@cd src && patch -p0 < mbedtls-3.1.0_make_patch.diff
	@cd src/mbedtls-3.1.0 && \
	$(MAKE) no_test CFLAGS="-m32 -g --static -DMBEDTLS_ALLOW_PRIVATE_ACCESS" && \
	$(MAKE) install DESTDIR=../../i686/mbedtls-3.1.0 && \
	$(MAKE) clean
	@cd src/mbedtls-3.1.0 && \
	$(MAKE) no_test CFLAGS="-g --static -DMBEDTLS_ALLOW_PRIVATE_ACCESS" && \
	$(MAKE) install DESTDIR=../../amd64/mbedtls-3.1.0

mbedtls-2.18.1:
	@echo "Building MbedTLS 2.18.1"
	@tar -xf src/mbedtls-2.18.1.tar.gz -C src
	@cd src && patch -p0 < mbedtls-2.18.1_make_patch.diff
	@cd src/mbedtls-2.18.1 && \
	$(MAKE) no_test CFLAGS="-m32 -g --static -DMBEDTLS_ALLOW_PRIVATE_ACCESS" && \
	$(MAKE) install DESTDIR=../../i686/mbedtls-2.18.1 && \
	$(MAKE) clean
	@cd src/mbedtls-2.18.1 && \
	$(MAKE) no_test CFLAGS="-g --static -DMBEDTLS_ALLOW_PRIVATE_ACCESS" && \
	$(MAKE) install DESTDIR=../../amd64/mbedtls-2.18.1

openssl-3.0.5:
	@echo "Building OpenSSL 3.0.5"
	@tar -xf src/openssl-3.0.5.tar.gz -C src
	@cd src/openssl-3.0.5 && \
	./Configure -m32 -g -static --openssldir=ssl/ --prefix=$(shell pwd)/i686/openssl-3.0.5/ linux-elf && \
	$(MAKE) && $(MAKE) install && $(MAKE) clean
	@cd src/openssl-3.0.5 && \
	./Configure -g -static --openssldir=ssl/ --prefix=$(shell pwd)/amd64/openssl-3.0.5/ linux-x86_64 && \
	$(MAKE) && $(MAKE) install

openssl-1.1.1a:
	@echo "Building OpenSSL 1.1.1a"
	@tar -xf src/openssl-1.1.1a.tar.gz -C src
	@cd src/openssl-1.1.1a && \
	./Configure -m32 -g -static --openssldir=ssl/ --prefix=$(shell pwd)/i686/openssl-1.1.1a/ linux-elf && \
	$(MAKE) && $(MAKE) install && $(MAKE) clean
	@cd src/openssl-1.1.1a && \
	./Configure -g -static --openssldir=ssl/ --prefix=$(shell pwd)/amd64/openssl-1.1.1a/ linux-x86_64 && \
	$(MAKE) && $(MAKE) install

openssl-1.0.2k:
	@echo "Building OpenSSL 1.0.2k"
	@tar -xf src/openssl-1.0.2k.tar.gz -C src
	@cd src/openssl-1.0.2k && \
	./Configure -m32 -g -static --openssldir=ssl/ --prefix=$(shell pwd)/i686/openssl-1.0.2k/ linux-elf && \
	$(MAKE) && $(MAKE) install && $(MAKE) clean
	@cd src/openssl-1.0.2k && \
	./Configure -g -static --openssldir=ssl/ --prefix=$(shell pwd)/amd64/openssl-1.0.2k/ linux-x86_64 && \
	$(MAKE) && $(MAKE) install

libgpg-error-1.45:
	@echo "Building Libgpg-error 1.45"
	@tar -xf src/libgpg-error-1.45.tar.bz2 -C src
	@cd src/libgpg-error-1.45 && \
    ./configure --host=i686-pc-linux-gnu --enable-static=yes --prefix=$(shell pwd)/i686/libgpg-error-1.45 CFLAGS="-m32 -g -O2" && \
	$(MAKE) && $(MAKE) install
	@cd src/libgpg-error-1.45 && \
    ./configure --host=x86_64-pc-linux-gnu --enable-static=yes --prefix=$(shell pwd)/amd64/libgpg-error-1.45 CFLAGS="-g -O2" && \
	$(MAKE) && $(MAKE) install

# aes must be disabled for 64-bits: weird gcc bug?
# similar to https://gitlab.alpinelinux.org/alpine/aports/-/issues/14105
libgcrypt-1.7.6:
	@echo "Building Libcrypt 1.7.6"
	@tar -xf src/libgcrypt-1.7.6.tar.gz -C src
	@cd src/libgcrypt-1.7.6 && \
	./configure --host=i686-pc-linux-gnu --disable-padlock-support --enable-static --prefix=$(shell pwd)/i686/libgcrypt-1.7.6 --with-libgpg-error-prefix=$(shell pwd)/i686/libgpg-error-1.45 CFLAGS="-m32 -g -O2" && \
	$(MAKE) && $(MAKE) install
	@cd src/libgcrypt-1.7.6 && \
	./configure --host=x86_64-pc-linux-gnu --disable-padlock-support --enable-static --prefix=$(shell pwd)/amd64/libgcrypt-1.7.6 --with-libgpg-error-prefix=$(shell pwd)/amd64/libgpg-error-1.45 --enable-ciphers="arcfour blowfish cast5 des twofish serpent rfc2268 seed camellia idea salsa20 gost28147 chacha20" CFLAGS="-g -O2" && \
	$(MAKE) clean && $(MAKE) && $(MAKE) install

clean:
	rm -r i686/* amd64/* src/openssl-3.0.5/ src/mbedtls-3.1.0/ src/openssl-1.1.1a src/openssl-1.0.2k/ src/mbedtls-2.18.1 src/libgcrypt-1.7.6 src/libgpg-error-1.45 src/bearssl-0.6
