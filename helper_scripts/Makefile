LIBOPENSSL = -I../lib/amd64/openssl-3.0.5/include -L../lib/amd64/openssl-3.0.5/lib64 -l:libcrypto.a -l:libssl.a
all:
	gcc -g generate_rand_bn.c -o generate_rand_bn $(LIBOPENSSL) 
