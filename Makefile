CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer -I/usr/include/openssl
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
LDFLAGS += -L/usr/lib -lcrypto
RM = /bin/rm

SOURCES = kyber-pake.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c aead.c permutations.c printstate.c
SOURCESKECCAK = $(SOURCES) fips202.c symmetric-shake.c
SOURCESNINETIES = $(SOURCES) sha256.c sha512.c aes256ctr.c symmetric-aes.c
HEADERS = params.h kyber-pake.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h permutations.h printstate.h crypto_aead.h config.h constants.h round.h forceinline.h word.h bendian.h
HEADERSKECCAK = $(HEADERS) fips202.h
HEADERSNINETIES = $(HEADERS) aes256ctr.h sha2.h

.PHONY: all speed shared clean

all: \
	test_kyber512 \
	test_kyber768 \
	test_kyber1024 \
	test_speed512 \
	test_speed768 \
	test_speed1024 \

kyber_pake: \
  test_kyber512 \
  test_kyber768 \
  test_kyber1024 \

kyber_pake_speed: \
  test_speed512 \
  test_speed768 \
  test_speed1024 \



test_kyber512: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kyber.c randombytes.c 
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) randombytes.c test_kyber.c -o pake_kyber512


test_kyber768: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kyber.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) randombytes.c test_kyber.c -o pake_kyber768

test_kyber1024: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kyber.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c test_kyber.c -o pake_kyber1024

test_speed512: $(SOURCESKECCAK) $(HEADERSKECCAK) cpucycles.h cpucycles.c speed_print.h speed_print.c test_speed.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) randombytes.c cpucycles.c speed_print.c test_speed.c -o test_speed512

test_speed768: $(SOURCESKECCAK) $(HEADERSKECCAK) cpucycles.h cpucycles.c speed_print.h speed_print.c test_speed.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) randombytes.c cpucycles.c speed_print.c test_speed.c -o test_speed768

test_speed1024: $(SOURCESKECCAK) $(HEADERSKECCAK) cpucycles.h cpucycles.c speed_print.h speed_print.c test_speed.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c cpucycles.c speed_print.c test_speed.c -o test_speed1024

clean:
	-$(RM) -rf *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf pake_kyber512
	-$(RM) -rf pake_kyber768
	-$(RM) -rf pake_kyber1024
	-$(RM) -rf test_speed512
	-$(RM) -rf test_speed768
	-$(RM) -rf test_speed1024

