#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "kyber-pake.h"
#include "randombytes.h"
#include "polyvec.h"
#include "poly.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 1

static int test_keys()
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  int i = 0;
  unsigned char pw[32] = "12345678";
  unsigned char a_id[32] = "87654321";
  unsigned char b_id[32] = "55555555";

  const uint8_t ssid[ID_BYTES] = {0};
  uint8_t k[CRYPTO_BYTES] = {0};
  uint8_t auth_b[AUTH_SIZE];

  uint8_t key_a[CRYPTO_BYTES] = {0};
  uint8_t key_b[CRYPTO_BYTES] = {0};

  uint8_t send_a0[PAKE_A0_SEND];
  uint8_t send_b0[SHA3_256_HashSize];

  pake_a0(pw, ssid, send_a0, pk, sk);
  pake_b0(pw, ssid, a_id, b_id, send_a0, send_b0, ct, k, auth_b);
  pake_a1(pw, pk, sk, send_a0, send_b0, ssid, a_id, b_id, ct, key_a);
  pake_b1(ssid, a_id, b_id, send_a0, ct, auth_b, k, key_b);

  printf("\nsuccess...");
  printf("\nSession Key A:");
  printData(key_a, SHA3_256_HashSize);
  printf("***************************************\n\n\n");

  printf("\nsuccess...");
  printf("\nSession Key B:");
  printData(key_b, SHA3_256_HashSize);
  printf("***************************************\n\n\n");

  return 0;
}

int main(void)
{

  int r;
  r = test_keys();
  return 0;
}
