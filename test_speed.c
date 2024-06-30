#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "kyber-pake.h"
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "cpucycles.h"
#include "speed_print.h"
#include <sys/time.h>

#define NTESTS 1000

uint64_t t[NTESTS];

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  int i=0;
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

int main()
{
  unsigned int i;
  
  struct timeval timeval_start, timeval_end;
  polyvec gamma;
  printf("\n--------------------\n");
  gettimeofday(&timeval_start, NULL);
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    pake_a0(pw, ssid, send_a0, pk, sk);
  }
  gettimeofday(&timeval_end, NULL);
  printf("The average time of a0:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (NTESTS * 1.0));

  print_results("pake_a0: ", t, NTESTS);


  gettimeofday(&timeval_start, NULL);
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    pake_b0(pw, ssid, a_id, b_id, send_a0, send_b0, ct, k, auth_b);
  }
  gettimeofday(&timeval_end, NULL);
  printf("The average time of b0:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (NTESTS * 1.0));

  print_results("pake_b0: ", t, NTESTS);

  gettimeofday(&timeval_start, NULL);
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    pake_a1(pw, pk, sk, send_a0, send_b0, ssid, a_id, b_id, ct, key_a);
  }
  gettimeofday(&timeval_end, NULL);
  printf("The average time of a1:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (NTESTS * 1.0));

  print_results("pake_a1: ", t, NTESTS);

  gettimeofday(&timeval_start, NULL);
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    pake_b1(ssid,a_id,b_id,send_a0,ct,auth_b,k,key_b);
  }
  gettimeofday(&timeval_end, NULL);
  printf("The average time of b1:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (NTESTS * 1.0));
printf("\n--------------------\n");
  print_results("pake_b1: ", t, NTESTS);

  



  return 0;
}
