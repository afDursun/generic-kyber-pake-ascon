#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber512-90s"
#else
#define CRYPTO_ALGNAME "Kyber512"
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber768-90s"
#else
#define CRYPTO_ALGNAME "Kyber768"
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber1024-90s"
#else
#define CRYPTO_ALGNAME "Kyber1024"
#endif
#endif


void pake_a0(
	const unsigned char *pw, 
	const uint8_t *ssid, 
	uint8_t *send_a0,
	uint8_t *pk, 
	uint8_t *sk);


void pake_b0(
	const unsigned char *pw, 
	const uint8_t *ssid,
	const unsigned char *a_id,
	const unsigned char *b_id,
	uint8_t *epk, 
	uint8_t *send_b0, 
	uint8_t *ct,
	uint8_t *k,
	uint8_t *auth_b);

void pake_a1(
	const unsigned char *pw,
	uint8_t *pk, 
	uint8_t *sk, 
	uint8_t *epk, 
	uint8_t *send_b0, 
	const uint8_t *ssid,
	const unsigned char *a_id,
	const unsigned char *b_id, 
	uint8_t *ct,
	uint8_t *key_a);

void pake_b1(
	const uint8_t *ssid,
	const unsigned char *a_id,
	const unsigned char *b_id,
	uint8_t *send_a0,
	uint8_t *ct,
	uint8_t *auth_b,
	uint8_t *k,
	uint8_t *key_b);

#endif