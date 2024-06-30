#ifndef PARAMS_H
#define PARAMS_H

#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif

//#define KYBER_90S	/* Uncomment this if you want the 90S variant */

/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_ref_##s
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_ref_##s
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_90s_ref_##s
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_ref_##s
#endif
#else
#error "KYBER_K must be in {2,3,4}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#define KYBER_ETA2 2

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)



#define SEED_BYTES 32
#define PAKE_KEYBYTES 32


#define ID_BYTES 32
#define PW_BYTES 32

#define SESSION_KEY 32 // 32*8 = 256bit
#define PAKE_VERIFY 32 //32*8 = 256bit(H_3)


#define PAKE_SENDC0 (ID_BYTES + (KYBER_POLYVECBYTES) + SEED_BYTES)//
#define PAKE_SENDS0 (KYBER_POLYVECBYTES + KYBER_CIPHERTEXTBYTES + PAKE_VERIFY)//
#define PAKE_SENDC1 (PAKE_VERIFY) //
#define HASH_BYTES (2*ID_BYTES + 3 * KYBER_POLYVECBYTES + PAKE_KEYBYTES)



#define PAKE_A0_SEND (ID_BYTES + PW_BYTES + KYBER_PUBLICKEYBYTES)
#define AUTH_SIZE (ID_BYTES + ID_BYTES + ID_BYTES + PW_BYTES + PAKE_A0_SEND + KYBER_CIPHERTEXTBYTES + SESSION_KEY)
#define SHA3_256_HashSize 32

#endif
