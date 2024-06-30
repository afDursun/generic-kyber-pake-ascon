#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "kyber-pake.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"
#include "poly.h"
#include "polyvec.h"
#include "ascon_api.h"

#define BLOCK_SIZE 16


void printData(const uint8_t *data, size_t dataSize) {
    for (size_t i = 0; i < dataSize; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


void pake_a0(const unsigned char *pw, const uint8_t *ssid, uint8_t *epk, uint8_t *pk, uint8_t *sk) {

unsigned char n[CRYPTO_NPUBBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,
                                       8, 9, 10, 11, 12, 13, 14, 15};

  unsigned char a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  unsigned char m[16+2] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,16,17};
  unsigned char c11[32], h[32], t[32];
  unsigned long long alen = 16;
  unsigned long long mlen = 16+2;
  unsigned long long c11len = CRYPTO_ABYTES;
  int result = 0;

    
    int i;
    const uint8_t key[16] = "my_128_bit_key";
    uint8_t components[PAKE_A0_SEND];
    unsigned char encrypted_components[PAKE_A0_SEND + CRYPTO_ABYTES]; 
    unsigned long long encrypted_length;
    
    
    crypto_kem_keypair(pk, sk);

    for(i = 0; i < ID_BYTES ; i++ ){
        components[i] = ssid[i];
    } 
    
    for(i = 0; i < PW_BYTES ; i++ ){
        components[i + ID_BYTES] = pw[i];
    } 
    
    for(i = 0; i < CRYPTO_PUBLICKEYBYTES ; i++ ){
        components[i + ID_BYTES + PW_BYTES] = pk[i];
    } 
    
    crypto_aead_encrypt(encrypted_components, &encrypted_length, components, PAKE_A0_SEND, a, alen, (void*)0, n, key);

    memcpy(epk, encrypted_components, PAKE_A0_SEND + CRYPTO_ABYTES);

}

void pake_b0(const unsigned char *pw, const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id,  
                    uint8_t *epk, uint8_t *send_b0,uint8_t *ct,uint8_t *k,uint8_t *auth_b){
    
    unsigned char a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    unsigned long long alen = 16;
    unsigned char n[CRYPTO_NPUBBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,
                                       8, 9, 10, 11, 12, 13, 14, 15};
    
    uint8_t key[16] = "my_128_bit_key";
    int i;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t components[PAKE_A0_SEND];
    unsigned char decrypted_components[PAKE_A0_SEND]; 
    unsigned long long decrypted_length;
    
    
    crypto_aead_decrypt(decrypted_components, &decrypted_length, (void*)0, epk, PAKE_A0_SEND+16, a, alen, n, key);
    memcpy(components, decrypted_components, PAKE_A0_SEND);


    for(i = 0 ; i < CRYPTO_PUBLICKEYBYTES ; i++){
        pk[i] = components[ID_BYTES + PW_BYTES + i];
    }
    
    crypto_kem_enc(ct, k, pk);

    for(i = 0; i < ID_BYTES ; i++ ){
        auth_b[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES ; i++ ){
        auth_b[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES ; i++ ){
        auth_b[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PW_BYTES ; i++ ){
        auth_b[i + ID_BYTES*3] = pw[i];
    } 

    for(i = 0; i < PAKE_A0_SEND ; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES] = epk[i];
    } 

    for(i = 0; i < CRYPTO_CIPHERTEXTBYTES ; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND + CRYPTO_CIPHERTEXTBYTES] = k[i];
    } 

    hash_h(send_b0, auth_b, AUTH_SIZE);

    


}


void pake_a1(const unsigned char *pw, uint8_t *pk, uint8_t *sk, uint8_t *epk, uint8_t *send_b0, const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id, uint8_t *ct, uint8_t *key_a){
    
    uint8_t k_prime[CRYPTO_BYTES];
    int i;
    int HASH_SIZE = ID_BYTES*3 + PAKE_A0_SEND + CRYPTO_CIPHERTEXTBYTES + AUTH_SIZE +CRYPTO_BYTES;
    uint8_t auth[AUTH_SIZE];
    uint8_t control_auth[SHA3_256_HashSize];
    uint8_t hash_array[HASH_SIZE];

    crypto_kem_dec(k_prime, ct, sk);

    //bunu parametre olarak gönder
    for(i = 0; i < ID_BYTES ; i++ ){
        auth[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES ; i++ ){
        auth[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES ; i++ ){
        auth[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PW_BYTES ; i++ ){
        auth[i + ID_BYTES*3] = pw[i];
    } 

    for(i = 0; i < PAKE_A0_SEND ; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES] = epk[i];
    } 

    for(i = 0; i < CRYPTO_CIPHERTEXTBYTES ; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND + CRYPTO_CIPHERTEXTBYTES] = k_prime[i];
    } 


    hash_h(control_auth, auth, AUTH_SIZE);

    if (memcmp(control_auth, send_b0, SHA3_256_HashSize) == 0) {
        for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i] = ssid[i];
        } 
        
        for(i = 0; i < ID_BYTES ; i++ ){
            hash_array[i + ID_BYTES] = a_id[i];
        } 

        for(i = 0; i < ID_BYTES ; i++ ){
            hash_array[i + ID_BYTES*2] = b_id[i];
        } 

        for(i = 0; i < PAKE_A0_SEND ; i++ ){
            hash_array[i + ID_BYTES*3 ] = epk[i];
        } 

        for(i = 0; i < CRYPTO_CIPHERTEXTBYTES ; i++ ){
            hash_array[i + ID_BYTES*3  + PAKE_A0_SEND] = ct[i];
        } 

        for(i = 0; i < AUTH_SIZE ; i++ ){
            hash_array[i + ID_BYTES*3 + PAKE_A0_SEND + CRYPTO_CIPHERTEXTBYTES] = auth[i];
        } 

        for(i = 0; i < CRYPTO_BYTES ; i++ ){
            hash_array[i + ID_BYTES*3  + PAKE_A0_SEND + CRYPTO_CIPHERTEXTBYTES+ AUTH_SIZE] = k_prime[i];
        } 
        
        hash_h(key_a, hash_array, HASH_SIZE);

    
    } else {
        printf("Auth Failed....\n");
    }
    
    

}

void pake_b1(const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id, uint8_t *epk, uint8_t *ct, uint8_t *auth_b, uint8_t *k, uint8_t *key_b){
    
    int HASH_SIZE = ID_BYTES*3 + PAKE_A0_SEND + CRYPTO_CIPHERTEXTBYTES + AUTH_SIZE +CRYPTO_BYTES;
    uint8_t hash_array[HASH_SIZE];
    int i;

    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PAKE_A0_SEND ; i++ ){
        hash_array[i + ID_BYTES*3 ] = epk[i];
    } 

    for(i = 0; i < CRYPTO_CIPHERTEXTBYTES ; i++ ){
        hash_array[i + ID_BYTES*3  + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < AUTH_SIZE ; i++ ){
        hash_array[i + ID_BYTES*3 + PAKE_A0_SEND + CRYPTO_CIPHERTEXTBYTES] = auth_b[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
        hash_array[i + ID_BYTES*3  + PAKE_A0_SEND + CRYPTO_CIPHERTEXTBYTES+ AUTH_SIZE] = k[i];
    } 

    hash_h(key_b, hash_array, HASH_SIZE);


}


/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  size_t i;
  indcpa_keypair(pk, sk);
  for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}

int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}
