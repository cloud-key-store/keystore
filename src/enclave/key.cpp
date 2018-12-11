/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "key.h"
#include "rsa.h"
#include "ecc.h"
#include <cstdlib>
#include <cstring>
#include <ippcp.h>

void swap_endianness(uint8_t *buf, int len)
{
    for(int i = 0; i < len/2; i++) {
        uint8_t t;
        t = buf[i];
        buf[i] = buf[len - i - 1];
        buf[len - i - 1] = t;
    }
}

void swap_endianness_to(uint8_t *res, uint8_t *buf, int len)
{
    memcpy(res, buf, len);
    swap_endianness(res, len);
}

static void fill_common_hash(Ipp8u* to_hash, uint32_t ts, int n)
{
  to_hash[0] = 0x99;
  to_hash[1] = n >> 8;
  to_hash[2] = n;
  to_hash[3] = 0x4;
  to_hash[4] = ts >> 24;
  to_hash[5] = ts >> 16;
  to_hash[6] = ts >> 8;
  to_hash[7] = ts;
}

static sgx_status_t rsa_hash_public_key(const struct user_key *key, unsigned char* buffer)
{
  // Big integers are prefixed with 2 bytes length header
  // Starting is 0x99, 2 byte length, 1 byte version, 4 bytes timestamp, 1 byte algo
  int n = 6 + 386 + 5;
  Ipp8u *to_hash = NULL;

  to_hash = (Ipp8u*)malloc(n+3);
  // ippsSHA1MessageDigest(const Ipp8u *pSrcMesg, int mesgLen, Ipp8u *pMD);

  memset(to_hash, 0, n+3);
  fill_common_hash(to_hash, key->timestamp, n);
  to_hash[8] = 0x1;  // RSA algo is 1;
  to_hash[9] = 3072 >> 8;
  to_hash[10] = 0; // 3072 / 256 = 12, 3072 mod 256 = 0
  memcpy(to_hash + 11, key->key.rsa_key.mod, 384);
  swap_endianness(to_hash + 11, 384);
  to_hash[395] = 0;
  to_hash[396] = 17;
  memcpy(to_hash + 397, key->key.rsa_key.e, 3);
  swap_endianness(to_hash + 397, 3);

  ippsSHA1MessageDigest(to_hash, n+3, buffer);

  free(to_hash);

  return SGX_SUCCESS;
}

static unsigned char nist256_asn[8] = /* Object ID is 1.2.840.10045.3.1.7 */
  { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };


static sgx_status_t ecc_hash_public_key(const struct user_key *key, unsigned char* buffer)
{
  int n = 6 + 9 + 67;
  Ipp8u *to_hash = NULL;

  // Hashing two pub key components
  // First is DER encoded OID of NIST-256 curve
  // Second is 515 bits of 0x04 x-coordinate, y-coordinate
  to_hash = (Ipp8u*)malloc(n+3);
  memset(to_hash, 0, n+3);

    uint8_t gy[SGX_ECP256_KEY_SIZE];

  fill_common_hash(to_hash, key->timestamp, n);
  to_hash[8] = key->key_algo;  // ECDSA algo is 19, ECDH is 18
  to_hash[9] = 0x8;
  memcpy(to_hash + 10, nist256_asn, 8);
  to_hash[18] = 0x02;
  to_hash[19] = 0x03;
  to_hash[20] = 0x04;
  memcpy(to_hash + 21, key->key.ec_key.pub.gx, SGX_ECP256_KEY_SIZE);
  memcpy(to_hash + 21 + SGX_ECP256_KEY_SIZE, key->key.ec_key.pub.gy, SGX_ECP256_KEY_SIZE);
  swap_endianness(to_hash + 21, SGX_ECP256_KEY_SIZE);
  swap_endianness(to_hash + 21 + SGX_ECP256_KEY_SIZE, SGX_ECP256_KEY_SIZE);

  ippsSHA1MessageDigest(to_hash, n+3, buffer);

  free(to_hash);

  return SGX_SUCCESS;
}

struct key_operations {
  sgx_status_t (*gen_key)(struct user_key *key);
  sgx_status_t (*hash)(const struct user_key *key, unsigned char *buffer);
  sgx_status_t (*algo_to_sexp)(const struct user_key *key, struct sexp** sexp);
  sgx_status_t (*key_to_sexp_short)(const struct user_key *key, struct sexp** sexp);
  sgx_status_t (*key_to_sexp)(const struct user_key *key, struct sexp** sexp);
  sgx_status_t (*read_key)(const struct user_key *key, struct sexp** sexp);
};

struct key_operations rsa_key_operations = {
    rsa_gen_key,
    rsa_hash_public_key,
    rsa_algo_to_sexp,
    rsa_pub_key_to_sexp,
    rsa_pub_key_to_sexp,
    rsa_read_key
};

struct key_operations ecc_key_operations = {
    ecc_gen_key,
    ecc_hash_public_key,
    ecc_algo_to_sexp,
    ecc_pub_key_to_sexp_short,
    ecc_pub_key_to_sexp,
    ecc_read_key
};

struct key_operations key_ops[2] = {rsa_key_operations, ecc_key_operations};

sgx_status_t hash_public_key(const struct user_key *key, unsigned char* buffer)
{
  return key_ops[ key->key_type ].hash(key, buffer);
}

sgx_status_t gen_key(struct user_key *key)
{
  return key_ops[ key->key_type ].gen_key(key);
}

sgx_status_t algo_to_sexp(const struct user_key *key, struct sexp** sexp)
{
  return key_ops[ key->key_type ].algo_to_sexp(key, sexp);
}

sgx_status_t public_key_to_sexp_buffer_short(const struct user_key *key,
                 unsigned char* buffer, int len, int *res_len)
{
  sgx_status_t ret;
  struct sexp* sexp;

  ret = key_ops[ key->key_type ].key_to_sexp_short(key, &sexp);

  if( ret != SGX_SUCCESS )
    return ret;

  *res_len = sexp_serialize( sexp, (char*)buffer, len );

  sexp_free(sexp);

  return SGX_SUCCESS;
}

sgx_status_t public_key_to_sexp_buffer(const struct user_key *key,
                 unsigned char* buffer, int len, int *res_len)
{
  sgx_status_t ret;
  struct sexp* sexp;

  ret = key_ops[ key->key_type ].key_to_sexp(key, &sexp);

  if( ret != SGX_SUCCESS )
    return ret;

  *res_len = sexp_serialize( sexp, (char*)buffer, len );

  sexp_free(sexp);

  return SGX_SUCCESS;
}

sgx_status_t read_key_buffer(const struct user_key *key,
                      unsigned char* buffer, int len, int *res_len)
{
  sgx_status_t ret;
  struct sexp* sexp;

  ret = key_ops[ key->key_type ].read_key(key, &sexp);

  if( ret != SGX_SUCCESS )
    return ret;

  *res_len = sexp_serialize( sexp, (char*)buffer, len );

  sexp_free(sexp);

  return SGX_SUCCESS;
}
