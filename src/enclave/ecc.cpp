/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

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

#include <sgx_tcrypto.h>
#include <string.h>
#include "ecc.h"
#include "ippcp.h"

IppStatus sgx_ipp_newBN(const Ipp32u *p_data, int size_in_bytes, IppsBigNumState **p_new_BN);

int bytes_to_hex( const uint8_t* buf, char* res, int len )
{
    const char *hex = "0123456789abcdef";

    for( int i = 0; i < len; i++ ) {
        res[ 2*i ]     = hex[ buf[i] / 16 ];
        res[ 2*i + 1 ] = hex[ buf[i] % 16 ];
    }
}

sgx_status_t ecc_fill_key(const struct sexp* sexp, struct user_key *key)
{
    struct sexp *d_sexp, *q_sexp;
    uint8_t *d, *q;
    ec256_key_t *ec_key;
    int d_len, q_len;

    key->key_type = EC_256_KEY;
    ec_key = &(key->key.ec_key);

    d_sexp = sexp_get( sexp, "d" );
    if( !d_sexp )
      return SGX_ERROR_INVALID_PARAMETER;

    d = (uint8_t*)sexp_get_str( d_sexp, &d_len );
    if( d_len != SGX_ECP256_KEY_SIZE )
      return SGX_ERROR_INVALID_PARAMETER;

    q_sexp = sexp_get( sexp, "q" );
    if( !d_sexp )
      return SGX_ERROR_INVALID_PARAMETER;

    q = (uint8_t*)sexp_get_str( q_sexp, &q_len );
    // 65 bytes are 0x04 and two coordinates, 32 bytes each
    if( q_len != 2*SGX_ECP256_KEY_SIZE + 1)
      return SGX_ERROR_INVALID_PARAMETER;

    // All the values are in big-endian
    // The IPP library works with little-endian
    swap_endianness(d, d_len);
    swap_endianness(&(q[1]), SGX_ECP256_KEY_SIZE);
    swap_endianness(&(q[1+SGX_ECP256_KEY_SIZE]), SGX_ECP256_KEY_SIZE);

    memcpy(ec_key->priv.r, d, d_len);
    memcpy(ec_key->pub.gx, &(q[1]), SGX_ECP256_KEY_SIZE);
    memcpy(ec_key->pub.gy, &(q[1+SGX_ECP256_KEY_SIZE]), SGX_ECP256_KEY_SIZE);

    return SGX_SUCCESS;
}

sgx_status_t ecc_gen_key(struct user_key *key)
{
  sgx_ecc_state_handle_t handle;
  sgx_status_t ret;

  key->key_type = EC_256_KEY;
  struct ec256_key_t *ec_key = &(key->key.ec_key);

  ret = sgx_ecc256_open_context(&handle);
  if( ret != SGX_SUCCESS )
    return ret;

  ret = sgx_ecc256_create_key_pair(&(ec_key->priv), &(ec_key->pub), handle);
  if( ret != SGX_SUCCESS )
    return ret;

  sgx_ecc256_close_context(handle);

  return SGX_SUCCESS;
}

sgx_status_t ecc_sign(const struct sexp* sexp, uint8_t* signature,
        uint32_t *res_len, struct user_key key)
{
    return SGX_SUCCESS;
}

sgx_status_t ecc_decrypt(const struct sexp* sexp, uint8_t* decryption,
        uint32_t *res_len, struct user_key key)
{
    return SGX_SUCCESS;
}

sgx_status_t ecc_pub_key_to_sexp_internal(const struct user_key* key,
        struct sexp** sexp, bool no_prefix);

sgx_status_t ecc_pub_key_to_sexp_short(const struct user_key* key, struct sexp** sexp)
{
  return ecc_pub_key_to_sexp_internal(key, sexp, true);
}

sgx_status_t ecc_pub_key_to_sexp(const struct user_key* key, struct sexp** sexp)
{
  return ecc_pub_key_to_sexp_internal(key, sexp, false);
}

sgx_status_t ecc_pub_key_to_sexp_internal(const struct user_key* key,
      struct sexp** sexp, bool no_prefix)
{
  struct sexp *q;
  // Two coordinates in hex (hence *4), plus one byte of prefix
  uint8_t res[1 + SGX_ECP256_KEY_SIZE*4];
  uint8_t tmp[SGX_ECP256_KEY_SIZE];
  uint32_t len = 1 + SGX_ECP256_KEY_SIZE*4;
  struct ec256_key_t ecc_key = key->key.ec_key;
  sgx_ec256_public_t ecc_pub_key = ecc_key.pub;

  res[0] = '\x04';

  swap_endianness_to(tmp, ecc_pub_key.gx, SGX_ECP256_KEY_SIZE);
  bytes_to_hex( tmp, (char*)res + 1, SGX_ECP256_KEY_SIZE );
  swap_endianness_to(tmp, ecc_pub_key.gy, SGX_ECP256_KEY_SIZE);
  bytes_to_hex( tmp, (char*)res + 1 + SGX_ECP256_KEY_SIZE*2, SGX_ECP256_KEY_SIZE );

  if( no_prefix )
    sexp_new_pair_len( &q, "q", (char*)res + 1, len - 1 );
  else
    sexp_new_pair_len( &q, "q", (char*)res, len );

  sexp_new_list( sexp );
  sexp_add( *sexp, q );

  return SGX_SUCCESS;
}

int int_to_ansi( int n, char* s, int max_len )
{
  int i = 0;
  bool negative = (n < 0);
  if( !max_len )
    return -1;

  if( !n ) {
    s[0] = '0';
    return 1;
  }

  if( negative )
    n = -n;

  for( i = 0 ; i < max_len, n > 0; i++ ) {
    s[i] = '0' + (n % 10);
    n /= 10;
  }

  if( n > 0 )
    return -1;

  if( negative ) {
    s[i++] = '-';
  }

  swap_endianness((uint8_t*)s, i);

  return i;
}

sgx_status_t ecc_algo_to_sexp(const struct user_key* key, struct sexp** sexp)
{
  char key_algo_symbol[20] = "key";
  char key_algo[20] = {0};
  char key_fpr_symbol[20] = "key";
  char key_hash[21] = {0};
  int n;
  struct sexp *fpr, *algo;

  n = int_to_ansi( key->key_no, &(key_algo_symbol[3]), 10 );
  memcpy(&(key_algo_symbol[3+n]), "_algo\0", 6);
  n = int_to_ansi( key->key_algo, key_algo, 10 );
  memcpy(&(key_algo[n]), " NIST P-256", 11);
  n = int_to_ansi( key->key_no, &(key_fpr_symbol[3]), 10 );
  memcpy(&(key_fpr_symbol[3+n]), "_fpr\0", 5);

  hash_public_key(key, (unsigned char*)key_hash);

  sexp_new_pair( &algo, key_algo_symbol, key_algo );
  sexp_new_pair( &fpr, key_fpr_symbol, key_hash);
  sexp_new_list( sexp );
  sexp_add( algo, fpr );
  sexp_add( *sexp, algo );

  return SGX_SUCCESS;
}

sgx_status_t ecc_read_key(const struct user_key* key, struct sexp** sexp)
{
  struct sexp *sexp_pointer, *curve_sexp, *key_sexp;

  sexp_new_list( sexp );

  sexp_pointer = sexp_add_string( *sexp, "public-key" );
  sexp_pointer = sexp_add_list( sexp_pointer );
  sexp_pointer = sexp_add_string( sexp_pointer, "ecc" );

  sexp_new_pair( &curve_sexp, "curve", "NIST P-256" );

  ecc_pub_key_to_sexp_internal(key, &key_sexp, false);
  sexp_add( curve_sexp, key_sexp->content.list );
  sexp_add( sexp_pointer, curve_sexp );

  return SGX_SUCCESS;
}
