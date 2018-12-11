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

#include <map>
#include <vector>

#include <assert.h>
#include <nrt_tke.h>
#include <sgx_tcrypto.h>
#include <string.h>
#include <ippcp.h>
#include "sexp.h"
#include "key.h"
#include "rsa.h"
#include "ecc.h"
#include "enclave_t.h"

static std::map<user_id_t, std::vector<struct user_key> > g_users;

#define DH_PUBKEY_LENGTH 64

#define SUPPLIED_KEY_DERIVATION
#ifdef SUPPLIED_KEY_DERIVATION

// #pragma message ("Supplied key derivation function is used.")

// Attestation requires key derivation
// shared key is 32 bytes in little endian
// Feed SHA with its hex representation
sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
    uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;
    const char *hex = "0123456789abcdef";
    uint8_t hash_buffer[2*sizeof(sgx_ec256_dh_shared_t)+1] = {0};

    if( NULL == shared_key )
        return SGX_ERROR_INVALID_PARAMETER;

    for( int i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++ ) {
        hash_buffer[ 2*i ]     = hex[ shared_key->s[i] / 16 ];
        hash_buffer[ 2*i + 1 ] = hex[ shared_key->s[i] % 16 ];
    }
    // memcpy(hash_buffer, shared_key, sizeof(sgx_ec256_dh_shared_t));

    sgx_ret = sgx_sha256_init(&sha_context);
    if( sgx_ret != SGX_SUCCESS )
        return sgx_ret;

    sgx_ret = sgx_sha256_update(hash_buffer, sizeof(hash_buffer)-1, sha_context);
    if( sgx_ret != SGX_SUCCESS ) {
        sgx_sha256_close(sha_context);
        return sgx_ret;
    }

    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if( sgx_ret != SGX_SUCCESS ) {
        sgx_sha256_close(sha_context);
        return sgx_ret;
    }
    sgx_sha256_close(sha_context);

    memcpy(sk_key, key_material, sizeof(sgx_ec_key_128bit_t));
    memset(key_material, 0, sizeof(sgx_sha256_hash_t));

    return SGX_SUCCESS;
}

#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t ecall_enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse)
    {
        int busy_retry_times = 2;
        do{
            ret = sgx_create_pse_session();
        }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = nrt_ra_init_ex(b_pse, key_derivation, p_context);
#else
    ret = nrt_ra_init(b_pse, p_context);
#endif
    if(b_pse)
    {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI ecall_enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = nrt_ra_close(context);
    return ret;
}


static sgx_status_t authenticate( const struct sexp *sexp, user_id_t user_id ) {
    const char* username;
    const struct sexp* sexp_username;

    if( (sexp_username = sexp_get( sexp, "username" )) == NULL ) {
        print_string_ocall("No username given\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    username = (const char*)sexp_get_str( sexp_username, NULL );
    user_id.assign(username);

    return SGX_SUCCESS;
}

static sgx_status_t decrypt( nrt_ra_context_t context, const struct sexp *sexp,
                             struct sexp **nested_sexp )
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    struct sexp *gb_sexp, *data_sexp;
    uint8_t *decryption;
    uint8_t gb[DH_PUBKEY_LENGTH];
    const uint8_t* gb_input;
    const uint8_t* data;
    int data_len, gb_len, err;
    user_id_t user_id;

    *nested_sexp = NULL;
    if( (gb_sexp = sexp_get( sexp, "gb" )) == NULL ) {
      print_string_ocall("No Gb\n");
      return SGX_SUCCESS;
    }

    if( (data_sexp = sexp_get( sexp, "data" )) == NULL ) {
      print_string_ocall("No encrypted data\n");
      return SGX_ERROR_INVALID_PARAMETER;
    }

    data = (const uint8_t*)sexp_get_str( data_sexp, &data_len );
    gb_input = (const uint8_t*)sexp_get_str( gb_sexp, &gb_len );
    if( gb_len < DH_PUBKEY_LENGTH ) {
      print_string_ocall("Wrong Gb len\n");
      return SGX_ERROR_INVALID_PARAMETER;
    }
    memcpy( gb, gb_input, DH_PUBKEY_LENGTH );

    // The key comes with both coordinates in big endian
    // Should be in little endian for lib_tke
    for(int i = 0; i < DH_PUBKEY_LENGTH/4; i++) {
      uint8_t t;
      t = gb[i];
      gb[i] = gb[ DH_PUBKEY_LENGTH/2 - 1 - i ];
      gb[ DH_PUBKEY_LENGTH/2 - 1 - i ] = t;

      t = gb[ DH_PUBKEY_LENGTH/2 + i ];
      gb[ DH_PUBKEY_LENGTH/2 + i ] = gb[ DH_PUBKEY_LENGTH - 1 - i ];
      gb[ DH_PUBKEY_LENGTH - 1 - i ] = t;
    }

    ret = nrt_ra_set_gb_trusted(context, (sgx_ec256_public_t*)gb);
    if( ret != SGX_SUCCESS ) {
      print_string_ocall("Error setting Gb\n");
      return ret;
    }

    sgx_ra_key_128_t sk_key;
    ret = nrt_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if( ret != SGX_SUCCESS ) {
      print_string_ocall("Error getting keys\n");
      return ret;
    }

    decryption = (uint8_t*)malloc(data_len + 1);
    memset(decryption, 0, data_len + 1);

    uint8_t aes_ctr[16] = {0};
    aes_ctr[15] = 1;
    ret = sgx_aes_ctr_decrypt(&sk_key, data, data_len,
                              aes_ctr, 128, decryption);
    if( ret != SGX_SUCCESS ) {
      print_string_ocall("Decryption error\n");
      free(decryption);
      return ret;
    }

    err = sexp_parse( nested_sexp, (const char*)decryption, data_len );
    if( err == -1 ) {
      print_string_ocall("Could not parse decrypted data\n");
      free(decryption);
      return SGX_ERROR_UNEXPECTED;
    }

    free(decryption);

    return SGX_SUCCESS;
}

static void add_key(user_id_t user_id, struct user_key *key)
{
  key->key_no = g_users[user_id].size() + 1;

  // Second ECC key is ECDH(18), others are ECDSA(19)
  if( key->key_type == EC_256_KEY )
    if( key->key_no == 2 )
      key->key_algo = 18;
    else
      key->key_algo = 19;
  else
    key->key_algo = 1;

  g_users[user_id].push_back(*key);
}

static uint32_t parse_timestamp( const unsigned char* ts_str, int ts_len )
{
  uint32_t ts = 0;

  for( int i = 0; i < ts_len; i++ ) {
    ts = ts*10 + (ts_str[i] - '0');
  }

  return ts;
}

static sgx_status_t fill_key(const struct sexp* sexp, struct user_key *key)
{
    struct sexp *key_sexp, *ts_sexp;
    const unsigned char* ts_str;
    int ts_len;

    // Sanity check that sexp represents a key
    key_sexp = sexp_get( sexp, "private-key");
    if( !key_sexp )
      return SGX_ERROR_INVALID_PARAMETER;

    ts_sexp = sexp_get( sexp, "created-at" );
    if( !ts_sexp )
      key->timestamp = 0;
    else {
      ts_str = sexp_get_str( ts_sexp, &ts_len );
      key->timestamp = parse_timestamp( ts_str, ts_len );
    }

    key_sexp = sexp_get( sexp, "rsa" );
    if( key_sexp )
      return rsa_fill_key(sexp, key);

    key_sexp = sexp_get( sexp, "ecc" );
    if( key_sexp )
      return ecc_fill_key(sexp, key);

    return SGX_ERROR_INVALID_PARAMETER;
}

// Enclave API
sgx_status_t ecall_process(nrt_ra_context_t context,
        const uint8_t* data, uint32_t data_length,
        uint8_t* result, uint32_t max_res_len, uint32_t *res_len)
{
    const char* operation;
    sgx_status_t ret;
    int err;
    struct sexp *sexp, *op_sexp, *decrypted_sexp;
    user_id_t user_id;
    struct user_key key;
    key.key_no = 0;

    if( max_res_len < SGX_RSA3072_KEY_SIZE )
        return SGX_ERROR_INVALID_PARAMETER;

    memset(result, 0, max_res_len);

    err = sexp_parse( &sexp, (const char*)data, data_length );
    if( err == -1 ) {
      return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = decrypt( context, sexp, &decrypted_sexp );
    if( ret == SGX_SUCCESS ) {
      if( decrypted_sexp ) {
        sexp_free(sexp);
        sexp = decrypted_sexp;
      }
    }

    if( (op_sexp = sexp_get( sexp, "operation" )) == NULL ) {
      print_string_ocall("No operation given\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto out;
    }

    operation = (const char*)sexp_get_str( op_sexp, NULL );
    if( operation == NULL ) {
      print_string_ocall("Could not get operation\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto out;
    }

    ret = authenticate(sexp, user_id);
    if( ret == -1 ) {
      print_string_ocall("Not authorized\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto out;
    }

    if( !strcmp( operation, "writekey" ) ) {
      if( (ret = fill_key(sexp, &key)) == SGX_SUCCESS ) {
        add_key(user_id, &key);
        memcpy(result, "OK", 2);
        *res_len = 2;
      }
    }

    else if( !strcmp( operation, "setkeytype" ) ) {
      // Do not let to set the key type if key already exists
      if( !g_users[user_id].empty() ) {
        ret = SGX_ERROR_INVALID_PARAMETER;
      } else {
        const unsigned char* key_type = NULL;
        if( (key_type = sexp_get_val( sexp, "keytypestr" )) != NULL) {
          if( !strcmp( (const char*)key_type, "rsa" ) )
            key.key_type = RSA_3072_KEY;
          else if( !strcmp( (const char*)key_type, "ecc" ) )
            key.key_type = EC_256_KEY;
          else {
            ret = SGX_ERROR_INVALID_PARAMETER;
            goto out;
          }

          key.key_algo = 0;
          g_users[user_id].push_back(key);
          memcpy(result, "OK", 2);
          *res_len = 2;
        }
      }
    }

    else if( !strcmp( operation, "genkey" ) ) {
      key.key_type = EC_256_KEY;

      if( !g_users[user_id].empty() ) {
        key.key_type = g_users[user_id][0].key_type;
        // Remove dummy key (only used to pass key type from setkeytype)
        // Or clear keys when there are 3 of them
        if( !g_users[user_id][0].key_algo || (g_users[user_id].size() == 3) ) {
          g_users[user_id].clear();
        }
      }

      if( (ret = gen_key(&key)) == SGX_SUCCESS ) {
        add_key(user_id, &key);

        ret = public_key_to_sexp_buffer_short(&key, result, max_res_len,
              (int*)res_len);
      }
    }

    else if( !strcmp( operation, "readkey" ) ) {
      if( g_users[user_id].empty() ) {
          memcpy(result, "OK", 2);
          *res_len = 2;
          ret = SGX_SUCCESS;
          goto out;
      }

      print_string_ocall("Reading key\n");
      ret = read_key_buffer(&g_users[user_id][0], result,
            max_res_len, (int*)res_len);
    }

    else if( !strcmp( operation, "pksign" ) ) {
      uint8_t s[SGX_RSA3072_KEY_SIZE];
      if( (ret = rsa_sign(sexp, s, res_len,
                          g_users[user_id][0] )) == SGX_SUCCESS ) {
        // The result is in litte-endian, change it to big
        // TODO for the moment sign with key at slot 0
        swap_endianness(s, SGX_RSA3072_KEY_SIZE);
        memcpy(result, s, *res_len);
      }
    }

    else if( !strcmp( operation, "pkdecrypt" ) ) {
      uint8_t d[SGX_RSA3072_KEY_SIZE];
      if( (ret = rsa_decrypt(sexp, d, res_len,
                             g_users[user_id][0] )) == SGX_SUCCESS ) {
        // The result is in litte-endian, change it to big
        swap_endianness(d, SGX_RSA3072_KEY_SIZE);
        memcpy(result, d, *res_len);
      } else
        ret = SGX_ERROR_UNEXPECTED;
    }

    else if( !strcmp( operation, "keyattr" ) ) {
      uint8_t keyfpr[20] = {0};
      print_string_ocall("Obtaining key finger print\n");
      struct sexp* sexp, *keyattr;
      if( g_users[user_id].empty() ) {
        key.key_type = EC_256_KEY;
        key.key_algo = 18;
        algo_to_sexp(&key, &sexp);
        *res_len = sexp_serialize(sexp, (char*)result, max_res_len);
        sexp_free(sexp);
      } else {
        sexp_new_list(&sexp);
        for (std::vector<struct user_key>::iterator it = g_users[user_id].begin();
             it != g_users[user_id].end(); ++it) {
          algo_to_sexp(it, &keyattr);
          sexp_add(sexp, keyattr);
        }

        *res_len = sexp_serialize(sexp, (char*)result, max_res_len);
        sexp_free(sexp);
      }
    }

out:
    sexp_free(sexp);
    return ret;
}
