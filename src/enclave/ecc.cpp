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

sgx_status_t ecc_gen_key(const struct sexp* sexp, uint8_t* pub_key_q,
        uint32_t *res_len, struct user_key *key)
{
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
