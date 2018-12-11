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

#include "rsa.h"
#include <sgx_tcrypto.h>
#include <string.h>
#include <ippcp.h>

static unsigned char asn256[19] = /* Object ID is  2.16.840.1.101.3.4.2.1 */
  { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20 };

IppStatus sgx_ipp_newBN(const Ipp32u *p_data, int size_in_bytes, IppsBigNumState **p_new_BN);

sgx_status_t rsa_fill_key(const struct sexp* sexp, struct user_key *key)
{
    uint8_t *n, *p, *q, *e;
    sgx_rsa3072_key_t *rsa_key;
    int n_len, p_len, q_len, e_len, d_len;
    IppsBigNumState *n_bn, *p_bn, *q_bn, *one_bn, *r_bn, *e_bn, *d_bn;
    IppsBigNumSGN d_sgn;
    const Ipp32u one[] = {0x1};

    key->key_type = RSA_3072_KEY;
    key->key_algo = 1;
    rsa_key = &(key->key.rsa_key);

    n = (uint8_t*)sexp_get_str( sexp_get( sexp, "n" ), &n_len );
    p = (uint8_t*)sexp_get_str( sexp_get( sexp, "p" ), &p_len );
    q = (uint8_t*)sexp_get_str( sexp_get( sexp, "q" ), &q_len );
    e = (uint8_t*)sexp_get_str( sexp_get( sexp, "e" ), &e_len );

    // All the values are in big-endian
    // The IPP library works with little-endian
    swap_endianness(n, n_len);
    swap_endianness(p, p_len);
    swap_endianness(q, q_len);
    swap_endianness(e, e_len);

    sgx_ipp_newBN((const Ipp32u*)n, n_len, &n_bn);
    sgx_ipp_newBN((const Ipp32u*)n, n_len, &r_bn);
    sgx_ipp_newBN((const Ipp32u*)n, n_len, &d_bn);
    sgx_ipp_newBN((const Ipp32u*)p, p_len, &p_bn);

    sgx_ipp_newBN((const Ipp32u*)q, q_len, &q_bn);
    // XXX hack to round the length up to sizeof(Ipp32u) = 4 bytes
    if( sgx_ipp_newBN((const Ipp32u*)e, e_len+1, &e_bn) != ippStsNoErr ) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_ipp_newBN(one, sizeof(one), &one_bn);

    ippsSub_BN(p_bn, one_bn, p_bn);
    ippsSub_BN(q_bn, one_bn, q_bn);
    ippsMul_BN(p_bn, q_bn, r_bn);
    ippsModInv_BN(e_bn, r_bn, d_bn);

    ippsGet_BN(&d_sgn, &d_len, (Ipp32u*)(rsa_key->d), d_bn);
    memcpy(rsa_key->mod, n, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_key->e, e, e_len);

    free(n_bn);
    free(r_bn);
    free(d_bn);
    free(p_bn);
    free(q_bn);
    free(e_bn);
    free(one_bn);

    return SGX_SUCCESS;
}

sgx_status_t rsa_gen_key(struct user_key* key)
{
    uint8_t n[SGX_RSA3072_KEY_SIZE], d[SGX_RSA3072_PRI_EXP_SIZE];
    uint8_t p[SGX_RSA3072_KEY_SIZE/2], q[SGX_RSA3072_KEY_SIZE/2],
            dmp1[SGX_RSA3072_KEY_SIZE/2], dmq1[SGX_RSA3072_KEY_SIZE/2],
            iqmp[SGX_RSA3072_KEY_SIZE/2];
    sgx_status_t ret;

    sgx_rsa3072_key_t *rsa_key;

    uint8_t e[] = {0x01, 0x00, 0x01, 0x00};

    key->key_type = RSA_3072_KEY;
    key->key_algo = 1;
    rsa_key = &(key->key.rsa_key);

    ret = sgx_create_rsa_key_pair( SGX_RSA3072_KEY_SIZE,
                                   SGX_RSA3072_PUB_EXP_SIZE,
                                   n, d, e, p, q,
                                   dmp1, dmq1, iqmp );
    if( ret != SGX_SUCCESS )
      return ret;

    memcpy(rsa_key->mod, n, SGX_RSA3072_KEY_SIZE);
    memcpy(rsa_key->d, d, SGX_RSA3072_PRI_EXP_SIZE);
    memcpy(rsa_key->e, e, SGX_RSA3072_PUB_EXP_SIZE);

    return SGX_SUCCESS;
}

static sgx_status_t rsa_exponentiation(Ipp32u* mod, IppsBigNumState* f_bn,
        IppsBigNumState* d_bn, IppsBigNumState *r_bn);

static sgx_status_t pkcs11_frame(const uint8_t* hash, int hash_len, uint8_t* frame)
{
    int n, pad_len;

    /* Construct the frame to be signed
     * 0  1  PAD  0  ASN  HASH
     *
     * Padding is 0xff bytes. Taken from g10/seskey.c
     * Only support SHA-256 for the moment.
     */

    n = 0;
    frame[n++] = 0;
    frame[n++] = 1;

    pad_len = SGX_RSA3072_KEY_SIZE - hash_len - sizeof(asn256) - 3;
    memset( frame + n, 0xff, pad_len );
    n += pad_len;
    frame[n++] = 0;
    memcpy( frame + n, asn256, sizeof(asn256) );
    n += sizeof(asn256);
    memcpy( frame + n, hash, hash_len );
    n += hash_len;

    return SGX_SUCCESS;
}


sgx_status_t rsa_sign(const struct sexp* sexp, uint8_t* signature,
                      uint32_t *res_len, struct user_key key)
{
    const uint8_t *hash;
    uint8_t frame[SGX_RSA3072_KEY_SIZE];
    uint8_t result[SGX_RSA3072_KEY_SIZE];
    sgx_rsa3072_key_t *rsa_key;
    int hash_len;
    IppsBigNumState *d_bn, *f_bn, *r_bn;
    IppsBigNumSGN s_sgn;
    sgx_status_t ret;

    rsa_key = &(key.key.rsa_key);

    hash = (const uint8_t*)sexp_get_str( sexp_get( sexp, "data" ), &hash_len );
    pkcs11_frame(hash, hash_len, frame);
    swap_endianness(frame, SGX_RSA3072_KEY_SIZE);

    if( sgx_ipp_newBN((const Ipp32u*)(rsa_key->d), SGX_RSA3072_KEY_SIZE, &d_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;
    if( sgx_ipp_newBN((const Ipp32u*)frame, SGX_RSA3072_KEY_SIZE, &f_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;
    if( sgx_ipp_newBN((const Ipp32u*)signature, SGX_RSA3072_KEY_SIZE, &r_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;

    ret = rsa_exponentiation((Ipp32u*)(rsa_key->mod), f_bn, d_bn, r_bn);

    ippsGet_BN(&s_sgn, (int*)res_len, (Ipp32u*)signature, r_bn);
    *res_len = *res_len * sizeof(Ipp32u);

    free(d_bn);
    free(f_bn);
    free(r_bn);
    return ret;
}

sgx_status_t rsa_decrypt(const struct sexp* sexp, uint8_t* decryption,
                         uint32_t *res_len, struct user_key key)
{
    uint8_t *frame;
    uint8_t result[SGX_RSA3072_KEY_SIZE];
    int frame_len;
    sgx_rsa3072_key_t *rsa_key;
    IppsBigNumState *d_bn, *f_bn, *r_bn;
    IppsBigNumSGN s_sgn;
    sgx_status_t ret;

    rsa_key = &(key.key.rsa_key);

    frame = (uint8_t*)sexp_get_str( sexp_get( sexp, "data" ), &frame_len );
    swap_endianness(frame, SGX_RSA3072_KEY_SIZE);

    if( sgx_ipp_newBN((const Ipp32u*)(rsa_key->d), SGX_RSA3072_KEY_SIZE, &d_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;
    if( sgx_ipp_newBN((const Ipp32u*)frame, SGX_RSA3072_KEY_SIZE, &f_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;
    if( sgx_ipp_newBN((const Ipp32u*)decryption, SGX_RSA3072_KEY_SIZE, &r_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;

    ret = rsa_exponentiation((Ipp32u*)(rsa_key->mod), f_bn, d_bn, r_bn);

    ippsGet_BN(&s_sgn, (int*)res_len, (Ipp32u*)decryption, r_bn);
    *res_len = *res_len * sizeof(Ipp32u);

    free(d_bn);
    free(f_bn);
    free(r_bn);
    return ret;
}

static sgx_status_t rsa_exponentiation(Ipp32u* mod, IppsBigNumState* f_bn, IppsBigNumState* d_bn, IppsBigNumState *r_bn)
{
    int mont_size;
    IppsMontState *Mont;
    const Ipp32u one[] = {0x1};
    IppsBigNumState *one_bn;
    IppsBigNumSGN d_sgn;

    sgx_ipp_newBN(one, sizeof(one), &one_bn);

    if( ippsMontGetSize(IppsSlidingWindows,
                SGX_RSA3072_KEY_SIZE/sizeof(Ipp32u), &mont_size) != ippStsNoErr ) {
        return SGX_ERROR_UNEXPECTED;
    }

    Mont = (IppsMontState*) malloc(mont_size);

    if( ippsMontInit(IppsSlidingWindows,
                SGX_RSA3072_KEY_SIZE/sizeof(Ipp32u), Mont) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;

    if( ippsMontSet(mod, SGX_RSA3072_KEY_SIZE/sizeof(Ipp32u), Mont) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;

    if( ippsMontForm(f_bn, Mont, f_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;

    if( ippsMontExp(f_bn, d_bn, Mont, r_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;

    if( ippsMontMul(r_bn, one_bn, Mont, r_bn) != ippStsNoErr )
        return SGX_ERROR_UNEXPECTED;

    free(Mont);
    free(one_bn);

    return SGX_SUCCESS;
}

sgx_status_t rsa_pub_key_to_sexp(const struct user_key* key, struct sexp** sexp)
{
  struct sexp *n_sexp, *e_sexp;
  uint8_t n[SGX_RSA3072_KEY_SIZE], e[SGX_RSA3072_PUB_EXP_SIZE];
  sgx_rsa3072_key_t rsa_key = key->key.rsa_key;

  swap_endianness_to(n, rsa_key.mod, SGX_RSA3072_KEY_SIZE);
  swap_endianness_to(e, rsa_key.e, SGX_RSA3072_PUB_EXP_SIZE);

  sexp_new_pair_len( &n_sexp, "n", (const char*)n, SGX_RSA3072_KEY_SIZE );
  sexp_new_pair_len( &e_sexp, "e", (const char*)e, SGX_RSA3072_PUB_EXP_SIZE );

  sexp_new_list( sexp );
  sexp_add( n_sexp, e_sexp );
  sexp_add( *sexp, n_sexp );

  return SGX_SUCCESS;
}

sgx_status_t rsa_algo_to_sexp(const struct user_key* key, struct sexp** sexp)
{
  return SGX_SUCCESS;
}

sgx_status_t rsa_read_key(const struct user_key* key, struct sexp** sexp)
{
  return SGX_SUCCESS;
}

