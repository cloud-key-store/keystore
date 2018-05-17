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

#ifndef _RSA_H
#define _RSA_H

#include "key.h"
#include "sexp.h"

sgx_status_t rsa_fill_key(const struct sexp* sexp, struct user_key *key);
sgx_status_t rsa_gen_key(const struct sexp* sexp, uint8_t* pub_key_n,
        uint32_t *res_len, struct user_key *key);
sgx_status_t rsa_sign(const struct sexp* sexp, uint8_t* signature,
        uint32_t *res_len, struct user_key key);
sgx_status_t rsa_decrypt(const struct sexp* sexp, uint8_t* decryption,
        uint32_t *res_len, struct user_key key);

#endif
