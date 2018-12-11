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

#ifndef _KEY_H
#define _KEY_H

#include <map>
#include <string>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>

typedef enum _key_type_t
{
    RSA_3072_KEY = 0,
    EC_256_KEY,
} key_type_t;

typedef std::string user_id_t;

struct key_policy
{
    int number_of_uses;
    sgx_time_t expiry_date;
};

struct ec256_key_t
{
  sgx_ec256_private_t priv;
  sgx_ec256_public_t pub;
};

struct user_key
{
    key_type_t key_type;
    union {
        sgx_rsa3072_key_t rsa_key;
        struct ec256_key_t ec_key;
    } key;
    struct key_policy policy;
    uint32_t timestamp;
    std::map<user_id_t, struct key_policy> delegated_users;
};

sgx_status_t hash_public_key(const struct user_key *key, unsigned char* buffer);

void swap_endianness(uint8_t *buf, int len);

#endif
