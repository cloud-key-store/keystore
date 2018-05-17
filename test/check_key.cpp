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

#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include "enclave/key.h"

unsigned char buf[200];

uint8_t modulus[384];
uint8_t exponent[3] = {0x01, 0x00, 0x01};
const char sample_mod_hex[] = "c727ddbf65893ce30eb42b9c0a0acc8b521b33ab6ba39d8521f9dc91a88100d2c1d9d2a604893ebc59710ccd7e3e4030dcb7ffcccde7f68a4d90224bc0e2e0e902413f2ba22604abb506687f47cfc741758cf153ba73fe04d4b8cb5fe4021433c5af9fd7a00503b23d642f5f14f983ec2fbc94beb6188347cbe76720ec632404181e2c1ecc270ed7ed2c8b49703ea1dcd079671a8bce69101524964cd616b43ff07de045d9e2f1a228e4d904d00dabe9e1e381d088cd70ae855a0a3806746737fc3a282078b7116e3181472d19c6737ad542daaf7e6fb310a497c8aeb2d7fd1befa3b5f72be3c22dcfd1ae534aa89e148bcce95f208b92cc853c1433baffc0e4b81cd64d774b2211d9b258efad4f01d33d5ca1946de63c27caf745a8308adbfa2b7d6e4530a4c20ec7cff06a0ed6e1b657d8579b62b3823045f50de9f7cec28dbbcabdb280fdc33f5928d7d03eb4172c173dca0df1c29005aa5a1ed8372b23a2bd232f5559aef2cf617938d69e8d9b2cdb90919eecbce2f1d58bbbaf2844ba4d";

uint8_t x[32];
uint8_t y[32];
unsigned char keyfpr[20];
const char sample_x_little[] = "86b2324abb772cf7f44d86a374a377bb40c71818103e0f661f986f1dd939a838";
const char sample_y_little[] = "5ff53d69a73e4df252c471797ecb1e99725cef9faa452c46d27f0f95e5a2963e";
const char fpr_hex[] = "71D2F02441DDB51D45826A28A4077414BAD2EF4C";

int hex2bytes(const char* hex, int len, char* res) {
  for(int i = 0; i < len/2; i++) {
    sscanf(&(hex[i*2]), "%2hhx", &(res[i]));
  }

  // Each 2 hex characters is one byte
  return len/2;
}

void
setup (void)
{
  memset(buf, 0, 200);
  hex2bytes(sample_mod_hex, 768, (char*)modulus);
  hex2bytes(sample_x_little, 64, (char*)x);
  hex2bytes(sample_y_little, 64, (char*)y);
  hex2bytes(fpr_hex, 40, (char*)keyfpr);
}

void
teardown (void)
{
}

START_TEST (test_keyfpr)
{
  sgx_status_t ret;
  struct user_key user_key;
  memset(&user_key, 0, sizeof(user_key));
  user_key.key_type = RSA_3072_KEY;

  memcpy(user_key.key.rsa_key.mod, modulus, 384);
  memcpy(user_key.key.rsa_key.e, exponent, 3);
  ret = hash_public_key(&user_key, buf);
  fail_unless( ret == SGX_SUCCESS,
          "Failed generating key fingerprint" );

  memset(&user_key, 0, sizeof(user_key));
  user_key.key_type = EC_256_KEY;
  memcpy(user_key.key.ec_key.pub.gx, x, 32);
  memcpy(user_key.key.ec_key.pub.gy, y, 32);
  user_key.timestamp = 1523998607;
  ret = hash_public_key(&user_key, buf);
  fail_unless( ret == SGX_SUCCESS,
          "Failed generating key fingerprint" );
  fail_unless( !memcmp(keyfpr, buf, 20),
          "Wrong key fingerprint" );
}
END_TEST

Suite *
key_suite(void)
{
  Suite *s = suite_create ("Key utils");

  TCase *tc_core = tcase_create ("Core");

  /* Core test case */
  tcase_add_checked_fixture (tc_core, setup, teardown);
  tcase_add_test (tc_core, test_keyfpr);
  suite_add_tcase (s, tc_core);

  return s;
}

int
main (void)
{
  int number_failed;
  Suite *s = key_suite ();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_NORMAL);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
