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

#include <stdlib.h>
#include <check.h>
#include "../src/sexp/sexp.h"

struct sexp* sexp;
char buf[200];

void
setup (void)
{
  memset(buf, 0, 200);
}

void
teardown (void)
{
}

START_TEST (test_sexp_parser)
{
  struct sexp *node, *child, *key;
  sexp_parse( &child, "4:test", 6 );
  fail_unless( !strcmp( sexp_get_str(child, NULL), "test" ),
          "Failed parsing of string" );
  sexp_free( child );

  /* ------------------------------------------------------------------------ */
  sexp_parse( &node, "()", 2 );
  fail_unless( node->next == NULL, "Error parsing empty list" );
  fail_unless( node->content.list == NULL, "Error parsing empty list" );
  sexp_free( node );

  /* ------------------------------------------------------------------------ */
  const char str_sample[] =
      "(11:private-key(3:rsa))";
  sexp_parse( &node, str_sample, strlen(str_sample) );
  sexp_serialize( node, buf, 200 );
  fail_unless( !strcmp( str_sample, buf ),
           "Failed parsing list after string" );
  sexp_free( node );

  /* ------------------------------------------------------------------------ */
  const char str_sample2[] =
      "(11:private-key)(3:rsa)";
  sexp_parse( &node, str_sample2, strlen(str_sample2) );
  sexp_serialize( node, buf, 200 );
  fail_unless( !strcmp( str_sample2, buf ),
           "Failed parsing list after list" );
  sexp_free( node );

  /* ------------------------------------------------------------------------ */
  const char str_key[] =
      "(11:private-key(3:rsa(1:n3:123)(1:p1:1)(1:q1:2))(10:created-at10:1513114623))";
  sexp_parse( &node, str_key, strlen(str_key) );
  sexp_serialize( node, buf, 200 );
  fail_unless( !strcmp( str_key, buf ),
           "Failed parsing the key" );
  sexp_free( node );

  /* ------------------------------------------------------------------------ */
  const char str_bad_sample[] =
      "(11:private-key(3:rsa:))";
  fail_unless( sexp_parse( &node, str_bad_sample, strlen(str_bad_sample) ) == -1,
          "Did not fail when parsing bad sample" );

  /* ------------------------------------------------------------------------ */
  sexp_parse( &node, str_key, strlen(str_key) );
  key = sexp_get( node, "private-key" );
  fail_unless( key,
           "Failed getting the key after parsing" );
  sexp_free( node );

  /* ------------------------------------------------------------------------ */
  const char str_ecc_key[] =
      "(11:private-key(3:ecc(1:q3:123)(1:d5:12345))(10:created-at10:1513114623))";
  sexp_parse( &node, str_ecc_key, strlen(str_ecc_key) );
  key = sexp_get( node, "rsa" );
  fail_unless( key == NULL,
           "Failed getting ecc key, rsa returned not NULL" );
  key = sexp_get( node, "ecc" );
  fail_unless( key,
           "Failed getting ecc key, ecc returned NULL" );
  sexp_free( node );

}
END_TEST

START_TEST (test_utils)
{
  memset(buf, 0, 200);
  memcpy( buf, "0123456789", 10 );
  inverse_str( buf, 10 );
  fail_unless( !strcmp( buf, "9876543210" ), "Failed to inverse the buffer" );

  memset(buf, 0, 200);
  serialize_int( buf, 1 );
  fail_unless( !strcmp( buf, "1" ), "Failed to serialize integer 1" );

  memset(buf, 0, 200);
  serialize_int( buf, 10 );
  fail_unless( !strcmp( buf, "10" ), "Failed to serialize integer 10" );

  memset(buf, 0, 200);
  serialize_int( buf, 14 );
  fail_unless( !strcmp( buf, "14" ), "Failed to serialize integer 14" );
}
END_TEST

START_TEST (test_sexp_serializer)
{
  struct sexp *node, *child, *key, *node2;
  int ret;

  /* ------------------------------------------------------------------------ */
  sexp_new_string( &node, "test" );
  memset(buf, 0, 200);
  ret = sexp_serialize( node, buf, 200 );
  fail_unless( ret == 6, "Failed to serialize string S-expression, len is wrong" );
  fail_unless( !strcmp(buf, "4:test"),
          "Failed to serialize string S-expression, string is wrong" );
  sexp_free( node );

  /* ------------------------------------------------------------------------ */
  sexp_new_list( &node );
  sexp_new_string( &child, "test" );
  sexp_add( node, child );
  ret = sexp_serialize( node, buf, 200 );
  fail_unless( ret == 8, "Failed to serialize one string in a list S-expression" );
  fail_unless( !strcmp(buf, "(4:test)"),
          "Failed to serialize one string in a list S-expression" );
  sexp_free( node );

  /* ------------------------------------------------------------------------ */
  /* (3:key4:test) */
  sexp_new_list( &node );
  sexp_new_string( &child, "test" );
  sexp_new_string( &key, "key" );
  sexp_add( key, child );
  sexp_add( node, key );
  ret = sexp_serialize( node, buf, 200 );
  fail_unless( ret == 13, "Failed to serialize two strings in a list S-expression" );
  fail_unless( !strcmp(buf, "(3:key4:test)"),
          "Failed to serialize two strings in a list S-expression" );
  sexp_free( node );

  /* ------------------------------------------------------------------------ */
  /* 3:key4:test */
  sexp_new_string( &child, "test" );
  sexp_new_string( &key, "key" );
  sexp_add( key, child );
  memset(buf, 0, 200);
  ret = sexp_serialize( key, buf, 200 );
  fail_unless( ret == 11, "Failed to serialize two consecutive strings, len" );
  fail_unless( !strcmp(buf, "3:key4:test"),
          "Failed to serialize two consecutive strings, value" );
  sexp_free( key );

  /* ------------------------------------------------------------------------ */
  /* (3:key)(4:test) */
  sexp_new_list( &node );
  sexp_new_list( &node2 );
  sexp_new_string( &child, "test" );
  sexp_new_string( &key, "key" );
  sexp_add( node, key );
  sexp_add( node2, child );
  sexp_add( node, node2 );
  ret = sexp_serialize( node, buf, 200 );
  fail_unless( ret == 15, "Failed to serialize two consecutive lists" );
  fail_unless( !strcmp(buf, "(3:key)(4:test)"),
          "Failed to serialize two consecutive lists" );
  sexp_free( node );
}
END_TEST

START_TEST (test_sexp_api)
{
  struct sexp *node, *child, *key;
  const char *str;

  /* Test new string S-expression */
  sexp_new_string( &node, "test" );
  fail_unless( node->type == SEXP_STRING,
          "Invalid S-expression type, should be STRING" );
  fail_unless( node->next == NULL, "Next node should be NULL" );
  fail_unless( !strcmp( node->content.string->string.str, "test" ),
          "String value should be test" );
  sexp_free( node );
  /* ------------------------------------------------------------------------ */

  /* Test new list S-expression */
  sexp_new_list( &node );
  fail_unless( node->type == SEXP_LIST,
          "Invalid S-expression type, should be LIST" );
  fail_unless( node->next == NULL, "Next node should be NULL" );
  sexp_free( node );
  /* ------------------------------------------------------------------------ */

  /* Test add node to list */
  sexp_new_string( &child, "test" );
  sexp_new_list( &node );
  sexp_add( node, child );
  fail_unless( node->content.list == child,
          "Failed to add node to linked list" );
  sexp_free( node );
  /* ------------------------------------------------------------------------ */

  /* Test getting a string content */
  sexp_new_string( &node, "test" );
  str = sexp_get_str(node, NULL);
  fail_if( str == NULL, "Got NULL instead of string" );
  fail_unless( !strcmp( str, "test" ),
          "Failed to get the string for S-expression" );
  sexp_free( node );
  /* ------------------------------------------------------------------------ */

  /* Test getting an associative array value */
  sexp_new_string( &child, "value" );
  sexp_new_string( &key, "key" );
  sexp_new_list( &node );
  sexp_add( key, child );
  sexp_add( node, key );

  fail_unless( child == sexp_get( node, "key" ),
            "Failed to get node from associative array" );
  sexp_free( node );
}
END_TEST

Suite *
sexp_parser_suite(void)
{
  Suite *s = suite_create ("S-exp parser");

  TCase *tc_core = tcase_create ("Core");

  /* Core test case */
  tcase_add_checked_fixture (tc_core, setup, teardown);
  tcase_add_test (tc_core, test_sexp_api);
  tcase_add_test (tc_core, test_sexp_serializer);
  tcase_add_test (tc_core, test_sexp_parser);
  tcase_add_test (tc_core, test_utils);
  suite_add_tcase (s, tc_core);

  return s;
}

int
main (void)
{
  int number_failed;
  Suite *s = sexp_parser_suite ();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_NORMAL);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
