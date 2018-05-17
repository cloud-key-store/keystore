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

#ifndef _SEXP_H
#define _SEXP_H

// ((8:username4:test)(8:password5:sample)(11:private-key(3:rsa(1:n384:...))
// sexp: {next = NULL, content = list1}
// list1: {next = list2, content = list_username}
// list_username = {next = string_test, content = string_username}
// list2: {next = list3, content = list_password}

#define CANONICAL 1

#define SEXP_STRING 1
#define SEXP_LIST 2

struct sexp_simple_string {
    int len;
    int max_len;
    unsigned char* str;
};

struct sexp_string {
    int type;
    struct sexp_simple_string string;
};

struct sexp {
    char type;
    struct sexp* next;
    union {
        struct sexp_string* string;
        struct sexp* list;
    } content;
};

void sexp_new_list( struct sexp** sexp );
void sexp_add( struct sexp* parent, struct sexp* sibling );
void sexp_new_string( struct sexp** sexp, const char* input );
void sexp_new_string_len( struct sexp** sexp, const char* input, int len );
void sexp_free( struct sexp* sexp );

const unsigned char* sexp_get_str( const struct sexp* sexp, int* len );
struct sexp* sexp_get( const struct sexp* sexp, const char* key );

int sexp_serialize( const struct sexp* sexp, char* buf, int len );
int sexp_parse( struct sexp** sexp, const char* buf, int buf_len );

void inverse_str( char* buf, int len );
int serialize_int( char* buf, int val );

#endif
