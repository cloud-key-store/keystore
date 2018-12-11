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

#include "sexp.h"
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

void sexp_new_string_len( struct sexp** sexp, const char* input, int len ) {
  *sexp = (struct sexp*) malloc(sizeof(struct sexp));
  struct sexp_string* sexp_str = (struct sexp_string*) malloc(sizeof(struct sexp_string));

  sexp_str->string.len = sexp_str->string.max_len = len;
  sexp_str->string.str = (unsigned char*) malloc(sexp_str->string.len + 1);
  sexp_str->type = CANONICAL;
  memset(sexp_str->string.str, 0, sexp_str->string.len + 1);
  memcpy(sexp_str->string.str, input, sexp_str->string.len);

  (*sexp)->type = SEXP_STRING;
  (*sexp)->next = NULL;
  (*sexp)->content.string = sexp_str;
}

void sexp_new_string( struct sexp** sexp, const char* input ) {
  sexp_new_string_len( sexp, input, strlen(input) );
}

void sexp_free( struct sexp* sexp ) {
  struct sexp *cur, *next;

  next = cur = sexp;
  do {
    cur = next;
    next = next->next;
    if( cur->type == SEXP_STRING ) {
      free(cur->content.string->string.str);
      free(cur->content.string);
      free(cur);
    }
    if( cur->type == SEXP_LIST ) {
      free(cur);
    }
  } while (next != NULL);
}

void sexp_new_list( struct sexp** sexp ) {
  *sexp = (struct sexp*) malloc(sizeof(struct sexp));
  (*sexp)->type = SEXP_LIST;
  (*sexp)->next = NULL;
  (*sexp)->content.list = NULL;
}

void sexp_add( struct sexp* parent, struct sexp* sibling ) {
  struct sexp *next, *cur;
  if( parent->type == SEXP_LIST && parent->content.list == NULL ) {
    parent->content.list = sibling;
    return;
  }

  next = parent;
  for(; cur = next, next = cur->next; next != NULL);

  cur->next = sibling;
}

struct sexp* sexp_add_list( struct sexp* sexp ) {
  struct sexp *sexp_list;
  sexp_new_list( &sexp_list );
  sexp_add( sexp, sexp_list );

  return sexp_list;
}

struct sexp* sexp_add_string( struct sexp* sexp, const char* val ) {
  struct sexp *sexp_str;
  sexp_new_string( &sexp_str, val );
  sexp_add( sexp, sexp_str );

  return sexp_str;
}

void sexp_new_pair( struct sexp** sexp, const char* key, const char* value ) {
  struct sexp *sexp_key, *sexp_value;

  sexp_new_string( &sexp_key, key );
  sexp_new_string( &sexp_value, value );
  sexp_new_list( sexp );
  sexp_add( sexp_key, sexp_value );
  sexp_add( *sexp, sexp_key );
}

void sexp_new_pair_len( struct sexp** sexp, const char* key,
    const char* value, int len ) {
  struct sexp *sexp_key, *sexp_value;

  sexp_new_string( &sexp_key, key );
  sexp_new_string_len( &sexp_value, value, len );
  sexp_new_list( sexp );
  sexp_add( sexp_key, sexp_value );
  sexp_add( *sexp, sexp_key );
}

static char numbers[] = "0123456789";
static bool str_contains( const char* str, char c ) {
  for( const char* s = str; *s != '\0'; s++ )
    if( c == *s )
      return true;
  return false;
}

void inverse_str( char* buf, int len ) {
  char c;
  for(int i = 0; i < len/2; i++) {
    c = buf[i];
    buf[i] = buf[len - i - 1];
    buf[len - i - 1] = c;
  }
}

int serialize_int( char* buf, int val ) {
  int remainder, left, cnt = 0;
  for( left = val; left > 0; left = left/10 ) {
    remainder = left % 10;
    buf[cnt] = remainder + '0';
    cnt++;
  }
  inverse_str( buf, cnt );
  return cnt;
}

int parse_int( const char* buf ) {
  int val = 0;
  while( str_contains( numbers, *buf ) ) {
    val = val*10 + (*buf - '0');
    buf++;
  }
  return val;
}

int sexp_serialize( const struct sexp* sexp, char* buf, int len ) {
  char* cursor = buf;
  int n, tot = 0;
  const struct sexp *cur_sexp;
  for( cur_sexp = sexp; cur_sexp != NULL; cur_sexp = cur_sexp->next ) {
    if( cur_sexp->type == SEXP_STRING ) {

      n = serialize_int( cursor, cur_sexp->content.string->string.len );
      if( n + cur_sexp->content.string->string.len >= len )
        return -1;

      cursor = cursor + n;
      *cursor = ':';
      cursor++;
      n++;
      len -= n;

      memcpy( cursor, cur_sexp->content.string->string.str,
              cur_sexp->content.string->string.len );

      cursor = cursor + cur_sexp->content.string->string.len;
      tot += n + cur_sexp->content.string->string.len;

    } else if( cur_sexp->type == SEXP_LIST ) {
      *(cursor++) = '(';

      n = sexp_serialize( cur_sexp->content.list, cursor, --len );
      if( n == -1 ) {
        return -1;
      }
      cursor += n;
      *(cursor++) = ')';
      len -= n + 1;
      tot += n + 2;
    }
  }
  return tot;
}

const unsigned char* sexp_get_str( const struct sexp* sexp, int* len ) {
  if( sexp->type == SEXP_STRING ) {
    if( len != NULL )
      *len = sexp->content.string->string.len;
    return sexp->content.string->string.str;
  }
  return NULL;
}

static bool sexp_cmp( const struct sexp* sexp, const char* str ) {
  if( sexp->type == SEXP_STRING ) {
    if( sexp->content.string && !strcmp( (const char*) sexp->content.string->string.str, str ) ) {
      return true;
    }
  }
  return false;
}

struct sexp* sexp_get( const struct sexp* sexp, const char* key ) {
  const struct sexp *cur, *next;
  struct sexp* nested;

  next = sexp;
  do {
    cur = next;
    next = cur->next;
    if( cur->type == SEXP_STRING ) {
      if( cur->content.string && !strcmp( (const char*) cur->content.string->string.str, key ) ) {
        return cur->next;
      }
    }
    if( cur->type == SEXP_LIST ) {
      nested = sexp_get( cur->content.list, key );
      if( nested )
        return nested;
    }
  } while (next != NULL);

  return NULL;
}

const unsigned char* sexp_get_val( const struct sexp* sexp, const char* key ) {
  struct sexp* pair;
  if( (pair = sexp_get( sexp, key )) == NULL )
    return NULL;

  return sexp_get_str( pair, NULL );
}

static void advance_parser(const char** cur, unsigned int* consumed,
        int* buf_len, unsigned int len) {
  *cur += len;
  *consumed += len;
  *buf_len -= len;
}

int sexp_parse( struct sexp** sexp, const char* buf, int buf_len ) {
  const char* cur = buf;
  struct sexp** res;
  unsigned int len, consumed = 0;

  if( buf_len < 0 )
    return -1;

  for( cur = buf, res = sexp; buf_len > 0; res = &((*res)->next) ) {
    if( str_contains( numbers, *cur ) ) {

      len = parse_int( cur );
      while( str_contains(numbers, *cur) ) {
        advance_parser( &cur, &consumed, &buf_len, 1 );
      }

      if( *cur != ':' || len > buf_len - 1 )
        return -1;
      advance_parser( &cur, &consumed, &buf_len, 1 );

      sexp_new_string_len( res, cur, len );
      advance_parser( &cur, &consumed, &buf_len, len );

    } else if( *cur == '(' ) {
      sexp_new_list( res );

      advance_parser( &cur, &consumed, &buf_len, 1 );
      len = sexp_parse( &((*res)->content.list), cur, buf_len );
      if( len == -1 )
        return -1;
      advance_parser( &cur, &consumed, &buf_len, len );
      if( *cur == ')' )
        advance_parser( &cur, &consumed, &buf_len, 1 );
    } else if( *cur == ')' ) {
      return consumed;
    } else
      return -1;
    if( buf_len == 0 )
      break;
  }

  return consumed;
}
