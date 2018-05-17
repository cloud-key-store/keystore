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
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <poll.h>

#include "logger.h"
#include "socket.h"
#include "sexp.h"

#define HOSTNAME_SIZE 255
#define BUF_SIZE 2048

static struct logger* l = NULL;

void usage()
{
    printf("\n Usage: client -i <ip address> -p <port>\n\n");
}

int parse_parameters(int argc, char *argv[],
        char* hostname, in_port_t* port, char* filename)
{
    int c = 0;

    while((c = getopt(argc,argv,"hi:p:f:")) != -1){
        switch(c){
            case 'i':
                if( strlen(optarg) < HOSTNAME_SIZE )
                    strcpy(hostname, optarg);
                else
                {
                    log_error(l, "Error: given hostname/ip_address is too long.\n");
                    return -1;
                }
                break;
            case 'p':
                if( (*port=atoi(optarg)) == 0 )
                {
                    log_error(l, "Error: invalid port number. Give a number between 1 and 65535.\n");
                    return -1;
                }
                break;

            case 'f':
                if( strlen(optarg) < HOSTNAME_SIZE )
                    strcpy(filename, optarg);
                else
                {
                    log_error(l, "Error: given filename is too long.\n");
                    return -1;
                }
                break;
            case 'h':
            default:
                usage();
                return -1;
                break;
        }
    }

    return 0;
}

int client_socket(const char* hostname, in_port_t port)
{
    int sd;

    if( (sd = init_socket(hostname, port, false, NULL)) == -1 ){
        log_error(l, "Socket init failed.\n");
        return -1;
    }

    return sd;
}

int send_sample(int client_sd)
{
    //char sample[] =
    //    "(11:private-key(3:rsa(1:n3:123)(1:p1:1)(1:q1:2))(10:created-at10:1513114623))";
    //char sample[] =
    //    "(11:private-key(3:rsa)(10:created-at10:1513114623))";
    //char sample[] =
    //    "(11:private-key(3:rsa(1:n3:123)(1:p1:1))(1:q1:2))";
    //char sample[] =
    //    "(3:rsa)(1:q)";
    //char sample[] =
    //    "(3:rsa(1:n3:123)(1:p1:1))(1:q1:2)";
    char sample[] =
        "3:rsa1:n";
    //char sample[] =
    //    "(11:private-key(3:rsa(1:n3:123)(1:p1:1)))";
     log_debug( l, sample );
    //char sample[] =
    //    "(11:private-key(3:rsa))";
    char buf[BUF_SIZE] = {0};
    struct sexp *bundle;

    sexp_parse( &bundle, sample, strlen(sample) );
    sexp_serialize( bundle, buf, BUF_SIZE );
    free( bundle );

    write_all(client_sd, buf, strlen(buf));
    return 0;
}

int send_sign(int client_sd)
{
    char buf[BUF_SIZE] = {0};
    struct sexp *sign, *sample, *s_list, *bundle;

    sexp_new_list( &bundle );
    sexp_new_string( &sign, "key" );
    sexp_new_string( &sample, "test" );
    sexp_add( sign, sample );
    sexp_add( bundle, sign );
    sexp_serialize( bundle, buf, BUF_SIZE );
    sexp_free( bundle );
    log_debug( l, buf );

    write_all(client_sd, buf, strlen(buf));
    return 0;
}

int send_key(int client_sd, char* filename)
{
    char buf[BUF_SIZE] = {0};
    char hex_buf[BUF_SIZE] = {0};
    FILE *input_file;
    int nread;
    struct sexp *username_symbol, *username, *password_symbol, *password, *key;
    struct sexp *op_symbol, *operation, *op_list;
    struct sexp *username_list, *password_list, *bundle;

    input_file = fopen( filename, "r" );
    if( !input_file ) {
        log_error(l, "Could not open key file for reading.\n" );
        return -1;
    }
    nread = fread( buf, 1, sizeof(buf), input_file );
    if( sexp_parse( &key, buf, nread-1 ) == -1 ) {
        log_error(l, "Error parsing the key file.\n" );
        return -1;
    }
    sprintf( hex_buf, "Read %d bytes\n", nread );

    log_debug(l, hex_buf);

    // ((8:username4:test)(8:password5:sample)(11:private-key(3:rsa(1:n384:...))
    sexp_new_string( &op_symbol, "operation" );
    sexp_new_string( &operation, "writekey" );
    sexp_new_string( &username_symbol, "username" );
    sexp_new_string( &username, "test_user" );
    sexp_new_string( &password_symbol, "password" );
    sexp_new_string( &password, "test_password" );
    sexp_new_list( &op_list );
    sexp_new_list( &username_list );
    sexp_new_list( &password_list );
    sexp_new_list( &bundle );
    sexp_add( op_symbol, operation );
    sexp_add( username_symbol, username );
    sexp_add( password_symbol, password );
    sexp_add( op_list, op_symbol );
    sexp_add( username_list, username_symbol );
    sexp_add( password_list, password_symbol );
    sexp_add( op_list, username_list );
    sexp_add( username_list, password_list );
    sexp_add( password_list, key );
    sexp_add( bundle, op_list);

    nread = sexp_serialize( bundle, buf, 2048 );
    sexp_free( bundle );

    if( write_all(client_sd, buf, nread ) < 0 ) {
        log_error(l, "Error communicating with the server.\n" );
        return -1;
    }

    return 0;
}


int main(int argc, char* argv[])
{
    int ret;
    in_port_t port = 7000;
    int client_sd = -1;
    char buf[BUF_SIZE] = {0};
    int n;
    char hostname[HOSTNAME_SIZE] = "localhost";
    char filename[HOSTNAME_SIZE] = "key.bin";

    l = init_logger(stdout, stderr, stderr, "Main");

    if( parse_parameters(argc, argv, hostname, &port, filename) )
        exit(EXIT_FAILURE);

    log_print(l, "Will connect to: %s:%u. Key file: %s\n", hostname, port, filename);

    client_sd = client_socket(hostname, port);
    if( client_sd == -1 ) exit(EXIT_FAILURE);

    if( send_key(client_sd, filename) == -1 ) exit(EXIT_FAILURE);
    // if( send_sign(client_sd) == -1 ) exit(EXIT_FAILURE);
    // if( send_sample(client_sd) == -1 ) exit(EXIT_FAILURE);

    n = read(client_sd, buf, BUF_SIZE);
    if( n == -1 ){
        log_error(l, "Error reading server response.\n");
        perror("read");
        return -1;
    }

    log_print(l, "Got %d bytes from the server\n", n);
    log_print(l, buf);
    printf("\n");

    shutdown_logger(l);
    return 0;
}
