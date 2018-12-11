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

#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <poll.h>

#include <curl/curl.h>
#include <nrt_ukey_exchange.h>

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#include "enclave_u.h"

#include "logger.h"
#include "socket.h"
#include "sgx_errors.h"

#include "sexp.h"

#include "cks.h"

#define ENCLAVE_PATH "build/enclave/enclave.signed.so"
#define HOSTNAME_SIZE 255
#define BUF_SIZE 2048

#define QUOTE_SIZE 1116
#define SIGNATURE_SIZE 32

static struct logger* l = NULL;
static sgx_enclave_id_t eid = 0;
static nrt_ra_context_t ra_context;

void print_byte_array_stdout(const void *mem, uint32_t len)
{
    print_byte_array(stdout, mem, len);
}

void print_string_ocall(const char *str)
{
    printf("%s", str);
}

void print_int(uint32_t to_print)
{
    printf("%d", to_print);
}


void usage()
{
    printf("\n Usage: keystore -i <ip address> -p <port>\n\n");
}

int sgx_init(nrt_ra_context_t *p_ra_context) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = create_enclave(ENCLAVE_PATH, &eid);

    if (ret != SGX_SUCCESS)
        return -1;

    ret = enclave_init_ra(eid, p_ra_context);
    if (ret != SGX_SUCCESS)
        return -1;

    return 0;
}

/* Get the quote */
int sgx_get_quote(uint8_t* quote)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = obtain_quote(eid, ra_context, quote);
    if (ret != SGX_SUCCESS)
        return ret;
    return 0;
}

static sgx_status_t get_quote_operation(const uint8_t* data, uint32_t data_length)
{
    const char* operation;
    sgx_status_t status;
    uint32_t ret = 0;
    int err;
    struct sexp *sexp, *op_sexp;

    err = sexp_parse( &sexp, (const char*)data, data_length );
    if( err == -1 ) {
      return SGX_ERROR_INVALID_PARAMETER;
    }

    if( (op_sexp = sexp_get( sexp, "operation" )) == NULL ) {
      log_error(l, "No operation given.\n");
      sexp_free(sexp);
      return SGX_ERROR_INVALID_PARAMETER;
    }

    operation = (const char*)sexp_get_str( op_sexp, NULL );
    if( operation == NULL ) {
      log_error(l, "Could not get operation.\n");
      sexp_free(sexp);
      return SGX_ERROR_INVALID_PARAMETER;
    }
    if( !strcmp( operation, "getquote" ) ) {
      sexp_free(sexp);
      return SGX_SUCCESS;
    }

    sexp_free(sexp);
    return SGX_ERROR_UNEXPECTED;
}

/* Process the request */
int sgx_process(char* buf, int buf_len, uint8_t *res, uint32_t *res_len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int err;

    ret = get_quote_operation((const unsigned char*)buf, buf_len);
    if (ret == SGX_SUCCESS)
    {
        log_debug(l, "Getting the quote.\n");
        err = sgx_get_quote(res);
        *res_len = sizeof(quote_t);
        return err;
    }
    log_debug(l, "Calling enclave, %d bytes for the result buffer.\n", *res_len);
    ret = enclave_process(eid, ra_context,
            (uint8_t*)buf, buf_len, res, res_len);
    log_debug(l, "Enclave returned with status %d and %d "
        "bytes of the result buffer.\n", ret, *res_len);

    if (ret != SGX_SUCCESS)
        return ret;
    return 0;
}

int parse_parameters(int argc, char *argv[],
        char* hostname, in_port_t* port)
{
    int c = 0;

    while((c = getopt(argc,argv,"hi:p:")) != -1){
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

        case 'h':
        default:
            usage();
            return -1;
            break;
        }
    }

    return 0;
}

int server_socket(const char* hostname, in_port_t port)
{
    int sd;

    if( (sd = init_socket(hostname, port, true, NULL)) == -1 ){
        log_error(l, "Socket init failed.\n");
        return -1;
    }

    return sd;
}

int handle_client(int sd)
{
    char buf[BUF_SIZE] = {0};
    uint8_t res[1024];
    uint32_t res_len = 1024;
    int n = 0, ret = 0;
    uint8_t quote[QUOTE_SIZE];

    log_print(l, "New client connected\n");
    while( ret == 0 )
    {
        memset(buf, 0, BUF_SIZE);
        n = 0;
        if( (ret = read(sd, &buf[n], BUF_SIZE-1)) == -1 ) {
            log_error(l, "Error reading from client\n");
            perror("read");
            close(sd);
            return ret;
        }

        n = n + ret;
        if( n == 0 )
            break;

        if( (ret = sgx_process( buf, n, res, &res_len )) == 0 ) {
          write_all(sd, res, res_len);
        }
    }

    close(sd);
    log_print(l, "Disconnect\n");
    return ret;
}

int main(int argc, char* argv[])
{
    int ret;
    char hostname[HOSTNAME_SIZE] = "localhost";
    in_port_t port = 7000;
    int server_sd = -1;
    l = init_logger(stdout, stderr, stderr, "Main");

    if( parse_parameters(argc, argv, hostname, &port) )
        exit(EXIT_FAILURE);

    ret = sgx_init(&ra_context);
    if( sgx_init(&ra_context) == -1 ) {
        log_error(l, "Could not create the enclave.\n");
        print_error_message((sgx_status_t)ret);
        exit( EXIT_FAILURE );
    }

    log_print(l, "Will bind to: %s.\n", hostname);
    log_print(l, "Port for clients: %u.\n", port);

    server_sd = server_socket(hostname, port);
    if( server_sd == -1 ) exit(EXIT_FAILURE);

    if( init_tcp_server( server_sd ) == -1 ){
        log_error(l, "Could not initiate the server.\n");
        perror("init_tcp_server");
        exit( EXIT_FAILURE );
    }

    if( (ret = accept_tcp_connections( server_sd, handle_client )) == -1 ){
        log_error(l, "Could not accept a new connection.\n");
        perror("accept_tcp_connections");
    }

    shutdown_logger(l);
    return 0;
}
