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
#include <stddef.h>
#include <time.h>
#include <string.h>

#include <curl/curl.h>

#include "ias.h"

#ifndef CERT_PATH
#define CERT_PATH "/etc/ssl/certs/ias_sgx.pem"
#endif

#define IAS_URL "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/sigrl/"

// Retrieve the SIGRL upon the request.
//
// @param gid Group ID for the EPID key.
// @param p_sig_rl_size Pointer to the output value of the full
//                      SIGRL size in bytes. (including the
//                      signature).
// @param p_sig_rl Pointer to the output of the SIGRL.
//
// @return int
int ias_get_sigrl( const epid_group_id_t gid,
                   uint32_t *p_sig_rl_size,
                   uint8_t **p_sig_rl )
{
    int ret = 0;
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init( );
    if( !curl ) return -1;

    static const char *lut = "0123456789ABCDEFG";
    static const char *p_cert_file = CERT_PATH;
    char url[255] = {0};
    int base_url_len = 0;
    strcpy( url, IAS_URL );
    base_url_len = strlen(url);
    for( int i = base_url_len, j = sizeof(epid_group_id_t) - 1; j >= 0; j--, i+=2 ) {
        url[i] = lut[gid[j] >> 4];
        url[i + 1] = lut[gid[j] & 15];
    }
    curl_easy_setopt( curl, CURLOPT_URL, url );
    curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );
    curl_easy_setopt( curl, CURLOPT_SSLCERTTYPE, "PEM" );
    curl_easy_setopt( curl, CURLOPT_SSLCERT, p_cert_file );
    curl_easy_setopt( curl, CURLOPT_USE_SSL, CURLUSESSL_ALL );
    curl_easy_setopt( curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2 );
    curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1L);
 
    do {
        if (NULL == p_sig_rl || NULL == p_sig_rl_size) {
            ret = -1;
            break;
        }
        *p_sig_rl_size = 0;
        *p_sig_rl = NULL;
        // get sig_rl from an attestation server
        res = curl_easy_perform( curl );
        if ( res != CURLE_OK )
        {
            fprintf( stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror( res ) );
                    return false;
        }
        printf( "Retrieved SIGRL\n" );
        break;
    } while (0);

    return(ret);
}

// Used to simulate the enrollment function of an attestation server.  It only
// gives back the SPID right now. In production, the enrollment
// occurs out of context from an attestation attempt and only
// occurs once.
//
//
// @param p_spid
//
// @return int

static spid_t g_spid = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

int ias_get_spid( spid_t *p_spid )
{
    if (NULL != p_spid) {
        memcpy(p_spid, &g_spid, sizeof(spid_t));
    } else {
        return -1;
    }
    return 0;
}
