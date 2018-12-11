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

#include <sgx_uae_service.h>

#include <nrt_tke.h>
#include <nrt_ukey_exchange.h>
#include "cks.h"
#include "enclave_u.h"

/*
 * Create the enclave instance
 * Call sgx_create_enclave to initialize an enclave instance
 */
sgx_status_t create_enclave(const char* enclave_filename, sgx_enclave_id_t *eid)
{
    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Debug Support: set 2nd parameter to 1 */
    return sgx_create_enclave(enclave_filename,
                              SGX_DEBUG_FLAG,
                              &launch_token,
                              &launch_token_update,
                              eid, NULL);
}

sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, nrt_ra_context_t *context)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    unsigned int enclave_lost_retry = 1;

    // Initialize the non-interactive remote attestion
    do {
        ret = ecall_enclave_init_ra(eid, &status, true, context);
    } while( SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry-- );

    if (ret != SGX_SUCCESS) {
        return ret;
    }
    if (status != SGX_SUCCESS) {
        return (sgx_status_t)status;
    }

    return SGX_SUCCESS;
}

sgx_status_t enclave_process(sgx_enclave_id_t eid,
                             nrt_ra_context_t context,
                             const uint8_t *data,
                             int data_len,
                             uint8_t *res_buf,
                             uint32_t *res_len)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t max_len = *res_len;

    ret = ecall_process(eid, &status, context, data, data_len, res_buf, max_len, res_len);

    if (ret != SGX_SUCCESS) {
        return ret;
    }
    if (status != SGX_SUCCESS) {
        return (sgx_status_t)status;
    }

    return SGX_SUCCESS;
}

// Set this to Service Provider ID agreed with Intel
static const sgx_spid_t g_spid = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

sgx_status_t obtain_quote(sgx_enclave_id_t eid, nrt_ra_context_t context, uint8_t* quote)
{
    sgx_status_t status;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    unsigned int busy_retry = 2;

    sgx_target_info_t qe_target_info;

    sgx_ec256_public_t g_power_a;

    sgx_epid_group_id_t gid = {0};
    uint32_t extended_epid_group_id = 0;

    uint32_t msg_quote_size = 0;
    nrt_ra_msg_quote_t *p_msg_quote = NULL;


    // Preparation for obtaining the quote
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    gid[0] = extended_epid_group_id >> 24;
    gid[1] = (extended_epid_group_id & 0x00FF0000) >> 16;
    gid[2] = (extended_epid_group_id & 0x0000FF00) >> 8;
    gid[3] = (extended_epid_group_id & 0x000000FF);

    memset(&qe_target_info, 0, sizeof(qe_target_info));
    ret = sgx_init_quote(&qe_target_info, &gid);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    // Retrieve enclave's DH ephemeral public key
    memset(&g_power_a, 0, sizeof(g_power_a));
    ret = nrt_ra_get_ga(eid, &status, context, &g_power_a);
    // If get_ga was already called, just ignore the returned error
    if (( ret != SGX_SUCCESS ) && ( ret != SGX_ERROR_INVALID_STATE )){
        return ret;
    }
    if (( status != SGX_SUCCESS) && ( status != SGX_ERROR_INVALID_STATE )) {
        return (sgx_status_t)status;
    }

    do {
        ret = nrt_ra_get_quote(context, eid, &qe_target_info, &g_spid,
                               nrt_ra_create_report, nrt_ra_get_quote_trusted,
                               &p_msg_quote, &msg_quote_size);
    } while( SGX_ERROR_BUSY == ret && busy_retry-- );

    if( !p_msg_quote ) {
        return SGX_ERROR_UNEXPECTED;
    }

    if (ret != SGX_SUCCESS) {
        return ret;
    }
    if (status != SGX_SUCCESS) {
        return (sgx_status_t)status;
    }

    print_quote( (quote_t*)p_msg_quote->quote );
    memcpy(quote, (quote_t*)p_msg_quote->quote, sizeof(quote_t));
    return SGX_SUCCESS;
}

// Prints an array of bytes in hexademical format
void print_byte_array(
    FILE *file, const void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

void print_quote( quote_t *p_isv_quote )
{
    printf( "Quote version: %d\n", p_isv_quote->version );
    printf( "Signature type: %s\n", p_isv_quote->sign_type ? "LINKABLE":"UNLINKABLE" );
    printf( "Group id: " );
    print_byte_array( stdout, p_isv_quote->epid_group_id, 4 );
    printf( "\nQE SVN: %d\n", p_isv_quote->qe_svn );
    printf( "Basename - " );
    print_byte_array( stdout, p_isv_quote->basename.name, 32 );

    printf( "\nCPU SVN:" );
    print_byte_array( stdout, p_isv_quote->report_body.cpu_svn, 16 );
    printf( "\nMRENCLAVE:" );
    print_byte_array( stdout, p_isv_quote->report_body.mr_enclave, 32 );
    printf( "\nMRSIGNER:" );
    print_byte_array( stdout, p_isv_quote->report_body.mr_signer, 32 );
    printf( "\nREPORTDATA:" );
    print_byte_array( stdout, p_isv_quote->report_body.report_data, 64 );
    printf( "\nProduct ID of the Enclave: %d\n", p_isv_quote->report_body.isv_prod_id );
    printf( "SVN of the Enclave: %d\n", p_isv_quote->report_body.isv_svn );
    //printf( "\nSignature - " );
    //print_byte_array( stdout, p_isv_quote->signature, p_isv_quote->signature_len );
    printf( "\nSignature length: %d\n", p_isv_quote->signature_len );
}
