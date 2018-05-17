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

#ifndef _IAS_RA_H
#define _IAS_RA_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "ra.h"

int ias_get_spid( spid_t* spid );
int ias_get_sigrl( const epid_group_id_t gid, uint32_t* p_sig_rl_size,
                   uint8_t** p_sig_rl );

#ifdef  __cplusplus
}
#endif

#endif
