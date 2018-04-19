/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under 
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.  
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef LINKED_EPS_BEARER_IDENTITY_SEEN
#define LINKED_EPS_BEARER_IDENTITY_SEEN

#ifdef __cplusplus
extern "C" {
#endif

#define LINKED_EPS_BEARER_IDENTITY_MINIMUM_LENGTH 1
#define LINKED_EPS_BEARER_IDENTITY_MAXIMUM_LENGTH 1

typedef uint8_t linked_eps_bearer_identity_t;

int encode_linked_eps_bearer_identity(linked_eps_bearer_identity_t *linkedepsbeareridentity, uint8_t iei, uint8_t *buffer, uint32_t len);

uint8_t encode_u8_linked_eps_bearer_identity(linked_eps_bearer_identity_t *linkedepsbeareridentity);

int decode_linked_eps_bearer_identity(linked_eps_bearer_identity_t *linkedepsbeareridentity, uint8_t iei, uint8_t *buffer, uint32_t len);

int decode_u8_linked_eps_bearer_identity(linked_eps_bearer_identity_t *linkedepsbeareridentity, uint8_t iei, uint8_t value, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* LINKED EPS BEARER IDENTITY_SEEN */
