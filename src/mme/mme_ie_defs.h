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

/*! \file mme_ie_defs.h
* \brief
* \author Dincer Beken
* \company Blackned GmbH
* \email: dbeken@blackned.de
*
* \author Andreas Eberlein
* \company Blackned GmbH
* \email: aberlein@blackned.de
*/

#ifndef FILE_MME_IE_DEFS_SEEN
#define FILE_MME_IE_DEFS_SEEN
#include "common_types.h"
#include "3gpp_24.008.h"
#include "sgw_ie_defs.h"

/* Cause as defined in 3GPP TS 29.274 #8.4 */
typedef SGWCause_t MMECause_t;

typedef enum {
  FCAUSE_RANAP,
  FCAUSE_BSSGP,
  FCAUSE_S1AP,
}F_Cause_Type_t;

typedef enum {
  FCAUSE_S1AP_RNL      = 0,  // Radio Network Layer
  FCAUSE_S1AP_TL       = 1,  // Transport Layer
  FCAUSE_S1AP_NAS      = 2,  // NAS Layer
  FCAUSE_S1AP_Protocol = 3,
  FCAUSE_S1AP_Misc     = 4,
}F_Cause_S1AP_Type_t;

/** Only S1AP will be supported for RAN cause. */
typedef struct {
  F_Cause_Type_t      fcause_type;
  F_Cause_S1AP_Type_t fcause_s1ap_type;
  uint8_t             fcause_value;
}F_Cause_t;

typedef enum {
  COMPLETE_ATTACH_REQUEST_TYPE      = 0,
  COMPLETE_TAU_REQUEST_TYPE         = 1,
}Complete_Request_Message_Type_t;

typedef struct F_Container{
  bstring     container_value;
  uint8_t     container_type;
}F_Container_t;

typedef struct Complete_Request_Message{
  bstring                             request_value;
  Complete_Request_Message_Type_t     request_type;
}Complete_Request_Message_t;

//-----------------
typedef struct bearer_context_setup {
  uint8_t      eps_bearer_id;       ///< EPS Bearer ID
  // todo: rest is for indirect data forwarding!
} bearer_context_setup_t;

#define MAX_SETUP_BEARERS 11

typedef struct list_of_setup_bearers_s {
  uint8_t num_bearer_context;
  bearer_context_setup_t bearer_contexts[MAX_SETUP_BEARERS];
} list_of_setup_bearers_t;

//------------------------
#define MSG_FORWARD_RELOCATION_REQUEST_MAX_PDN_CONNECTIONS   3
#define MSG_FORWARD_RELOCATION_REQUEST_MAX_BEARER_CONTEXTS   11

typedef struct pdn_connection_s {
  char                      apn[APN_MAX_LENGTH + 1]; ///< Access Point Name
  //  protocol_configuration_options_t pco;
  bstring                   apn_str;
  int                       pdn_type;

  APNRestriction_t          apn_restriction;     ///< This IE shall be included on the S5/S8 and S4/S11
  ///< interfaces in the E-UTRAN initial attach, PDP Context
  ///< Activation and UE Requested PDN connectivity
  ///< procedures.
  ///< This IE shall also be included on S4/S11 during the Gn/Gp
  ///< SGSN to S4 SGSN/MME RAU/TAU procedures.
  ///< This IE denotes the restriction on the combination of types
  ///< of APN for the APN associated with this EPS bearer
  ///< Context.

  SelectionMode_t           selection_mode;      ///< Selection Mode
  ///< This IE shall be included on the S4/S11 and S5/S8
  ///< interfaces for an E-UTRAN initial attach, a PDP Context
  ///< Activation and a UE requested PDN connectivity.
  ///< This IE shall be included on the S2b interface for an Initial
  ///< Attach with GTP on S2b and a UE initiated Connectivity to
  ///< Additional PDN with GTP on S2b.
  ///< It shall indicate whether a subscribed APN or a non
  ///< subscribed APN chosen by the MME/SGSN/ePDG was
  ///< selected.
  ///< CO: When available, this IE shall be sent by the MME/SGSN on
  ///< the S11/S4 interface during TAU/RAU/HO with SGW
  ///< relocation.

//  uint8_t                   ipv4_address[4];
//  uint8_t                   ipv6_address[16];
  gtp_ip_address_t          ip_address;

  ebi_t                     linked_eps_bearer_id;

  FTeid_t                   pgw_address_for_cp;  ///< PGW S5/S8 address for control plane or PMIP

  bearer_context_to_be_created_t  bearer_context;

  ambr_t                    apn_ambr; //todo: ul/dl?

} pdn_connection_t;

typedef struct mme_ue_eps_pdn_connections_s {
  uint8_t num_pdn_connections;
  pdn_connection_t pdn_connection[MSG_FORWARD_RELOCATION_REQUEST_MAX_PDN_CONNECTIONS];
} mme_ue_eps_pdn_connections_t;
//----------------------------

//----------------------------
typedef struct mm_ue_eps_authentication_quadruplet_s{
  uint8_t                   rand[16];
  uint8_t                   xres_len;
  uint8_t                   xres[XRES_LENGTH_MAX];
  uint8_t                   autn_len;
  uint8_t                   autn[AUTN_LENGTH_OCTETS];
  uint8_t                   k_asme[32];
} mm_ue_eps_authentication_quadruplet_t;

typedef struct mm_ue_eps_authentication_quintuplet_s{
  uint8_t                   rand[16];
  uint8_t                   xres_len;
  uint8_t                   xres[XRES_LENGTH_MAX];
  uint8_t                   ck[16];
  uint8_t                   ik[16];
  uint8_t                   autn_len;
  uint8_t                   autn[AUTN_LENGTH_OCTETS];
} mm_ue_eps_authentication_quintuplet_t;

typedef struct mm_context_eps_s {
  // todo: better structure for flags
//  uint32_t                  mm_context_flags:24;
  uint8_t                   sec_mode:3;
  // todo: uint8_t                   drxi:1;
  uint8_t                   ksi:3;
  uint8_t                   num_quit:3;
  uint8_t                   num_quad:3;
  // todo: osci 0 --> old stuff (everything from s to s+64 in 29.274 --> 8-38.5 not present
  uint8_t                   nas_int_alg:3;
  uint8_t                   nas_cipher_alg:4;
//  uint32_t                   nas_dl_count[3]; // todo: or directly uint32_t?
//  uint8_t                   nas_ul_count[3]; // todo: or directly uint32_t?
  count_t                   nas_dl_count;
  count_t                   nas_ul_count;
  uint8_t                   k_asme[32];
  mm_ue_eps_authentication_quadruplet_t* auth_quadruplet[5];
  mm_ue_eps_authentication_quintuplet_t* auth_quintuplet[5];
  // todo : drx_t*                    drx;
  uint8_t                   nh[32];
  uint8_t                   ncc:3;
  uint32_t                  ul_subscribed_ue_ambr;
  uint32_t                  dl_subscribed_ue_ambr;
  uint32_t                  ul_used_ue_ambr;
  uint32_t                  dl_used_ue_ambr;
  uint8_t                   ue_nc_length;
  ue_network_capability_t   ue_nc;
  uint8_t                   ms_nc_length;
  ms_network_capability_t   ms_nc;
  uint8_t                   mei_length;
  Mei_t*                    mei;
  uint8_t                   vdp_lenth;
  uint8_t                   vdp; // todo: ??
  uint8_t                   access_restriction_flags;
} mm_context_eps_t;
//----------------------------


/** @struct bearer_context_t
 *  @brief Parameters that should be kept for an eps bearer.
 */
typedef struct bearer_context_s {
  /* S-GW Tunnel Endpoint for User-Plane */
  s1u_teid_t              s_gw_teid;

  /* S-GW IP address for User-Plane */
  ip_address_t            s_gw_address;

  /* P-GW Tunnel Endpoint for User-Plane */
  teid_t                  p_gw_teid;

  /* P-GW IP address for User-Plane */
  ip_address_t            p_gw_address;

  /* QoS for this bearer */
  qci_t                   qci;
  priority_level_t        prio_level;
  pre_emp_vulnerability_t pre_emp_vulnerability;
  pre_emp_capability_t    pre_emp_capability;

  /* TODO: add TFT */
} bearer_context_t;


#endif  /* FILE_MME_IE_DEFS_SEEN */

