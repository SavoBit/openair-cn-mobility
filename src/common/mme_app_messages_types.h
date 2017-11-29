/*
 * Copyright (c) 2015, EURECOM (www.eurecom.fr)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
 */
#ifndef FILE_MME_APP_MESSAGES_TYPES_SEEN
#define FILE_MME_APP_MESSAGES_TYPES_SEEN
#include "nas_messages_types.h"
#include "s1ap_common.h"

#define MME_APP_INITIAL_UE_MESSAGE(mSGpTR)                  (mSGpTR)->ittiMsg.mme_app_initial_ue_message
#define MME_APP_INITIAL_UE_MESSAGE_CHECK_DUPLICATE(mSGpTR)  (mSGpTR)->ittiMsg.mme_app_initial_ue_message_check_duplicate

#define MME_APP_CONNECTION_ESTABLISHMENT_CNF(mSGpTR)     (mSGpTR)->ittiMsg.mme_app_connection_establishment_cnf
#define MME_APP_INITIAL_CONTEXT_SETUP_RSP(mSGpTR)        (mSGpTR)->ittiMsg.mme_app_initial_context_setup_rsp
#define MME_APP_INITIAL_CONTEXT_SETUP_FAILURE(mSGpTR)    (mSGpTR)->ittiMsg.mme_app_initial_context_setup_failure
#define MME_APP_S1AP_MME_UE_ID_NOTIFICATION(mSGpTR)      (mSGpTR)->ittiMsg.mme_app_s1ap_mme_ue_id_notification

// Duplicate message detection
#define MME_APP_S1AP_INITIAL_UE_MESSAGE_DUPLICATE_CNF(mSGpTR) (mSGpTR)->ittiMsg.mme_app_s1ap_initial_ue_message_duplicate_cnf

// handover messages from S11 to MME_APP to NAS
#define MME_APP_HO_BEARER_MODIFICATION_RES(mSGpTR)       (mSGpTR)->ittiMsg.mme_app_ho_bearer_modification_rsp
#define MME_APP_HO_BEARER_MODIFICATION_FAIL(mSGpTR)      (mSGpTR)->ittiMsg.mme_app_ho_bearer_modification_fail
// handover messages from NAS to MME_APP to S1AP
#define MME_APP_HANDOVER_CNF(mSGpTR)                     (mSGpTR)->ittiMsg.mme_app_handover_cnf
#define MME_APP_HANDOVER_REJ(mSGpTR)                     (mSGpTR)->ittiMsg.mme_app_handover_rej

#define MME_APP_PATH_SWITCH_REQ(mSGpTR)                  (mSGpTR)->ittiMsg.mme_app_path_switch_req


typedef struct itti_mme_app_initial_ue_message_s {
  sctp_assoc_id_t     sctp_assoc_id; // key stored in MME_APP for MME_APP forward NAS response to S1AP
  uint32_t            enb_id; 
  mme_ue_s1ap_id_t    mme_ue_s1ap_id;
  enb_ue_s1ap_id_t    enb_ue_s1ap_id;
  bstring             nas;
  tai_t               tai;               /* Indicating the Tracking Area from which the UE has sent the NAS message.                         */
  ecgi_t              cgi;               /* Indicating the cell from which the UE has sent the NAS message.                         */
  as_cause_t          as_cause;          /* Establishment cause                     */

  bool                is_s_tmsi_valid;
  bool                is_csg_id_valid;
  bool                is_gummei_valid;
  as_stmsi_t          opt_s_tmsi;
  csg_id_t            opt_csg_id;
  gummei_t            opt_gummei;
  //void                opt_cell_access_mode;
  //void                opt_cell_gw_transport_address;
  //void                opt_relay_node_indicator;
  /* Transparent message from s1ap to be forwarded to MME_APP or
   * to S1AP if connection establishment is rejected by NAS.
   */
  itti_s1ap_initial_ue_message_t transparent;
} itti_mme_app_initial_ue_message_t;



typedef struct itti_mme_app_initial_ue_message_check_duplicate_s {
  sctp_assoc_id_t     sctp_assoc_id; // key stored in MME_APP for MME_APP forward NAS response to S1AP
  sctp_stream_id_t    stream_id;

  uint32_t            enb_id;
  mme_ue_s1ap_id_t    mme_ue_s1ap_id;
  enb_ue_s1ap_id_t    new_enb_ue_s1ap_id;
//  S1ap_InitialUEMessageIEs_t       *s1ap_InitialUEMessageIEs;
//  uint8_t             mmec;
//  uint32_t            s_tmsi;
  as_cause_t          as_cause;          /* Establishment cause                     */
  tai_t               tai;               /* Indicating the Tracking Area from which the UE has sent the NAS message.                         */
  ecgi_t              cgi;
  as_stmsi_t          opt_s_tmsi;
  csg_id_t            opt_csg_id;
  gummei_t            opt_gummei;
  bool                is_s_tmsi_valid;
  bool                is_csg_id_valid;
  bool                is_gummei_valid;
  bstring             nas;
} itti_mme_app_initial_ue_message_check_duplicate_t;


typedef struct itti_mme_app_connection_establishment_cnf_s {
  ebi_t                   eps_bearer_id;
  FTeid_t                 bearer_s1u_sgw_fteid;
  qci_t                   bearer_qos_qci;
  priority_level_t        bearer_qos_prio_level;
  pre_emp_vulnerability_t bearer_qos_pre_emp_vulnerability;
  pre_emp_capability_t    bearer_qos_pre_emp_capability;
  ambr_t                  ambr;

  bool                    create_new_ue_reference;

  /* Key eNB */
  uint8_t                 kenb[AUTH_KASME_SIZE];
  uint16_t                security_capabilities_encryption_algorithms;
  uint16_t                security_capabilities_integrity_algorithms;

  uint8_t                 *ue_radio_capabilities;
  int                     ue_radio_cap_length;

  itti_nas_conn_est_cnf_t nas_conn_est_cnf;
} itti_mme_app_connection_establishment_cnf_t;

// HANDOVER MESSAGES SENT FROM MBR TO NAS AFTER RECEIVAL OF MBR
typedef struct itti_mme_app_ho_bearer_modification_rsp_s {
  ebi_t                   eps_bearer_id;
  FTeid_t                 bearer_s1u_sgw_fteid;

  /* Key eNB */
  uint8_t                 kenb[AUTH_KASME_SIZE];
  uint16_t                security_capabilities_encryption_algorithms;
  uint16_t                security_capabilities_integrity_algorithms;
} itti_mme_app_ho_bearer_modification_rsp_t;

typedef struct itti_mme_app_ho_bearer_modification_fail_s {
  ebi_t                   eps_bearer_id;
//  FTeid_t                 bearer_s1u_sgw_fteid;
} itti_mme_app_ho_bearer_modification_fail_t;

// HANDOVER MESSAGE SENT FROM MME_APP to S1AP after processing and validating in NAS todo: reject
typedef struct itti_mme_app_handover_cnf_s {
  ebi_t                   eps_bearer_id;
  FTeid_t                 bearer_s1u_sgw_fteid;

  /* Key eNB */
  uint8_t                 nh[AUTH_NH_SIZE];
  uint8_t                 ncc:3;

  uint16_t                security_capabilities_encryption_algorithms;
  uint16_t                security_capabilities_integrity_algorithms;

  itti_nas_handover_cnf_t nas_handover_cnf; /**< Original message sent by NAS after validation. */
} itti_mme_app_handover_cnf_t;

typedef struct itti_mme_app_handover_rej_s {
  itti_nas_handover_rej_t nas_handover_rej; /**< Original message sent by NAS after validation. */
} itti_mme_app_handover_rej_t;

typedef struct itti_mme_app_initial_context_setup_rsp_s {
  uint32_t                mme_ue_s1ap_id;
  ebi_t                   eps_bearer_id;
  FTeid_t                 bearer_s1u_enb_fteid;
} itti_mme_app_initial_context_setup_rsp_t;




typedef struct itti_mme_app_path_switch_req_s {
  uint32_t                mme_ue_s1ap_id;
  uint32_t                enb_ue_s1ap_id;
  sctp_assoc_id_t         sctp_assoc_id;
  sctp_stream_id_t        sctp_stream;
  ebi_t                   eps_bearer_id;
  FTeid_t                 bearer_s1u_enb_fteid;
} itti_mme_app_path_switch_req_t;

typedef struct itti_mme_app_initial_context_setup_failure_s {
  uint32_t                mme_ue_s1ap_id;
} itti_mme_app_initial_context_setup_failure_t;

typedef struct itti_mme_app_delete_session_rsp_s {
  /* UE identifier */
  mme_ue_s1ap_id_t	  ue_id;
} itti_mme_app_delete_session_rsp_t;

typedef struct itti_mme_app_s1ap_mme_ue_id_notification_s {
  enb_ue_s1ap_id_t	    enb_ue_s1ap_id;
  mme_ue_s1ap_id_t	    mme_ue_s1ap_id;
  sctp_assoc_id_t       sctp_assoc_id;
} itti_mme_app_s1ap_mme_ue_id_notification_t;

// duplicate detection
typedef struct itti_mme_app_s1ap_initial_ue_message_duplicate_cnf_s {
  enb_ue_s1ap_id_t      old_enb_ue_s1ap_id;
  enb_ue_s1ap_id_t      new_enb_ue_s1ap_id;
  mme_ue_s1ap_id_t      mme_ue_s1ap_id;
  sctp_assoc_id_t       sctp_assoc_id;
  sctp_stream_id_t      stream_id;

  bool                  duplicate_detec;
  uint32_t              enb_id;
//  S1ap_InitialUEMessageIEs_t       *s1ap_InitialUEMessageIEs;
//  bool                  is_s_tmsi_valid;
//  as_stmsi_t            opt_s_tmsi;
//  tai_t                 tai;               /* Indicating the Tracking Area from which the UE has sent the NAS message.                         */
//  ecgi_t                cgi;               /* Indicating the Tracking Area from which the UE has sent the NAS message.                         */
//  uint8_t              *nas_msg;
//  size_t                nas_msg_length;

  tai_t               tai;               /* Indicating the Tracking Area from which the UE has sent the NAS message.                         */
  ecgi_t              cgi;
  as_cause_t          as_cause;          /* Establishment cause                     */
  as_stmsi_t          opt_s_tmsi;
  csg_id_t            opt_csg_id;
  gummei_t            opt_gummei;
  bstring             nas;
  bool                is_s_tmsi_valid;
  bool                is_csg_id_valid;
  bool                is_gummei_valid;
} itti_mme_app_s1ap_initial_ue_message_duplicate_cnf_t;


//// handover messages
//typedef struct itti_mme_app_path_switch_req_s {
//  uint32_t                mme_ue_s1ap_id;
//  ebi_t                   eps_bearer_id;
//  //FTeid_t                 bearer_s1u_enb_fteid;
//} itti_mme_app_path_switch_req_t;

#endif /* FILE_MME_APP_MESSAGES_TYPES_SEEN */
