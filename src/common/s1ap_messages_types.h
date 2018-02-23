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
#ifndef FILE_S1AP_MESSAGES_TYPES_SEEN
#define FILE_S1AP_MESSAGES_TYPES_SEEN


#include "../mme/mme_ie_defs.h"
#include "../nas/securityDef.h"  /* UE lower layer identifier   */

//#include "nas_messages_types.h"
#include "s1ap_common.h"


#define S1AP_ENB_DEREGISTERED_IND(mSGpTR)   (mSGpTR)->ittiMsg.s1ap_eNB_deregistered_ind
#define S1AP_DEREGISTER_UE_REQ(mSGpTR)      (mSGpTR)->ittiMsg.s1ap_deregister_ue_req
#define S1AP_UE_CONTEXT_RELEASE_REQ(mSGpTR) (mSGpTR)->ittiMsg.s1ap_ue_context_release_req
#define S1AP_UE_CONTEXT_RELEASE_COMMAND(mSGpTR) (mSGpTR)->ittiMsg.s1ap_ue_context_release_command
#define S1AP_UE_CONTEXT_RELEASE_COMPLETE(mSGpTR) (mSGpTR)->ittiMsg.s1ap_ue_context_release_complete
#define S1AP_NAS_DL_DATA_REQ(mSGpTR)        (mSGpTR)->ittiMsg.s1ap_nas_dl_data_req
#define S1AP_ENB_INITIATED_RESET_REQ(mSGpTR) (mSGpTR)->ittiMsg.s1ap_enb_initiated_reset_req
#define S1AP_ENB_INITIATED_RESET_ACK(mSGpTR) (mSGpTR)->ittiMsg.s1ap_enb_initiated_reset_ack

// handover messages from NAS to MME_APP to S1AP
#define S1AP_HANDOVER_CNF(mSGpTR)                     (mSGpTR)->ittiMsg.s1ap_handover_cnf
#define S1AP_HANDOVER_REJ(mSGpTR)                     (mSGpTR)->ittiMsg.s1ap_handover_rej
/** eNB/MME status transfer. */
#define S1AP_ENB_STATUS_TRANSFER(mSGpTR)              (mSGpTR)->ittiMsg.s1ap_enb_status_transfer
#define S1AP_MME_STATUS_TRANSFER(mSGpTR)              (mSGpTR)->ittiMsg.s1ap_mme_status_transfer
/** Handover Notify. */
#define S1AP_HANDOVER_NOTIFY(mSGpTR)                  (mSGpTR)->ittiMsg.s1ap_handover_notify

/** Handover Required, Preparation Failure, Cancel (source eNB side). */
#define S1AP_HANDOVER_REQUIRED(mSGpTR)                (mSGpTR)->ittiMsg.s1ap_handover_required
#define S1AP_HANDOVER_PREPARATION_FAILURE(mSGpTR)     (mSGpTR)->ittiMsg.s1ap_handover_preparation_failure
#define S1AP_HANDOVER_CANCEL(mSGpTR)                  (mSGpTR)->ittiMsg.s1ap_handover_cancel
#define S1AP_HANDOVER_CANCEL_ACKNOWLEDGE(mSGpTR)      (mSGpTR)->ittiMsg.s1ap_handover_cancel_acknowledge

/** Handover Request. */
#define S1AP_HANDOVER_REQUEST(mSGpTR)                 (mSGpTR)->ittiMsg.s1ap_handover_request
/** Handover Command. */
#define S1AP_HANDOVER_COMMAND(mSGpTR)                 (mSGpTR)->ittiMsg.s1ap_handover_command

/** Handover RequestAcknowledge/Failure. */
#define S1AP_HANDOVER_REQUEST_ACKNOWLEDGE(mSGpTR)     (mSGpTR)->ittiMsg.s1ap_handover_request_acknowledge
#define S1AP_HANDOVER_FAILURE(mSGpTR)                 (mSGpTR)->ittiMsg.s1ap_handover_failure

/** S1AP Paging. */
#define S1AP_PAGING(mSGpTR)                           (mSGpTR)->ittiMsg.s1ap_paging

typedef struct itti_s1ap_initial_ue_message_s {
  mme_ue_s1ap_id_t     mme_ue_s1ap_id;
  enb_ue_s1ap_id_t     enb_ue_s1ap_id:24;
  ecgi_t                e_utran_cgi;
} itti_s1ap_initial_ue_message_t;

typedef struct itti_s1ap_handover_s {
  mme_ue_s1ap_id_t     mme_ue_s1ap_id;
  enb_ue_s1ap_id_t     enb_ue_s1ap_id:24;
  ecgi_t                e_utran_cgi;
} itti_s1ap_handover_t;

typedef struct itti_s1ap_initial_ctxt_setup_req_s {
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  enb_ue_s1ap_id_t        enb_ue_s1ap_id:24;

  /* Key eNB */
  uint8_t                 kenb[32];

  ambr_t                  ambr;
  ambr_t                  apn_ambr;

  /* EPS bearer ID */
  unsigned                ebi:4;

  /* QoS */
  qci_t                   qci;
  priority_level_t        prio_level;
  pre_emp_vulnerability_t pre_emp_vulnerability;
  pre_emp_capability_t    pre_emp_capability;

  /* S-GW TEID for user-plane */
  teid_t                  teid;
  /* S-GW IP address for User-Plane */
  ip_address_t            s_gw_address;
} itti_s1ap_initial_ctxt_setup_req_t;

typedef struct itti_s1ap_ue_cap_ind_s {
  mme_ue_s1ap_id_t  mme_ue_s1ap_id;
  enb_ue_s1ap_id_t  enb_ue_s1ap_id:24;
  uint8_t           *radio_capabilities;
  size_t            radio_capabilities_length;
} itti_s1ap_ue_cap_ind_t;

#define S1AP_ITTI_UE_PER_DEREGISTER_MESSAGE 128
typedef struct itti_s1ap_eNB_deregistered_ind_s {
  uint8_t          nb_ue_to_deregister;
  enb_ue_s1ap_id_t enb_ue_s1ap_id[S1AP_ITTI_UE_PER_DEREGISTER_MESSAGE];
  mme_ue_s1ap_id_t mme_ue_s1ap_id[S1AP_ITTI_UE_PER_DEREGISTER_MESSAGE];
  uint32_t         enb_id;
} itti_s1ap_eNB_deregistered_ind_t;

typedef struct itti_s1ap_deregister_ue_req_s {
  mme_ue_s1ap_id_t mme_ue_s1ap_id;
} itti_s1ap_deregister_ue_req_t;

typedef struct itti_s1ap_ue_context_release_req_s {
  mme_ue_s1ap_id_t  mme_ue_s1ap_id;
  enb_ue_s1ap_id_t  enb_ue_s1ap_id:24;
  uint32_t         enb_id;
} itti_s1ap_ue_context_release_req_t;

typedef enum s1ap_reset_type_e {
  RESET_ALL = 0,
  RESET_PARTIAL
} s1ap_reset_type_t;

typedef struct s1_sig_conn_id_s {
  mme_ue_s1ap_id_t*  mme_ue_s1ap_id;
  enb_ue_s1ap_id_t*  enb_ue_s1ap_id;
} s1_sig_conn_id_t;

typedef struct itti_s1ap_enb_initiated_reset_req_s {
  uint32_t          sctp_assoc_id;
  uint16_t          sctp_stream_id;
  uint32_t          enb_id;
  s1ap_reset_type_t  s1ap_reset_type;
  uint32_t          num_ue;
  s1_sig_conn_id_t  *ue_to_reset_list;
} itti_s1ap_enb_initiated_reset_req_t;

typedef struct itti_s1ap_enb_initiated_reset_ack_s {
  uint32_t          sctp_assoc_id;
  uint16_t          sctp_stream_id;
  s1ap_reset_type_t  s1ap_reset_type;
  uint32_t          num_ue;
  s1_sig_conn_id_t  *ue_to_reset_list;
} itti_s1ap_enb_initiated_reset_ack_t;

// List of possible causes for MME generated UE context release command towards eNB
enum s1cause {
  S1AP_INVALID_CAUSE = 0,
  S1AP_NAS_NORMAL_RELEASE,
  S1AP_NAS_DETACH,
  S1AP_RADIO_EUTRAN_GENERATED_REASON,
  S1AP_IMPLICIT_CONTEXT_RELEASE,
  S1AP_INITIAL_CONTEXT_SETUP_FAILED,
  S1AP_SCTP_SHUTDOWN_OR_RESET,

  S1AP_HANDOVER_CANCELLED,
  S1AP_HANDOVER_FAILED,
  S1AP_NETWORK_ERROR,
  S1AP_SYSTEM_FAILURE,

  // todo: not sure if this is the correct
  S1AP_SUCCESSFUL_HANDOVER
};
typedef struct itti_s1ap_ue_context_release_command_s {
  mme_ue_s1ap_id_t  mme_ue_s1ap_id;
  enb_ue_s1ap_id_t  enb_ue_s1ap_id:24;
  enum s1cause      cause;
} itti_s1ap_ue_context_release_command_t;

typedef struct itti_s1ap_dl_nas_data_req_s {
  mme_ue_s1ap_id_t  mme_ue_s1ap_id;
  enb_ue_s1ap_id_t  enb_ue_s1ap_id:24;
  bstring           nas_msg;            /* Downlink NAS message             */
} itti_s1ap_nas_dl_data_req_t;

typedef struct itti_s1ap_ue_context_release_complete_s {
  mme_ue_s1ap_id_t  mme_ue_s1ap_id;
  enb_ue_s1ap_id_t  enb_ue_s1ap_id:24;
  uint32_t          enb_id;
  uint32_t          sctp_assoc_id;
} itti_s1ap_ue_context_release_complete_t;

// handover messaging
typedef struct itti_s1ap_path_switch_req_s {
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  enb_ue_s1ap_id_t        enb_ue_s1ap_id:24;

//  /* Key eNB */
//  uint8_t                 kenb[32];
//
//  ambr_t                  ambr;
//  ambr_t                  apn_ambr;
//
//  /* EPS bearer ID */
//  unsigned                ebi:4;
//
//  /* QoS */
//  qci_t                   qci;
//  priority_level_t        prio_level;
//  pre_emp_vulnerability_t pre_emp_vulnerability;
//  pre_emp_capability_t    pre_emp_capability;
//
//  /* S-GW TEID for user-plane */
//  teid_t                  teid;
//  /* S-GW IP address for User-Plane */
//  ip_address_t            s_gw_address;
} itti_s1ap_path_switch_req_t;

/** Handover Confirmation and Request messages sent from MME_APP to S1AP layer. */
// HANDOVER MESSAGE SENT FROM MME_APP to S1AP after processing and validating in NAS todo: reject
typedef struct itti_s1ap_handover_cnf_s {
  ebi_t                   eps_bearer_id;
  FTeid_t                 bearer_s1u_sgw_fteid;
  mme_ue_s1ap_id_t        ue_id;            /* UE lower layer identifier   */

  /* Key eNB */
  uint8_t                 nh[AUTH_NH_SIZE];
  uint8_t                 ncc:3;

  uint16_t                security_capabilities_encryption_algorithms;
  uint16_t                security_capabilities_integrity_algorithms;
} itti_s1ap_handover_cnf_t;

typedef struct itti_s1ap_handover_rej_s {
  mme_ue_s1ap_id_t        ue_id;            /* UE lower layer identifier   */
} itti_s1ap_handover_rej_t;

typedef struct itti_s1ap_handover_required_s {
  uint32_t                mme_ue_s1ap_id;
  uint32_t                enb_ue_s1ap_id;
  sctp_assoc_id_t         sctp_assoc_id;
  /** Target Id. */
  tai_t                   selected_tai;
  ecgi_t                  global_enb_id;
  /** Cause. */
  S1ap_Cause_PR           f_cause_type;
  long                    f_cause_value;

  /** Source-To-Target Transparent Container. */
  // todo: if this is an buffer, how is it freed? does everything needs to be stacked
  bstring                 eutran_source_to_target_container;
} itti_s1ap_handover_required_t;

typedef struct itti_s1ap_handover_command_s {
  ebi_t                   eps_bearer_id;

  /** Since no inner NAS structure is present (message does not travel NAS layer) set the UE_IDs manually. */
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  enb_ue_s1ap_id_t        enb_ue_s1ap_id:24;

  uint32_t                enb_id;
  /** F-Container. */
  bstring                 eutran_target_to_source_container;

  // todo: handover type will always be set as intra_lte in s1ap layer..

//  itti_nas_handover_tau_cnf_t         nas_handover_tau_cnf; /**< Original message sent by NAS after validation. */
  // todo: add the enb_ue_s1ap_id and the mme_ue_s1ap_id.. No
} itti_s1ap_handover_command_t;

typedef struct bearer_ctx_to_be_setup_list_s {
  uint8_t n_bearers;
  bearer_context_t **bearer_ctx;
}bearer_ctx_to_be_setup_list_t;


typedef struct itti_s1ap_handover_request_s {
//  ebi_t                   eps_bearer_id;
//  FTeid_t                 bearer_s1u_sgw_fteid;
  mme_ue_s1ap_id_t        ue_id;            /* UE lower layer identifier   */

  /* Key eNB */
  uint8_t                 nh[AUTH_NH_SIZE];
  uint8_t                 ncc:3;

  uint16_t                security_capabilities_encryption_algorithms;
  uint16_t                security_capabilities_integrity_algorithms;

  /** UE AMBR. */
  ambr_t                          ambr;
  /** Bearer Contexts to be Setup List. */
  bearer_ctx_to_be_setup_list_t   bearer_ctx_to_be_setup_list;

//  /** Bearer Level QoS. */
//  qci_t                           bearer_qos_qci;
//  priority_level_t                bearer_qos_prio_level;
//  pre_emp_vulnerability_t         bearer_qos_pre_emp_vulnerability;
//  pre_emp_capability_t            bearer_qos_pre_emp_capability;

  /** F-Container. */
  bstring                   source_to_target_eutran_container;
  /** Target Id. */
//  tai_t                           target_tai;
  unsigned                        macro_enb_id:20;    /* Macro-Enb-Id.                        */
} itti_s1ap_handover_request_t;

/** Handover Request Acknowledge. */
typedef struct itti_s1ap_handover_request_acknowledge_s {
  uint32_t                mme_ue_s1ap_id;
  uint32_t                enb_ue_s1ap_id;
//  sctp_assoc_id_t         sctp_assoc_id;
//  sctp_stream_id_t        sctp_stream;
  ebi_t                   eps_bearer_id;
  FTeid_t                 bearer_s1u_enb_fteid;
  bstring                 target_to_source_eutran_container; /**< Target-ToSource Transparent Container. */
} itti_s1ap_handover_request_acknowledge_t;

/** Handover Failure. */
typedef struct itti_s1ap_handover_failure_s {
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  enb_ue_s1ap_id_t        enb_ue_s1ap_id:24;
  uint32_t                enb_id;
  sctp_assoc_id_t         assoc_id;
  enum s1cause            cause;
} itti_s1ap_handover_failure_t;

/** Handover Preparation Failure. */
typedef struct itti_s1ap_handover_preparation_failure_s {
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  enb_ue_s1ap_id_t        enb_ue_s1ap_id:24;
  sctp_assoc_id_t         assoc_id;
  enum s1cause            cause;
} itti_s1ap_handover_preparation_failure_t;

/** Handover Cancel. */
typedef struct itti_s1ap_handover_cancel_s {
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  enb_ue_s1ap_id_t        enb_ue_s1ap_id:24;
  sctp_assoc_id_t         assoc_id;
  uint32_t                enb_id;
} itti_s1ap_handover_cancel_t;

/** Handover Cancel Acknowledge. */
typedef struct itti_s1ap_handover_cancel_acknowledge_s {
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  enb_ue_s1ap_id_t        enb_ue_s1ap_id:24;
  sctp_assoc_id_t         assoc_id;
  uint32_t                enb_id;
} itti_s1ap_handover_cancel_acknowledge_t;

/** S1AP ENB/MME Status Transfer. */
typedef struct itti_s1ap_status_transfer_s {
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  enb_ue_s1ap_id_t        enb_ue_s1ap_id:24;
  /** F-Container. */
  bstring                 bearerStatusTransferList_buffer; /**< Target-ToSource Transparent Container. */

} itti_s1ap_status_transfer_t;

typedef struct itti_s1ap_handover_notify_s {
  uint32_t                mme_ue_s1ap_id;
  uint32_t                enb_ue_s1ap_id;
  sctp_assoc_id_t         assoc_id;

  tai_t                   tai;               /* Indicating the Tracking Area from which the UE has sent the NAS message.                         */
  ecgi_t                  cgi;

//  sctp_assoc_id_t         sctp_assoc_id;
//  sctp_stream_id_t        sctp_stream;
} itti_s1ap_handover_notify_t;

typedef struct itti_s1ap_paging_s {
  mme_ue_s1ap_id_t        mme_ue_s1ap_id;
  uint32_t                ue_identity_index;
  tmsi_t                  tmsi;

  tai_t                   tai;               /* Indicating the Tracking Area from which the UE has sent the NAS message.                         */

} itti_s1ap_paging_t;

#endif /* FILE_S1AP_MESSAGES_TYPES_SEEN */
