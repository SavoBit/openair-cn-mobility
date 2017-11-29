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



#ifndef FILE_S1AP_MME_NAS_PROCEDURES_SEEN
#define FILE_S1AP_MME_NAS_PROCEDURES_SEEN
#include <stdint.h>

#include "common_defs.h"
#include "bstrlib.h"
#include "s1ap_ies_defs.h"
#include "intertask_interface.h"

/** \brief Handle an Initial UE message.
 * \param assocId lower layer assoc id (SCTP)
 * \param stream SCTP stream on which data had been received
 * \param message The message as decoded by the ASN.1 codec
 * @returns -1 on failure, 0 otherwise
 **/
int s1ap_mme_handle_initial_ue_message(const sctp_assoc_id_t assocId,
                                       const sctp_stream_id_t stream,
                                       struct s1ap_message_s *message);

/**
 * Message to process duplicate confirmation --> removal of the duplicate s1ap ue reference and continuing with the initial UE message.
 * todo: use signal saving instead..
 */
int
s1ap_mme_handle_initial_ue_message_duplicate_cnf (
    const itti_mme_app_s1ap_initial_ue_message_duplicate_cnf_t * const initial_ue_message_duplicate_cnf_p);

/** \brief Handle an Uplink NAS transport message.
 * Process the RRC transparent container and forward it to NAS entity.
 * \param assocId lower layer assoc id (SCTP)
 * \param stream SCTP stream on which data had been received
 * \param message The message as decoded by the ASN.1 codec
 * @returns -1 on failure, 0 otherwise
 **/
int s1ap_mme_handle_uplink_nas_transport(const sctp_assoc_id_t assocId,
                                         const sctp_stream_id_t stream,
                                         struct s1ap_message_s *message);

/** \brief Handle a NAS non delivery indication message from eNB
 * \param assocId lower layer assoc id (SCTP)
 * \param stream SCTP stream on which data had been received
 * \param message The message as decoded by the ASN.1 codec
 * @returns -1 on failure, 0 otherwise
 **/
int s1ap_mme_handle_nas_non_delivery(const sctp_assoc_id_t assocId,
                                     const sctp_stream_id_t stream,
                                     struct s1ap_message_s *message);

void s1ap_handle_conn_est_cnf(const itti_mme_app_connection_establishment_cnf_t * const conn_est_cnf_p);

//void s1ap_handle_handover_cnf(const itti_mme_app_handover_cnf_t * const handover_cnf_p);
void s1ap_handle_handover_cnf(const itti_mme_app_handover_cnf_t * const handover_cnf_pP);

//void s1ap_handle_bearer_modification_res (const itti_mme_app_bearer_modification_rsp_t * const bearer_modification_res_pP);
//void s1ap_handle_bearer_modification_fail (const itti_mme_app_bearer_modification_fail_t * const bearer_modification_fail_pP);

int s1ap_generate_downlink_nas_transport (
  const enb_ue_s1ap_id_t enb_ue_s1ap_id,
  const mme_ue_s1ap_id_t ue_id,
  STOLEN_REF bstring *payload);

void
s1ap_handle_mme_ue_id_notification (
  const itti_mme_app_s1ap_mme_ue_id_notification_t * const notification_p);

#endif /* FILE_S1AP_MME_NAS_PROCEDURES_SEEN */
