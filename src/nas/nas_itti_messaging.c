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

#include <string.h>
#include <ctype.h>

#include "conversions.h"
#include "dynamic_memory_check.h"
#include "intertask_interface.h"
#include "msc.h"
#include "mme_app_ue_context.h"
#include "nas_itti_messaging.h"
#include "nas_proc.h"
#include "secu_defs.h"

#define TASK_ORIGIN  TASK_NAS_MME

//   Timer handler
static void * _s6a_auth_info_rsp_timer_expiry_handler (void *);

static const uint8_t                    emm_message_ids[] = {
  ATTACH_REQUEST,
  ATTACH_ACCEPT,
  ATTACH_COMPLETE,
  ATTACH_REJECT,
  DETACH_REQUEST,
  DETACH_ACCEPT,
  TRACKING_AREA_UPDATE_REQUEST,
  TRACKING_AREA_UPDATE_ACCEPT,
  TRACKING_AREA_UPDATE_COMPLETE,
  TRACKING_AREA_UPDATE_REJECT,
  EXTENDED_SERVICE_REQUEST,
  SERVICE_REQUEST,
  SERVICE_REJECT,
  GUTI_REALLOCATION_COMMAND,
  GUTI_REALLOCATION_COMPLETE,
  AUTHENTICATION_REQUEST,
  AUTHENTICATION_RESPONSE,
  AUTHENTICATION_REJECT,
  AUTHENTICATION_FAILURE,
  IDENTITY_REQUEST,
  IDENTITY_RESPONSE,
  SECURITY_MODE_COMMAND,
  SECURITY_MODE_COMPLETE,
  SECURITY_MODE_REJECT,
  EMM_STATUS,
  EMM_INFORMATION,
  DOWNLINK_NAS_TRANSPORT,
  UPLINK_NAS_TRANSPORT,
  CS_SERVICE_NOTIFICATION,
};

static const uint8_t                    esm_message_ids[] = {
  ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST,
  ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT,
  ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT,
  ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST,
  ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT,
  ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT,
  MODIFY_EPS_BEARER_CONTEXT_REQUEST,
  MODIFY_EPS_BEARER_CONTEXT_ACCEPT,
  MODIFY_EPS_BEARER_CONTEXT_REJECT,
  DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST,
  DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT,
  PDN_CONNECTIVITY_REQUEST,
  PDN_CONNECTIVITY_REJECT,
  PDN_DISCONNECT_REQUEST,
  PDN_DISCONNECT_REJECT,
  BEARER_RESOURCE_ALLOCATION_REQUEST,
  BEARER_RESOURCE_ALLOCATION_REJECT,
  BEARER_RESOURCE_MODIFICATION_REQUEST,
  BEARER_RESOURCE_MODIFICATION_REJECT,
  ESM_INFORMATION_REQUEST,
  ESM_INFORMATION_RESPONSE,
  ESM_STATUS,
};

//------------------------------------------------------------------------------
static int
_nas_find_message_index (
  const uint8_t message_id,
  const uint8_t * message_ids,
  const int ids_number)
{
  int                                     i;

  for (i = 0; i < ids_number; i++) {
    if (message_id == message_ids[i]) {
      return (2 + i);
    }
  }

  return (1);
}

int
nas_itti_plain_msg (
  const char *buffer,
  const nas_message_t * msg,
  const size_t          length,
  const bool            is_down_link)
{
  MessageDef                             *message_p = NULL;
  int                                     data_length = length < NAS_DATA_LENGHT_MAX ? length : NAS_DATA_LENGHT_MAX;
  int                                     message_type = -1;
  MessagesIds                             messageId_raw = -1;
  MessagesIds                             messageId_plain = -1;

  /*
   * Define message ids
   */
  if (msg->header.protocol_discriminator == EPS_MOBILITY_MANAGEMENT_MESSAGE) {
    message_type = 0;
    messageId_raw = is_down_link ? NAS_DL_EMM_RAW_MSG : NAS_UL_EMM_RAW_MSG;
    messageId_plain = is_down_link ? NAS_DL_EMM_PLAIN_MSG : NAS_UL_EMM_PLAIN_MSG;
  } else {
    if (msg->header.protocol_discriminator == EPS_SESSION_MANAGEMENT_MESSAGE) {
      message_type = 1;
      messageId_raw = is_down_link ? NAS_DL_ESM_RAW_MSG : NAS_UL_ESM_RAW_MSG;
      messageId_plain = is_down_link ? NAS_DL_ESM_PLAIN_MSG : NAS_UL_ESM_PLAIN_MSG;
    }
  }

  if (message_type >= 0) {
    /*
     * Create and send the RAW message
     */
    message_p = itti_alloc_new_message (TASK_ORIGIN, messageId_raw);
    NAS_DL_EMM_RAW_MSG (message_p).length = length;
    memset ((void *)&(NAS_DL_EMM_RAW_MSG (message_p).data), 0, NAS_DATA_LENGHT_MAX);
    memcpy ((void *)&(NAS_DL_EMM_RAW_MSG (message_p).data), buffer, data_length);
    itti_send_msg_to_task (TASK_UNKNOWN, INSTANCE_DEFAULT, message_p);

    /*
     * Create and send the plain message
     */
    if (message_type == 0) {
      message_p = itti_alloc_new_message (TASK_ORIGIN, messageId_plain);
      NAS_DL_EMM_PLAIN_MSG (message_p).present = _nas_find_message_index (msg->plain.emm.header.message_type, emm_message_ids, sizeof (emm_message_ids) / sizeof (emm_message_ids[0]));
      memcpy ((void *)&(NAS_DL_EMM_PLAIN_MSG (message_p).choice), &msg->plain.emm, sizeof (EMM_msg));
    } else {
      message_p = itti_alloc_new_message (TASK_ORIGIN, messageId_plain);
      NAS_DL_ESM_PLAIN_MSG (message_p).present = _nas_find_message_index (msg->plain.esm.header.message_type, esm_message_ids, sizeof (esm_message_ids) / sizeof (esm_message_ids[0]));
      memcpy ((void *)&(NAS_DL_ESM_PLAIN_MSG (message_p).choice), &msg->plain.esm, sizeof (ESM_msg));
    }

    return itti_send_msg_to_task (TASK_UNKNOWN, INSTANCE_DEFAULT, message_p);
  }

  return EXIT_FAILURE;
}

//------------------------------------------------------------------------------
int
nas_itti_protected_msg (
  const char          *buffer,
  const nas_message_t *msg,
  const size_t         length,
  const bool           is_down_link)
{
  MessageDef                             *message_p = NULL;

  if (msg->header.protocol_discriminator == EPS_MOBILITY_MANAGEMENT_MESSAGE) {
    message_p = itti_alloc_new_message (TASK_ORIGIN, is_down_link ? NAS_DL_EMM_PROTECTED_MSG : NAS_UL_EMM_PROTECTED_MSG);
    memcpy ((void *)&(NAS_DL_EMM_PROTECTED_MSG (message_p).header), &msg->header, sizeof (nas_message_security_header_t));
    NAS_DL_EMM_PROTECTED_MSG (message_p).present = _nas_find_message_index (msg->security_protected.plain.emm.header.message_type, emm_message_ids, sizeof (emm_message_ids) / sizeof (emm_message_ids[0]));
    memcpy ((void *)&(NAS_DL_EMM_PROTECTED_MSG (message_p).choice), &msg->security_protected.plain.emm, sizeof (EMM_msg));
  } else {
    if (msg->header.protocol_discriminator == EPS_SESSION_MANAGEMENT_MESSAGE) {
      message_p = itti_alloc_new_message (TASK_ORIGIN, is_down_link ? NAS_DL_ESM_PROTECTED_MSG : NAS_UL_ESM_PROTECTED_MSG);
      memcpy ((void *)&(NAS_DL_ESM_PROTECTED_MSG (message_p).header), &msg->header, sizeof (nas_message_security_header_t));
      NAS_DL_ESM_PROTECTED_MSG (message_p).present = _nas_find_message_index (msg->security_protected.plain.esm.header.message_type, esm_message_ids, sizeof (esm_message_ids) / sizeof (esm_message_ids[0]));
      memcpy ((void *)&(NAS_DL_ESM_PROTECTED_MSG (message_p).choice), &msg->security_protected.plain.esm, sizeof (ESM_msg));
    }
  }

  if (message_p ) {
    return itti_send_msg_to_task (TASK_UNKNOWN, INSTANCE_DEFAULT, message_p);
  }

  return EXIT_FAILURE;
}

//------------------------------------------------------------------------------
int
nas_itti_dl_data_req (
  const mme_ue_s1ap_id_t ue_id,
  bstring                nas_msg,
  nas_error_code_t transaction_status
  )
{
  MessageDef  *message_p = itti_alloc_new_message (TASK_NAS_MME, NAS_DOWNLINK_DATA_REQ);
  NAS_DL_DATA_REQ (message_p).ue_id   = ue_id;
  NAS_DL_DATA_REQ (message_p).nas_msg = nas_msg;
  nas_msg = NULL;
  NAS_DL_DATA_REQ (message_p).transaction_status = transaction_status;
  MSC_LOG_TX_MESSAGE (MSC_NAS_MME, MSC_S1AP_MME, NULL, 0, "0 NAS_DOWNLINK_DATA_REQ ue id " MME_UE_S1AP_ID_FMT " len %u", ue_id, blength(nas_msg));
  // make a long way by MME_APP instead of S1AP to retrieve the sctp_association_id key.
  return itti_send_msg_to_task (TASK_MME_APP, INSTANCE_DEFAULT, message_p);
}

//------------------------------------------------------------------------------
void nas_itti_pdn_connectivity_req(
  int                     ptiP,
  unsigned int            ue_idP,
  const imsi_t           *const imsi_pP,
  esm_proc_data_t        *proc_data_pP,
  esm_proc_pdn_request_t  request_typeP)
{
  OAILOG_FUNC_IN(LOG_NAS);
  MessageDef *message_p = NULL;

  AssertFatal(imsi_pP       != NULL, "imsi_pP param is NULL");
  AssertFatal(proc_data_pP  != NULL, "proc_data_pP param is NULL");


  message_p = itti_alloc_new_message(TASK_NAS_MME, NAS_PDN_CONNECTIVITY_REQ);
  memset(&message_p->ittiMsg.nas_pdn_connectivity_req,
         0,
         sizeof(itti_nas_pdn_connectivity_req_t));

  hexa_to_ascii((uint8_t *)imsi_pP->u.value,
                NAS_PDN_CONNECTIVITY_REQ(message_p).imsi,
                8);

  NAS_PDN_CONNECTIVITY_REQ(message_p).pti             = ptiP;
  NAS_PDN_CONNECTIVITY_REQ(message_p).ue_id           = ue_idP;
  NAS_PDN_CONNECTIVITY_REQ(message_p).imsi[15]        = '\0';

  if (isdigit(NAS_PDN_CONNECTIVITY_REQ(message_p).imsi[14])) {
    NAS_PDN_CONNECTIVITY_REQ(message_p).imsi_length = 15;
  } else {
    NAS_PDN_CONNECTIVITY_REQ(message_p).imsi_length = 14;
    NAS_PDN_CONNECTIVITY_REQ(message_p).imsi[14] = '\0';
  }

  bassign(NAS_PDN_CONNECTIVITY_REQ(message_p).apn, proc_data_pP->apn);
  bassign(NAS_PDN_CONNECTIVITY_REQ(message_p).pdn_addr, proc_data_pP->pdn_addr);

  switch (proc_data_pP->pdn_type) {
  case ESM_PDN_TYPE_IPV4:
    NAS_PDN_CONNECTIVITY_REQ(message_p).pdn_type = IPv4;
    break;

  case ESM_PDN_TYPE_IPV6:
    NAS_PDN_CONNECTIVITY_REQ(message_p).pdn_type = IPv6;
    break;

  case ESM_PDN_TYPE_IPV4V6:
    NAS_PDN_CONNECTIVITY_REQ(message_p).pdn_type = IPv4_AND_v6;
    break;

  default:
    NAS_PDN_CONNECTIVITY_REQ(message_p).pdn_type = IPv4;
    break;
  }

  // not efficient but be careful about "typedef network_qos_t esm_proc_qos_t;"
  NAS_PDN_CONNECTIVITY_REQ(message_p).qos.gbrUL = proc_data_pP->qos.gbrUL;
  NAS_PDN_CONNECTIVITY_REQ(message_p).qos.gbrDL = proc_data_pP->qos.gbrDL;
  NAS_PDN_CONNECTIVITY_REQ(message_p).qos.mbrUL = proc_data_pP->qos.mbrUL;
  NAS_PDN_CONNECTIVITY_REQ(message_p).qos.mbrDL = proc_data_pP->qos.mbrDL;
  NAS_PDN_CONNECTIVITY_REQ(message_p).qos.qci   = proc_data_pP->qos.qci;

  NAS_PDN_CONNECTIVITY_REQ(message_p).proc_data = proc_data_pP;

  NAS_PDN_CONNECTIVITY_REQ(message_p).request_type  = request_typeP;

  copy_protocol_configuration_options (&NAS_PDN_CONNECTIVITY_REQ(message_p).pco, &proc_data_pP->pco);

  MSC_LOG_TX_MESSAGE(
        MSC_NAS_MME,
        MSC_MMEAPP_MME,
        NULL,0,
        "NAS_PDN_CONNECTIVITY_REQ ue id %06"PRIX32" IMSI %X",
        ue_idP, NAS_PDN_CONNECTIVITY_REQ(message_p).imsi);

  itti_send_msg_to_task(TASK_MME_APP, INSTANCE_DEFAULT, message_p);

  OAILOG_FUNC_OUT(LOG_NAS);
}

//------------------------------------------------------------------------------
void nas_itti_auth_info_req(
  const uint32_t        ue_idP,
  const imsi64_t        imsi64_P,
  const bool            is_initial_reqP,
  plmn_t        * const visited_plmnP,
  const uint8_t         num_vectorsP,
  const_bstring const auts_pP)
{
  OAILOG_FUNC_IN(LOG_NAS);
  MessageDef                             *message_p = NULL;
  s6a_auth_info_req_t                    *auth_info_req = NULL;
  struct emm_data_context_s              *emm_ctx = NULL;
  s6a_auth_info_rsp_timer_arg_t          *timer_arg = NULL;

  message_p = itti_alloc_new_message (TASK_NAS_MME, S6A_AUTH_INFO_REQ);
  auth_info_req = &message_p->ittiMsg.s6a_auth_info_req;
  memset(auth_info_req, 0, sizeof(s6a_auth_info_req_t));

  auth_info_req->imsi_length =
      snprintf (auth_info_req->imsi, IMSI_BCD_DIGITS_MAX+1, IMSI_64_FMT, imsi64_P);

  AssertFatal((15 == auth_info_req->imsi_length)|| (14 == auth_info_req->imsi_length),
      "Bad IMSI length %d", auth_info_req->imsi_length);

  auth_info_req->visited_plmn  = *visited_plmnP;
  auth_info_req->nb_of_vectors = num_vectorsP;

  if (is_initial_reqP ) {
    auth_info_req->re_synchronization = 0;
    memset (auth_info_req->resync_param, 0, sizeof auth_info_req->resync_param);
  } else {
    AssertFatal(auts_pP != NULL, "Autn Null during resynchronization");
    auth_info_req->re_synchronization = 1;
    memcpy (auth_info_req->resync_param, auts_pP->data, sizeof auth_info_req->resync_param);
  }

  MSC_LOG_TX_MESSAGE (MSC_NAS_MME, MSC_S6A_MME, NULL, 0, "0 S6A_AUTH_INFO_REQ IMSI "IMSI_64_FMT" visited_plmn "PLMN_FMT" re_sync %u",
      imsi64_P, PLMN_ARG(visited_plmnP), auth_info_req->re_synchronization);
  itti_send_msg_to_task (TASK_S6A, INSTANCE_DEFAULT, message_p);

  //Start timer to wait for Auth Info Response 
  emm_ctx = emm_data_context_get (&_emm_data, ue_idP);
  DevAssert (emm_ctx);
  
  timer_arg = (s6a_auth_info_rsp_timer_arg_t *) calloc (1, sizeof (s6a_auth_info_rsp_timer_arg_t));
  DevAssert (timer_arg);
  emm_ctx->timer_s6a_auth_info_rsp_arg = (void*) timer_arg; 
  timer_arg->ue_id = emm_ctx->ue_id;
  timer_arg->resync = (auth_info_req->re_synchronization == 1) ? true : false;

  emm_ctx->timer_s6a_auth_info_rsp.id = nas_timer_start (emm_ctx->timer_s6a_auth_info_rsp.sec, _s6a_auth_info_rsp_timer_expiry_handler, timer_arg); 
  
  OAILOG_DEBUG (LOG_NAS_EMM, "EMM-PROC  - Timer timer_s6_auth_info_rsp (%d) started in for UE  " MME_UE_S1AP_ID_FMT " \n ", emm_ctx->timer_s6a_auth_info_rsp.id, timer_arg->ue_id);
  
  OAILOG_FUNC_OUT(LOG_NAS);
}

//------------------------------------------------------------------------------
void nas_itti_establish_rej(
  const uint32_t      ue_idP,
  const imsi_t *const imsi_pP
  , uint8_t           initial_reqP)
{
  OAILOG_FUNC_IN(LOG_NAS);
  MessageDef *message_p;

  message_p = itti_alloc_new_message(TASK_NAS_MME, NAS_AUTHENTICATION_PARAM_REQ);
  memset(&message_p->ittiMsg.nas_auth_param_req,
         0,
         sizeof(itti_nas_auth_param_req_t));

  hexa_to_ascii((uint8_t *)imsi_pP->u.value,
                NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi, 8);

  NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi[15] = '\0';

  if (isdigit(NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi[14])) {
    NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi_length = 15;
  } else {
    NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi_length = 14;
    NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi[14]    = '\0';
  }

  NAS_AUTHENTICATION_PARAM_REQ(message_p).initial_req = initial_reqP;
  NAS_AUTHENTICATION_PARAM_REQ(message_p).ue_id       = ue_idP;

  MSC_LOG_TX_MESSAGE(
        MSC_NAS_MME,
        MSC_MMEAPP_MME,
        NULL,0,
        "NAS_AUTHENTICATION_PARAM_REQ ue id %06"PRIX32" IMSI %s (establish reject)",
        ue_idP, NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi);

  itti_send_msg_to_task(TASK_MME_APP, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT(LOG_NAS);
}

//------------------------------------------------------------------------------
void nas_itti_establish_cnf(
  const uint32_t         ue_idP,
  const nas_error_code_t error_codeP,
  bstring                msgP,
  const uint16_t         selected_encryption_algorithmP,
  const uint16_t         selected_integrity_algorithmP)
{
  OAILOG_FUNC_IN(LOG_NAS);
  MessageDef                             *message_p        = NULL;
  emm_data_context_t                     *emm_ctx = emm_data_context_get (&_emm_data, ue_idP);

  if (emm_ctx) {

    message_p = itti_alloc_new_message(TASK_NAS_MME, NAS_CONNECTION_ESTABLISHMENT_CNF);
    memset(&message_p->ittiMsg.nas_conn_est_cnf, 0, sizeof(itti_nas_conn_est_cnf_t));
    NAS_CONNECTION_ESTABLISHMENT_CNF(message_p).ue_id                           = ue_idP;
    NAS_CONNECTION_ESTABLISHMENT_CNF(message_p).err_code                        = error_codeP;
    NAS_CONNECTION_ESTABLISHMENT_CNF(message_p).nas_msg                         = msgP; msgP = NULL;

    // According to 3GPP 9.2.1.40, the UE security capabilities are 16-bit
    // strings, EEA0 is inherently supported, so its support is not tracked in
    // the bit string. However, emm_ctx->eea is an 8-bit string with the highest
    // order bit representing EEA0 support, so we need to trim it. The same goes
    // for integrity.
    //
    // TODO: change the way the EEA and EIA are translated into the packets.
    //       Currently, the 16-bit string is 8-bit rotated to produce the string
    //       sent in the packets, which is why we're using bits 8-10 to
    //       represent EEA1/2/3 (and EIA1/2/3) support here.
    NAS_CONNECTION_ESTABLISHMENT_CNF(message_p)
      .encryption_algorithm_capabilities =
      ((uint16_t)emm_ctx->eea & ~(1 << 7)) << 1;
    NAS_CONNECTION_ESTABLISHMENT_CNF(message_p)
      .integrity_algorithm_capabilities =
      ((uint16_t)emm_ctx->eia & ~(1 << 7)) << 1;

    AssertFatal((0 <= emm_ctx->_security.vector_index) && (MAX_EPS_AUTH_VECTORS > emm_ctx->_security.vector_index),
        "Invalid vector index %d", emm_ctx->_security.vector_index);

    derive_keNB (emm_ctx->_vector[emm_ctx->_security.vector_index].kasme,
        emm_ctx->_security.ul_count.seq_num | (emm_ctx->_security.ul_count.overflow << 8),
        NAS_CONNECTION_ESTABLISHMENT_CNF(message_p).kenb);

    uint8_t                                 zero[32];
    memset(zero, 0, 32);
    memset(emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, 0, 32);

    OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - KENB @ INITIAL UE. \n");
     OAILOG_STREAM_HEX (OAILOG_LEVEL_DEBUG, LOG_NAS_EMM, "KENB :", NAS_CONNECTION_ESTABLISHMENT_CNF(message_p).kenb, 32);

     OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - OLD NH value before @ initial UE  \n");
     OAILOG_STREAM_HEX (OAILOG_LEVEL_DEBUG, LOG_NAS_EMM, "OLD_NH :", emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, 32);

      /** Derive the next hop. */
      /** Calculate and set the next hop value into the context. Use the above derived kenb as first nh value. */
      if(memcmp(emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, zero, 32) == 0){
          OAILOG_DEBUG (LOG_NAS_EMM, "EMM-PROC  - NH value is 0 as expected. Setting kEnb as NH0  \n");
          memcpy(emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, NAS_CONNECTION_ESTABLISHMENT_CNF(message_p).kenb, 32);
      }else{
        OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - NH value is NOT 0 @ initial S1AP context establishment  \n");
      }

      OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - NH value after copy of kenb @ initial UE  \n");
      OAILOG_STREAM_HEX (OAILOG_LEVEL_DEBUG, LOG_NAS_EMM, "NEW_NH :", emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, 32);


    /** Reset the next chaining hop counter.
     * TS. 33.401:
     * Upon receipt of the NAS Service Request message, the MME shall derive key KeNB as specified in Annex A.3 using the
      NAS COUNT [9] corresponding to the NAS Service Request and initialize the value of the Next hop Chaining Counter
      (NCC) to one. The MME shall further derive a next hop parameter NH as specified in Annex A.4 using the newly
      derived KeNB as basis for the derivation. This fresh {NH, NCC=1} pair shall be stored in the MME and shall be used for
      the next forward security key derivation. The MME shall communicate the {KeNB, NCC=0} pair and KSIASME to the
      serving eNB in the S1-AP procedure INITIAL CONTEXT SETUP.
 */
    emm_ctx->_security.ncc = 0;
    /* The NCC is a 3-bit key index (values from 0 to 7) for the NH and is sent to the
    UE in the handover command signalling. */
//    emm_ctx->_security.ncc = emm_ctx->_security.ncc % 8;

    MSC_LOG_TX_MESSAGE(
        MSC_NAS_MME,
        MSC_MMEAPP_MME,
        NULL,0,
        "NAS_CONNECTION_ESTABLISHMENT_CNF ue id %06"PRIX32" len %u sea %x sia %x ",
        ue_idP, blength(msgP), selected_encryption_algorithmP, selected_integrity_algorithmP);

    itti_send_msg_to_task(TASK_MME_APP, INSTANCE_DEFAULT, message_p);
  }

  OAILOG_FUNC_OUT(LOG_NAS);
}

////------------------------------------------------------------------------------
//void nas_itti_establish_rej(
//  const uint32_t      ue_idP,
//  const imsi_t *const imsi_pP
//  , uint8_t           initial_reqP)
//{
//  OAILOG_FUNC_IN(LOG_NAS);
//  MessageDef *message_p;
//
//  message_p = itti_alloc_new_message(TASK_NAS_MME, NAS_AUTHENTICATION_PARAM_REQ);
//  memset(&message_p->ittiMsg.nas_auth_param_req,
//         0,
//         sizeof(itti_nas_auth_param_req_t));
//
//  hexa_to_ascii((uint8_t *)imsi_pP->u.value,
//                NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi, 8);
//
//  NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi[15] = '\0';
//
//  if (isdigit(NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi[14])) {
//    NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi_length = 15;
//  } else {
//    NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi_length = 14;
//    NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi[14]    = '\0';
//  }
//
//  NAS_AUTHENTICATION_PARAM_REQ(message_p).initial_req = initial_reqP;
//  NAS_AUTHENTICATION_PARAM_REQ(message_p).ue_id       = ue_idP;
//
//  MSC_LOG_TX_MESSAGE(
//        MSC_NAS_MME,
//        MSC_MMEAPP_MME,
//        NULL,0,
//        "NAS_AUTHENTICATION_PARAM_REQ ue id %06"PRIX32" IMSI %s (establish reject)",
//        ue_idP, NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi);
//
//  itti_send_msg_to_task(TASK_MME_APP, INSTANCE_DEFAULT, message_p);
//  OAILOG_FUNC_OUT(LOG_NAS);
//}

//------------------------------------------------------------------------------
void nas_itti_handover_cnf(
  const uint32_t         ue_idP,
  const nas_error_code_t error_codeP,
  const uint16_t         selected_encryption_algorithmP,
  const uint16_t         selected_integrity_algorithmP)
{
  OAILOG_FUNC_IN(LOG_NAS);
  MessageDef                             *message_p        = NULL;
  emm_data_context_t                     *emm_ctx = emm_data_context_get (&_emm_data, ue_idP);

  if (emm_ctx) {
    message_p = itti_alloc_new_message(TASK_NAS_MME, NAS_HANDOVER_CNF);
    memset(&message_p->ittiMsg.nas_handover_cnf, 0, sizeof(itti_nas_handover_cnf_t));
    NAS_HANDOVER_CNF(message_p).ue_id                           = ue_idP;
    NAS_HANDOVER_CNF(message_p).err_code                        = error_codeP;

    // According to 3GPP 9.2.1.40, the UE security capabilities are 16-bit
    // strings, EEA0 is inherently supported, so its support is not tracked in
    // the bit string. However, emm_ctx->eea is an 8-bit string with the highest
    // order bit representing EEA0 support, so we need to trim it. The same goes
    // for integrity.
    //
    // TODO: change the way the EEA and EIA are translated into the packets.
    //       Currently, the 16-bit string is 8-bit rotated to produce the string
    //       sent in the packets, which is why we're using bits 8-10 to
    //       represent EEA1/2/3 (and EIA1/2/3) support here.
    NAS_HANDOVER_CNF(message_p)
      .encryption_algorithm_capabilities =
      ((uint16_t)emm_ctx->eea & ~(1 << 7)) << 1;
    NAS_HANDOVER_CNF(message_p)
      .integrity_algorithm_capabilities =
      ((uint16_t)emm_ctx->eia & ~(1 << 7)) << 1;

    AssertFatal((0 <= emm_ctx->_security.vector_index) && (MAX_EPS_AUTH_VECTORS > emm_ctx->_security.vector_index),
        "Invalid vector index %d", emm_ctx->_security.vector_index);

//    derive_keNB (emm_ctx->_vector[emm_ctx->_security.vector_index].kasme,
//        emm_ctx->_security.ul_count.seq_num | (emm_ctx->_security.ul_count.overflow << 8),
//        NAS_HANDOVER_CNF(message_p).kenb);

    /** Reset the ncc value. */
//    emm_ctx->_security.ncc = 1;

    // todo: check that the nh value is not null/0/empty

    OAILOG_DEBUG (LOG_NAS_EMM, "EMM-PROC  - CALCULATING WRONG HANDOVER VALUE \n");

    uint8_t                                 zero[32];
    memset(zero, 0, 32);

    /** Derive the next hop. */
    /** Calculate and set the next hop value into the context. Use the above derived kenb as first nh value. */
    if(memcmp(emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, zero, 32) == 0){
        OAILOG_DEBUG (LOG_NAS_EMM, "EMM-PROC  - NH value is not 0.  \n");
    }else{
      OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - NH value is 0 NH calculation . \n");
    }

    OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - Old NH value before derive_nh @ handover. \n");
    OAILOG_STREAM_HEX (OAILOG_LEVEL_DEBUG, LOG_NAS_EMM, "NEW NH:", emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, 32);

    derive_nh(emm_ctx->_vector[emm_ctx->_security.vector_index].kasme,
        emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj);

    OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - NEW NH value after derive_nh @ handover. \n");
    OAILOG_STREAM_HEX (OAILOG_LEVEL_DEBUG, LOG_NAS_EMM, "NEW NH:", emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, 32);

//    OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - NH value is 0 NH calculation. New Nh Value %x.", *(emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj));

    memcpy(NAS_HANDOVER_CNF(message_p).nh_conj, emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, 32 );

    OAILOG_WARNING( LOG_NAS_EMM, "EMM-PROC  - Sent NH value after derive_nh @ handover.  \n");
    OAILOG_STREAM_HEX (OAILOG_LEVEL_DEBUG, LOG_NAS_EMM, "NEW NH:", NAS_HANDOVER_CNF(message_p).nh_conj, 32);

    /** Calculate and set the next hop value into the context. */
//    derive_nh(emm_ctx->_vector[emm_ctx->_security.vector_index].kasme,
//        emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, sizeof(emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj)/8,
//        &NAS_HANDOVER_CNF(message_p).nh_conj);
//
//    derive_nh(emm_ctx->_vector[emm_ctx->_security.vector_index].kasme,
//           emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj,
//           NAS_HANDOVER_CNF(message_p).kenb);




//    derive_nh (
//      const uint8_t *kasme_32,
//      uint8_t * nh,
//      uint8_t * kenb)
//    {
//
//      uint8_t                                 s[35], zero[32];
//      memset(zero, 0, 32);
//      memset(s, 0, 35);
//
//      s[0] = (FC_NH);
//       // P0
//      if(memcmp(nh, zero, 32)==0){
//          /*First hop*/
//          memcpy(s+1, kenb, 32);
//      }else{
//          memcpy(s+1, nh, 32);
//      }




  //    derive_nh(emm_ctx->_vector[emm_ctx->_security.vector_index].kasme,
  //        emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj,
  //        NAS_CONNECTION_ESTABLISHMENT_CNF(message_p).kenb);
  //
  //
  ////    derive_nh (
  ////      const uint8_t *kasme_32,
  ////      uint8_t * nh,
  ////      uint8_t * kenb)
  ////    {
  ////
  ////      uint8_t                                 s[35], zero[32];
  ////      memset(zero, 0, 32);
  ////      memset(s, 0, 35);
  ////
  ////      s[0] = (FC_NH);
  ////       // P0
  ////      if(memcmp(nh, zero, 32)==0){
  ////          /*First hop*/
  //          memcpy(s+1, kenb, 32);
  //      }else{
  //          memcpy(s+1, nh, 32);
  //      }
  //
  //








//    memcpy ((void *)emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj, NAS_HANDOVER_CNF(message_p).nh_conj,  sizeof(emm_ctx->_vector[emm_ctx->_security.vector_index].nh_conj)/8);

    /** Increase the next hop counter. */
    emm_ctx->_security.ncc++;
    /* The NCC is a 3-bit key index (values from 0 to 7) for the NH and is sent to the
    UE in the handover command signaling. */
    emm_ctx->_security.ncc = emm_ctx->_security.ncc % 8;
    NAS_HANDOVER_CNF(message_p).ncc = emm_ctx->_security.ncc;

    MSC_LOG_TX_MESSAGE(
        MSC_NAS_MME,
        MSC_MMEAPP_MME,
        NULL,0,
        "NAS_HANDOVER_CNF ue id %06"PRIX32/*" len %u sea %x sia %x "*/,
        ue_idP, /*blength(msgP),*/ selected_encryption_algorithmP, selected_integrity_algorithmP);

    itti_send_msg_to_task(TASK_MME_APP, INSTANCE_DEFAULT, message_p);
  }

  OAILOG_FUNC_OUT(LOG_NAS);
}

//------------------------------------------------------------------------------
void nas_itti_handover_rej(
  const uint32_t      ue_idP,
  const nas_error_code_t error_codeP)
{
  OAILOG_FUNC_IN(LOG_NAS);
  MessageDef *message_p;

  message_p = itti_alloc_new_message(TASK_NAS_MME, NAS_HANDOVER_REJ);

  NAS_HANDOVER_CNF(message_p).err_code                        = error_codeP;
  NAS_HANDOVER_REJ(message_p).ue_id                           = ue_idP;

  MSC_LOG_TX_MESSAGE(
        MSC_NAS_MME,
        MSC_MMEAPP_MME,
        NULL,0,
        "NAS_HANDOVER_REJ ue id %06"PRIX32" IMSI %s (establish reject)",
        ue_idP, NAS_AUTHENTICATION_PARAM_REQ(message_p).imsi);

  itti_send_msg_to_task(TASK_MME_APP, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT(LOG_NAS);
}

//------------------------------------------------------------------------------
void nas_itti_detach_req(
  const uint32_t      ue_idP)
{
  OAILOG_FUNC_IN(LOG_NAS);
  MessageDef *message_p;

  message_p = itti_alloc_new_message(TASK_NAS_MME, NAS_DETACH_REQ);
  memset(&message_p->ittiMsg.nas_detach_req,
         0,
         sizeof(itti_nas_detach_req_t));

  NAS_DETACH_REQ(message_p).ue_id = ue_idP;

  MSC_LOG_TX_MESSAGE(
                MSC_NAS_MME,
                MSC_MMEAPP_MME,
                NULL,0,
                "0 NAS_DETACH_REQ ue id %06"PRIX32" ",
          ue_idP);

  itti_send_msg_to_task(TASK_MME_APP, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT(LOG_NAS);
}
//***************************************************************************
static void  *_s6a_auth_info_rsp_timer_expiry_handler (void *args)
{
  struct emm_data_context_s              *emm_ctx = NULL;
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  s6a_auth_info_rsp_timer_arg_t  *timer_args = (s6a_auth_info_rsp_timer_arg_t *) (args);
  if (timer_args) {
    emm_ctx = emm_data_context_get (&_emm_data,timer_args->ue_id);
    if (emm_ctx) {  
      emm_ctx->timer_s6a_auth_info_rsp.id = NAS_TIMER_INACTIVE_ID;
      if (timer_args->resync) {
        OAILOG_ERROR (LOG_NAS_EMM, 
            "EMM-PROC  - Timer timer_s6_auth_info_rsp expired. Resync auth procedure was in progress. Aborting attach procedure. UE id %d \n", 
                                                                                                                                  emm_ctx->ue_id);
      } else {

        OAILOG_ERROR (LOG_NAS_EMM, 
              "EMM-PROC  - Timer timer_s6_auth_info_rsp expired. Initial auth procedure was in progress. Aborting attach procedure. UE id %d \n", 
                                                                                                                                  emm_ctx->ue_id);
      }
      // Free timer args
      free_wrapper (&args);
      emm_ctx->timer_s6a_auth_info_rsp_arg = NULL;
      
      // Send Attach Reject with cause NETWORK FAILURE and delete UE context
      nas_proc_auth_param_fail (emm_ctx->ue_id, NAS_CAUSE_NETWORK_FAILURE);
    } else { 
      free_wrapper (&args);
      OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - Timer timer_s6_auth_info_rsp expired. Null EMM Context for UE %d\n", timer_args->ue_id);
    }
  } else { 
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - Timer timer_s6_auth_info_rsp expired. Null Timer arguments. Ignoring it \n");
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, NULL);
}
//***************************************************************************
