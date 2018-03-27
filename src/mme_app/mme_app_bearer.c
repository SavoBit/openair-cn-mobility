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


/*! \file mme_app_bearer.c
  \brief
  \author Sebastien ROUX, Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "assertions.h"
#include "log.h"
#include "msc.h"
#include "conversions.h"
#include "common_types.h"
#include "intertask_interface.h"
#include "mme_app_ue_context.h"
#include "mme_app_defs.h"
#include "mme_app_itti_messaging.h"
#include "mme_config.h"
#include "emmData.h"
#include "mme_app_statistics.h"
#include "timer.h"
#include "s1ap_mme.h"
#include "s1ap_mme_ta.h"

//----------------------------------------------------------------------------
static bool mme_app_construct_guti(const plmn_t * const plmn_p, const as_stmsi_t * const s_tmsi_p,  guti_t * const guti_p);

static void notify_s1ap_new_ue_mme_s1ap_id_association (struct ue_context_s *ue_context_p);
static bool mme_app_check_ta_local(const plmn_t * target_plmn, const tac_t target_tac);

static int mme_app_compare_tac (uint16_t tac_value);
static int mme_app_compare_plmn(const plmn_t * plmn);

static void mme_app_send_s1ap_handover_preparation_failure(mme_ue_s1ap_id_t mme_ue_s1ap_id, enb_ue_s1ap_id_t enb_ue_s1ap_id, sctp_assoc_id_t assoc_id, MMECause_t mmeCause);

static void mme_app_send_s1ap_path_switch_request_acknowledge(mme_ue_s1ap_id_t mme_ue_s1ap_id);

static void mme_app_send_s1ap_path_switch_request_failure(mme_ue_s1ap_id_t mme_ue_s1ap_id, enb_ue_s1ap_id_t enb_ue_s1ap_id, sctp_assoc_id_t assoc_id, MMECause_t mmeCause);

static void mme_app_send_s1ap_handover_request(mme_ue_s1ap_id_t mme_ue_s1ap_id, uint32_t                enb_id,
    uint16_t                encryption_algorithm_capabilities,
    uint16_t                integrity_algorithm_capabilities,
    uint8_t                 nh[AUTH_NH_SIZE],
    uint8_t                 ncc);

static void mme_app_send_s1ap_handover_command(mme_ue_s1ap_id_t mme_ue_s1ap_id, enb_ue_s1ap_id_t enb_ue_s1ap_id, bstring target_to_source_cont);

static void mme_app_send_s10_forward_relocation_response_err(teid_t mme_source_s10_teid, uint32_t mme_source_ipv4_address, MMECause_t mmeCause);

static void mme_app_send_s1ap_mme_status_transfer(mme_ue_s1ap_id_t mme_ue_s1ap_id, enb_ue_s1ap_id_t enb_ue_s1ap_id, uint32_t enb_id, bstring source_to_target_cont);

/** External definitions in MME_APP UE Data Context. */
extern int mme_app_set_ue_eps_mm_context(mm_context_eps_t * ue_eps_mme_context_p, struct ue_context_s *ue_context_p, emm_data_context_t *ue_nas_ctx);
extern int mme_app_set_pdn_connections(struct mme_ue_eps_pdn_connections_s * pdn_connections, struct ue_context_s * ue_context_p);
extern void mme_app_handle_pending_pdn_connectivity_information(ue_context_t *ue_context_p, pdn_connection_t * pdn_conn_pP);
extern bearer_context_t* mme_app_create_new_bearer_context(ue_context_t *ue_context_p, ebi_t bearer_id);


//------------------------------------------------------------------------------
int
mme_app_send_s11_release_access_bearers_req (
  struct ue_context_s *const ue_context_pP)
{
  /*
   * Keep the identifier to the default APN
   */
  MessageDef                             *message_p = NULL;
  itti_s11_release_access_bearers_request_t         *release_access_bearers_request_p = NULL;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ue_context_pP );
  message_p = itti_alloc_new_message (TASK_MME_APP, S11_RELEASE_ACCESS_BEARERS_REQUEST);
  release_access_bearers_request_p = &message_p->ittiMsg.s11_release_access_bearers_request;
  memset ((void*)release_access_bearers_request_p, 0, sizeof (itti_s11_release_access_bearers_request_t));
  release_access_bearers_request_p->local_teid = ue_context_pP->mme_s11_teid;
  release_access_bearers_request_p->teid = ue_context_pP->sgw_s11_teid;
  release_access_bearers_request_p->list_of_rabs.num_ebi = 1;
  release_access_bearers_request_p->list_of_rabs.ebis[0] = ue_context_pP->default_bearer_id;
  release_access_bearers_request_p->originating_node = NODE_TYPE_MME;


  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 S11_RELEASE_ACCESS_BEARERS_REQUEST teid %u ebi %u",
      release_access_bearers_request_p->teid, release_access_bearers_request_p->list_of_rabs.ebis[0]);
  rc = itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}


//------------------------------------------------------------------------------
int
mme_app_send_s11_create_session_req (
  struct ue_context_s *const ue_context_pP)
{
  uint8_t                                 i = 0;

  /*
   * Keep the identifier to the default APN
   */
  context_identifier_t                    context_identifier = 0;
  MessageDef                             *message_p = NULL;
  itti_s11_create_session_request_t      *session_request_p = NULL;
  struct apn_configuration_s             *default_apn_p = NULL;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ue_context_pP );
  OAILOG_DEBUG (LOG_MME_APP, "Handling imsi " IMSI_64_FMT "\n", ue_context_pP->imsi);

  if (ue_context_pP->sub_status != SS_SERVICE_GRANTED) {
    /*
     * HSS rejected the bearer creation or roaming is not allowed for this
     * UE. This result will trigger an ESM Failure message sent to UE.
     */
    DevMessage ("Not implemented: ACCESS NOT GRANTED, send ESM Failure to NAS\n");
  }

  message_p = itti_alloc_new_message (TASK_MME_APP, S11_CREATE_SESSION_REQUEST);
  /*
   * WARNING:
   * Some parameters should be provided by NAS Layer:
   * - ue_time_zone
   * - mei
   * - uli
   * - uci
   * Some parameters should be provided by HSS:
   * - PGW address for CP
   * - paa
   * - ambr
   * and by MME Application layer:
   * - selection_mode
   * Set these parameters with random values for now.
   */
  session_request_p = &message_p->ittiMsg.s11_create_session_request;
  memset (session_request_p, 0, sizeof (itti_s11_create_session_request_t));
  /*
   * As the create session request is the first exchanged message and as
   * no tunnel had been previously setup, the distant teid is set to 0.
   * The remote teid will be provided in the response message.
   */
  session_request_p->teid = 0;
  IMSI64_TO_STRING (ue_context_pP->imsi, (char *)session_request_p->imsi.digit);
  // message content was set to 0
  session_request_p->imsi.length = strlen ((const char *)session_request_p->imsi.digit);
  /*
   * Copy the MSISDN
   */
  memcpy (session_request_p->msisdn.digit, ue_context_pP->msisdn, ue_context_pP->msisdn_length);
  session_request_p->msisdn.length = ue_context_pP->msisdn_length;
  session_request_p->rat_type = RAT_EUTRAN;
  /*
   * Copy the subscribed ambr to the sgw create session request message
   */
  memcpy (&session_request_p->ambr, &ue_context_pP->subscribed_ambr, sizeof (ambr_t));

  if (ue_context_pP->apn_profile.nb_apns == 0) {
    DevMessage ("No APN returned by the HSS");
  }

  context_identifier = ue_context_pP->apn_profile.context_identifier;

  for (i = 0; i < ue_context_pP->apn_profile.nb_apns; i++) {
    default_apn_p = &ue_context_pP->apn_profile.apn_configuration[i];

    /*
     * OK we got our default APN
     */
    if (default_apn_p->context_identifier == context_identifier)
      break;
  }

  if (!default_apn_p) {
    /*
     * Unfortunately we didn't find our default APN...
     * This could be a Handover message. In that case, fill the elements of the bearer contexts from NAS_PDN_CONNECTIVITY_MSG.
     *
     */
    // Zero because default bearer (see 29.274)
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.gbr.br_ul = 0;
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.gbr.br_dl = 0;
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.mbr.br_ul = 0;
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.mbr.br_dl = 0;
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.qci = default_apn_p->subscribed_qos.qci;
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pvi = default_apn_p->subscribed_qos.allocation_retention_priority.pre_emp_vulnerability;
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pci = default_apn_p->subscribed_qos.allocation_retention_priority.pre_emp_capability;
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pl = default_apn_p->subscribed_qos.allocation_retention_priority.priority_level;
    session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].eps_bearer_id = 5;
    session_request_p->bearer_contexts_to_be_created.num_bearer_context = 1;

  }

  // Zero because default bearer (see 29.274)
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.gbr.br_ul = 0;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.gbr.br_dl = 0;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.mbr.br_ul = 0;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.mbr.br_dl = 0;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.qci = default_apn_p->subscribed_qos.qci;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pvi = default_apn_p->subscribed_qos.allocation_retention_priority.pre_emp_vulnerability;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pci = default_apn_p->subscribed_qos.allocation_retention_priority.pre_emp_capability;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pl = default_apn_p->subscribed_qos.allocation_retention_priority.priority_level;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].eps_bearer_id = 5;
  session_request_p->bearer_contexts_to_be_created.num_bearer_context = 1;
  /*
   * Asking for default bearer in initial UE message.
   * Use the address of ue_context as unique TEID: Need to find better here
   * and will generate unique id only for 32 bits platforms.
   */
  OAI_GCC_DIAG_OFF(pointer-to-int-cast);
  session_request_p->sender_fteid_for_cp.teid = (teid_t) ue_context_pP;
  OAI_GCC_DIAG_ON(pointer-to-int-cast);
  session_request_p->sender_fteid_for_cp.interface_type = S11_MME_GTP_C;
  mme_config_read_lock (&mme_config);
  session_request_p->sender_fteid_for_cp.ipv4_address = mme_config.ipv4.s11;
  mme_config_unlock (&mme_config);
  session_request_p->sender_fteid_for_cp.ipv4 = 1;

  //ue_context_pP->mme_s11_teid = session_request_p->sender_fteid_for_cp.teid;
  ue_context_pP->sgw_s11_teid = 0;
  mme_ue_context_update_coll_keys (&mme_app_desc.mme_ue_contexts, ue_context_pP,
                                   ue_context_pP->enb_s1ap_id_key,
                                   ue_context_pP->mme_ue_s1ap_id,
                                   ue_context_pP->imsi,
                                   session_request_p->sender_fteid_for_cp.teid,       // mme_s11_teid is new
                                   ue_context_pP->local_mme_s10_teid,       // set to 0
                                   &ue_context_pP->guti);
  memcpy (session_request_p->apn, default_apn_p->service_selection, default_apn_p->service_selection_length);
  /*
   * Set PDN type for pdn_type and PAA even if this IE is redundant
   */
  session_request_p->pdn_type = default_apn_p->pdn_type;
  session_request_p->paa.pdn_type = default_apn_p->pdn_type;

  if (default_apn_p->nb_ip_address == 0) {
    /*
     * UE DHCPv4 allocated ip address
     */
    memset (session_request_p->paa.ipv4_address, 0, 4);
    memset (session_request_p->paa.ipv6_address, 0, 16);
  } else {
    uint8_t                                 j;

    for (j = 0; j < default_apn_p->nb_ip_address; j++) {
      ip_address_t                           *ip_address;

      ip_address = &default_apn_p->ip_address[j];

      if (ip_address->pdn_type == IPv4) {
        memcpy (session_request_p->paa.ipv4_address, ip_address->address.ipv4_address, 4);
      } else if (ip_address->pdn_type == IPv6) {
        memcpy (session_request_p->paa.ipv6_address, ip_address->address.ipv6_address, 16);
      }
      //             free(ip_address);
    }
  }

  // todo: where to set this from? config?
  session_request_p->apn_restriction = 0x00;


  copy_protocol_configuration_options (&session_request_p->pco, &ue_context_pP->pending_pdn_connectivity_req_pco);
  clear_protocol_configuration_options(&ue_context_pP->pending_pdn_connectivity_req_pco);

  mme_config_read_lock (&mme_config);
  session_request_p->peer_ip = mme_config.ipv4.sgw_s11;
  mme_config_unlock (&mme_config);
  session_request_p->serving_network.mcc[0] = ue_context_pP->e_utran_cgi.plmn.mcc_digit1;
  session_request_p->serving_network.mcc[1] = ue_context_pP->e_utran_cgi.plmn.mcc_digit2;
  session_request_p->serving_network.mcc[2] = ue_context_pP->e_utran_cgi.plmn.mcc_digit3;
  session_request_p->serving_network.mnc[0] = ue_context_pP->e_utran_cgi.plmn.mnc_digit1;
  session_request_p->serving_network.mnc[1] = ue_context_pP->e_utran_cgi.plmn.mnc_digit2;
  session_request_p->serving_network.mnc[2] = ue_context_pP->e_utran_cgi.plmn.mnc_digit3;
  session_request_p->selection_mode = MS_O_N_P_APN_S_V;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0,
      "0 S11_CREATE_SESSION_REQUEST imsi " IMSI_64_FMT, ue_context_pP->imsi);
  rc = itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}


//------------------------------------------------------------------------------
// todo: no default_apn set at the moment since no subscription data!
// todo: setting the apn_configuration
// todo: combine this and the other s11_csr method to a single one (w/wo default_apn_config) --> one should overwrite the values of another
int
mme_app_send_s11_create_session_req_from_handover_tau (
    mme_ue_s1ap_id_t ueId)
{
  uint8_t                                 i = 0;
  context_identifier_t                    context_identifier = 0;
  MessageDef                             *message_p = NULL;
  itti_s11_create_session_request_t      *session_request_p = NULL;
  imsi64_t                                imsi64 = INVALID_IMSI64;
  int                                     rc = RETURNok;
  emm_data_context_t                     *ue_nas_ctx = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);

  /** Find the UE context. */
  ue_context_t * ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, ueId);
  DevAssert(ue_context_p); /**< Should always exist. Any mobility issue in which this could occur? */

  /** Not getting the NAS EMM context. */
  OAILOG_INFO(LOG_MME_APP, "Sending CSR for UE in Handover/TAU procedure with mmeUeS1apId " MME_UE_S1AP_ID_FMT ". \n", ueId);
  ue_context_p->imsi_auth = IMSI_AUTHENTICATED;

  /**
   * Trigger a Create Session Request.
   * Keep the identifier to the default APN
   */
  if (ue_context_p->sub_status != SS_SERVICE_GRANTED) {
    /*
     * HSS rejected the bearer creation or roaming is not allowed for this
     * UE. This result will trigger an ESM Failure message sent to UE.
     */
    DevMessage ("Not implemented: ACCESS NOT GRANTED, send ESM Failure to NAS\n");
  }

  /**
   * Check if there are already bearer contexts in the MME_APP UE context,
   * if so no need to send S11 CSReq. Directly respond to the NAS layer.
   */
  bearer_context_t* bearer_ctx = mme_app_is_bearer_context_in_list(ue_context_p->mme_ue_s1ap_id, ue_context_p->default_bearer_id);
  if(bearer_ctx){
    OAILOG_INFO (LOG_MME_APP, "A bearer context is already established for default bearer EBI %d for UE " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->default_bearer_id, ue_context_p->mme_ue_s1ap_id);
    ue_nas_ctx = emm_data_context_get_by_imsi (&_emm_data, ue_context_p->imsi);
      if (ue_nas_ctx) {
        OAILOG_INFO (LOG_MME_APP, "Informing the NAS layer about the received CREATE_SESSION_REQUEST for UE " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->mme_ue_s1ap_id);
        //uint8_t *keNB = NULL;
        message_p = itti_alloc_new_message (TASK_MME_APP, NAS_PDN_CONNECTIVITY_RSP);
        itti_nas_pdn_connectivity_rsp_t *nas_pdn_connectivity_rsp = &message_p->ittiMsg.nas_pdn_connectivity_rsp;
        memset ((void *)nas_pdn_connectivity_rsp, 0, sizeof (itti_nas_pdn_connectivity_rsp_t));
        // moved to NAS_CONNECTION_ESTABLISHMENT_CONF, keNB not handled in NAS MME
        //derive_keNB(ue_context_p->vector_in_use->kasme, 156, &keNB);
        //memcpy(NAS_PDN_CONNECTIVITY_RSP(message_p).keNB, keNB, 32);
        //free(keNB);
        /** Check if this is a handover procedure, set the flag. Don't reset the MME_APP UE context flag till HANDOVER_NOTIFY is received. */
        // todo: states don't match for handover!
    //    if(ue_context_p->mm_state == UE_REGISTERED && (ue_context_p->handover_info != NULL)){
    //      nas_pdn_connectivity_rsp->pending_mobility = true;
    //      /**
    //       * The Handover Information will still be kept in the UE context and not used until HANDOVER_REQUEST is sent to the target ENB..
    //       * Sending CSR may only imply S1AP momentarily.. X2AP is assumed not to switch SAE-GWs (todo: not supported yet).
    //       */
    //    }
        nas_pdn_connectivity_rsp->pti = 0;  // NAS internal ref
        nas_pdn_connectivity_rsp->ue_id = ue_context_p->mme_ue_s1ap_id;      // NAS internal ref

        // TO REWORK:
        if (ue_context_p->pending_pdn_connectivity_req_apn) {
          nas_pdn_connectivity_rsp->apn = bstrcpy (ue_context_p->pending_pdn_connectivity_req_apn);
          bdestroy(ue_context_p->pending_pdn_connectivity_req_apn);
          OAILOG_DEBUG (LOG_MME_APP, "SET APN FROM NAS PDN CONNECTIVITY CREATE: %s\n", bdata(nas_pdn_connectivity_rsp->apn));
        }
        //else {
        int                                     i;
        context_identifier_t                    context_identifier = ue_context_p->apn_profile.context_identifier;

        // todo: for the s1ap handover case, no apn configuration exists yet..
        for (i = 0; i < ue_context_p->apn_profile.nb_apns; i++) {
          if (ue_context_p->apn_profile.apn_configuration[i].context_identifier == context_identifier) {
            AssertFatal (ue_context_p->apn_profile.apn_configuration[i].service_selection_length > 0, "Bad APN string (len = 0)");

            if (ue_context_p->apn_profile.apn_configuration[i].service_selection_length > 0) {
              nas_pdn_connectivity_rsp->apn = blk2bstr(ue_context_p->apn_profile.apn_configuration[i].service_selection,
                  ue_context_p->apn_profile.apn_configuration[i].service_selection_length);
              AssertFatal (ue_context_p->apn_profile.apn_configuration[i].service_selection_length <= APN_MAX_LENGTH, "Bad APN string length %d",
                  ue_context_p->apn_profile.apn_configuration[i].service_selection_length);

              OAILOG_DEBUG (LOG_MME_APP, "SET APN FROM HSS ULA: %s\n", bdata(nas_pdn_connectivity_rsp->apn));
              break;
            }
          }
        }
        //    }
        OAILOG_DEBUG (LOG_MME_APP, "APN: %s\n", bdata(nas_pdn_connectivity_rsp->apn));
        switch (ue_context_p->pending_pdn_connectivity_req_pdn_type) {
        case IPv4:
          nas_pdn_connectivity_rsp->pdn_addr = blk2bstr(ue_context_p->pending_pdn_connectivity_req_pdn_addr, 4);
          DevAssert (nas_pdn_connectivity_rsp->pdn_addr);
          break;

          // todo:
//        case IPv6:
//          DevAssert (create_sess_resp_pP->paa.ipv6_prefix_length == 64);    // NAS seems to only support 64 bits
//          nas_pdn_connectivity_rsp->pdn_addr = blk2bstr(create_sess_resp_pP->paa.ipv6_address, create_sess_resp_pP->paa.ipv6_prefix_length / 8);
//          DevAssert (nas_pdn_connectivity_rsp->pdn_addr);
//          break;
//
//        case IPv4_AND_v6:
//          DevAssert (create_sess_resp_pP->paa.ipv6_prefix_length == 64);    // NAS seems to only support 64 bits
//          nas_pdn_connectivity_rsp->pdn_addr = blk2bstr(create_sess_resp_pP->paa.ipv4_address, 4 + create_sess_resp_pP->paa.ipv6_prefix_length / 8);
//          DevAssert (nas_pdn_connectivity_rsp->pdn_addr);
//          bcatblk(nas_pdn_connectivity_rsp->pdn_addr, create_sess_resp_pP->paa.ipv6_address, create_sess_resp_pP->paa.ipv6_prefix_length / 8);
//          break;
//
//        case IPv4_OR_v6:
//          nas_pdn_connectivity_rsp->pdn_addr = blk2bstr(create_sess_resp_pP->paa.ipv4_address, 4);
//          DevAssert (nas_pdn_connectivity_rsp->pdn_addr);
//          break;

        default:
          DevAssert (0);
        }
        // todo: IP address strings are not cleared

        nas_pdn_connectivity_rsp->pdn_type = ue_context_p->pending_pdn_connectivity_req_pdn_type;
        nas_pdn_connectivity_rsp->proc_data = ue_context_p->pending_pdn_connectivity_req_proc_data;      // NAS internal ref
        ue_context_p->pending_pdn_connectivity_req_proc_data = NULL;
    //#pragma message  "QOS hardcoded here"
        //memcpy(&NAS_PDN_CONNECTIVITY_RSP(message_p).qos,
        //        &ue_context_p->pending_pdn_connectivity_req_qos,
        //        sizeof(network_qos_t));
        nas_pdn_connectivity_rsp->qos.gbrUL = 64;        /* 64=64kb/s   Guaranteed Bit Rate for uplink   */
        nas_pdn_connectivity_rsp->qos.gbrDL = 120;       /* 120=512kb/s Guaranteed Bit Rate for downlink */
        nas_pdn_connectivity_rsp->qos.mbrUL = 72;        /* 72=128kb/s   Maximum Bit Rate for uplink      */
        nas_pdn_connectivity_rsp->qos.mbrDL = 135;       /*135=1024kb/s Maximum Bit Rate for downlink    */
        /*
         * Note : Above values are insignificant because bearer with QCI = 9 is NON-GBR bearer and ESM would not include GBR and MBR values
         * in Activate Default EPS Bearer Context Setup Request message
         */
        nas_pdn_connectivity_rsp->qos.qci = 9;   /* QoS Class Identifier                           */
        nas_pdn_connectivity_rsp->request_type = ue_context_p->pending_pdn_connectivity_req_request_type;        // NAS internal ref
        ue_context_p->pending_pdn_connectivity_req_request_type = 0;
        // here at this point OctetString are saved in resp, no loss of memory (apn, pdn_addr)
        nas_pdn_connectivity_rsp->ue_id = ue_context_p->mme_ue_s1ap_id;
        nas_pdn_connectivity_rsp->ebi = ue_context_p->default_bearer_id;
        nas_pdn_connectivity_rsp->qci = bearer_ctx->qci;
        nas_pdn_connectivity_rsp->prio_level = bearer_ctx->prio_level;
        nas_pdn_connectivity_rsp->pre_emp_vulnerability = bearer_ctx->pre_emp_vulnerability;
        nas_pdn_connectivity_rsp->pre_emp_capability = bearer_ctx->pre_emp_capability;
        nas_pdn_connectivity_rsp->sgw_s1u_teid = bearer_ctx->s_gw_teid;
        memcpy (&nas_pdn_connectivity_rsp->sgw_s1u_address, &bearer_ctx->s_gw_address, sizeof (ip_address_t));
        nas_pdn_connectivity_rsp->ambr.br_ul = ue_context_p->subscribed_ambr.br_ul;
        nas_pdn_connectivity_rsp->ambr.br_dl = ue_context_p->subscribed_ambr.br_dl;
        copy_protocol_configuration_options (&nas_pdn_connectivity_rsp->pco, &ue_context_p->pending_pdn_connectivity_req_pco);
        clear_protocol_configuration_options(&ue_context_p->pending_pdn_connectivity_req_pco);

        MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_PDN_CONNECTIVITY_RSP sgw_s1u_teid %u ebi %u qci %u prio %u", bearer_ctx->s_gw_teid, ue_context_p->default_bearer_id, bearer_ctx->qci, bearer_ctx->prio_level);
        rc = itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
        OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
      }else{
        OAILOG_ERROR(LOG_MME_APP, "Bearer context exists but no NAS EMM context exists for UE " MME_UE_S1AP_ID_FMT"\n", ue_context_p->mme_ue_s1ap_id);
        // todo: this case could happen?
        OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
      }
  }else{
    OAILOG_ERROR(LOG_MME_APP, "No bearer context exists for UE " MME_UE_S1AP_ID_FMT". Continuing with CSReq. \n", ue_context_p->mme_ue_s1ap_id);
  }


  message_p = itti_alloc_new_message (TASK_MME_APP, S11_CREATE_SESSION_REQUEST);
  /*
   * WARNING:
   * Some parameters should be provided by NAS Layer:
   * - ue_time_zone
   * - mei
   * - uli
   * - uci
   * Some parameters should be provided by HSS:
   * - PGW address for CP
   * - paa
   * - ambr
   * and by MME Application layer:
   * - selection_mode
   * Set these parameters with random values for now.
   */
  session_request_p = &message_p->ittiMsg.s11_create_session_request;
  memset (session_request_p, 0, sizeof (itti_s11_create_session_request_t));
  /*
   * As the create session request is the first exchanged message and as
   * no tunnel had been previously setup, the distant teid is set to 0.
   * The remote teid will be provided in the response message.
   */
  session_request_p->teid = 0;

  memset (&session_request_p->imsi.digit, 0, 16); /**< IMSI in create session request. */
  memcpy (&session_request_p->imsi.digit, &(ue_context_p->pending_pdn_connectivity_req_imsi), ue_context_p->pending_pdn_connectivity_req_imsi_length);
  session_request_p->imsi.length = strlen ((const char *)session_request_p->imsi.digit);

  /*
   * Copy the MSISDN
   */
  memcpy (session_request_p->msisdn.digit, ue_context_p->msisdn, ue_context_p->msisdn_length);
  session_request_p->msisdn.length = ue_context_p->msisdn_length;
  session_request_p->rat_type = RAT_EUTRAN;

  /**
   * Set the indication flag.
   */
  memset(&session_request_p->indication_flags, 0, sizeof(session_request_p->indication_flags));   // TO DO
  session_request_p->indication_flags.oi = 0x1;

  /*
   * Copy the subscribed ambr to the sgw create session request message
   */
  memcpy (&session_request_p->ambr, &ue_context_p->subscribed_ambr, sizeof (ambr_t));

//  if (ue_context_pP->apn_profile.nb_apns == 0) {
//    DevMessage ("No APN returned by the HSS");
//  }

  context_identifier = ue_context_p->apn_profile.context_identifier;

  /** Set the IPv4 Address from the msg. */
  // todo: currently only 1 IPv4 address is expected.
  //  for (i = 0; i < ue_context_pP->apn_profile.nb_apns; i++) {
  //    default_apn_p = &ue_context_pP->apn_profile.apn_configuration[i];

  // Zero because default bearer (see 29.274) todo: also for handover?
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.gbr.br_ul = 0;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.gbr.br_dl = 0;

  // todo: why should MBR be 0 ?
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.mbr.br_ul = ue_context_p->pending_pdn_connectivity_req_qos.mbrUL;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.mbr.br_dl = ue_context_p->pending_pdn_connectivity_req_qos.mbrDL;
  /** QCI & Bearer ARP. */
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.qci = ue_context_p->pending_pdn_connectivity_req_qos.qci;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pvi = ue_context_p->pending_pdn_connectivity_req_qos.pvi;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pl  = ue_context_p->pending_pdn_connectivity_req_qos.pl;
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].bearer_level_qos.pci = ue_context_p->pending_pdn_connectivity_req_qos.pci;

  /** Set EBI. */
  session_request_p->bearer_contexts_to_be_created.bearer_contexts[0].eps_bearer_id        = ue_context_p->pending_pdn_connectivity_req_ebi;

  session_request_p->bearer_contexts_to_be_created.num_bearer_context = 1;    /**< Multi-PDN Handover. */

  session_request_p->apn_restriction = ue_context_p->pending_pdn_connectivity_req_apn_restriction;

  /*
   * Asking for default bearer in initial UE message.
   * Use the address of ue_context as unique TEID: Need to find better here
   * and will generate unique id only for 32 bits platforms.
   */
  OAI_GCC_DIAG_OFF(pointer-to-int-cast);
  session_request_p->sender_fteid_for_cp.teid = (teid_t) ue_context_p;
  OAI_GCC_DIAG_ON(pointer-to-int-cast);
  session_request_p->sender_fteid_for_cp.interface_type = S11_MME_GTP_C;
  mme_config_read_lock (&mme_config);
  session_request_p->sender_fteid_for_cp.ipv4_address = mme_config.ipv4.s11;
  mme_config_unlock (&mme_config);
  session_request_p->sender_fteid_for_cp.ipv4 = 1;

  //ue_context_pP->mme_s11_teid = session_request_p->sender_fteid_for_cp.teid;
  ue_context_p->sgw_s11_teid = 0;
  mme_ue_context_update_coll_keys (&mme_app_desc.mme_ue_contexts, ue_context_p,
      ue_context_p->enb_s1ap_id_key,
      ue_context_p->mme_ue_s1ap_id,
      ue_context_p->imsi, /**< Set the IMSI from the EMM data context. */
      session_request_p->sender_fteid_for_cp.teid,       // mme_s11_teid is new
      ue_context_p->local_mme_s10_teid,       // set to 0
      &ue_context_p->guti); /**< Set the invalid context as it is. */

  memcpy (session_request_p->apn, ue_context_p->pending_pdn_connectivity_req_apn->data, ue_context_p->pending_pdn_connectivity_req_apn->slen);
  /*
   * Set PDN type for pdn_type and PAA even if this IE is redundant
   */
  session_request_p->pdn_type = ue_context_p->pending_pdn_connectivity_req_pdn_type;
  session_request_p->paa.pdn_type = ue_context_p->pending_pdn_connectivity_req_pdn_type;

//  session_request_pnas_pdn_connectivity_req_pP->(default_apn_p->nb_ip_address == 0) {
  /*
   * Set the UE IPv4 address
   */
  memset (session_request_p->paa.ipv4_address, 0, 4);
  memset (session_request_p->paa.ipv6_address, 0, 16);
  if (ue_context_p->pending_pdn_connectivity_req_pdn_type == IPv4) {
    /** Copy from IP address. */
    memcpy (session_request_p->paa.ipv4_address, ue_context_p->pending_pdn_connectivity_req_pdn_addr->data, 4); /**< String to array. */
  } else if (ue_context_p->pending_pdn_connectivity_req_pdn_type == IPv6) {
    // todo: UE IPV6 not implemented yet. memcpy (session_request_p->paa.ipv6_address, ip_address->address.ipv6_address, 16);
  }
  // todo: user location information
  // todo: set the serving network from ue_context and mnc/mcc configurations.
//  copy_protocol_configuration_options (&session_request_p->pco, &ue_context_pP->pending_pdn_connectivity_req_pco);
//  clear_protocol_configuration_options(&ue_context_pP->pending_pdn_connectivity_req_pco);

  mme_config_read_lock (&mme_config);
  session_request_p->peer_ip = mme_config.ipv4.sgw_s11;
  mme_config_unlock (&mme_config);

  /**
   * For TAU/Attach Request use the last TAI.
   */
  /** Get the EMM DATA context. */
  ue_nas_ctx = emm_data_context_get(&_emm_data, ueId);
  if(!ue_nas_ctx || ue_nas_ctx->_tai_list.n_tais == 0){
    OAILOG_INFO(LOG_MME_APP, "No EMM Data Context or TAI list exists for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " Sending pending TAI.\n", ueId);
    session_request_p->serving_network.mcc[0] = ue_context_p->pending_handover_target_tai.plmn.mcc_digit1;
    session_request_p->serving_network.mcc[1] = ue_context_p->pending_handover_target_tai.plmn.mcc_digit2;
    session_request_p->serving_network.mcc[2] = ue_context_p->pending_handover_target_tai.plmn.mcc_digit3;
    session_request_p->serving_network.mnc[0] = ue_context_p->pending_handover_target_tai.plmn.mnc_digit1;
    session_request_p->serving_network.mnc[1] = ue_context_p->pending_handover_target_tai.plmn.mnc_digit2;
    session_request_p->serving_network.mnc[2] = ue_context_p->pending_handover_target_tai.plmn.mnc_digit3;
    session_request_p->selection_mode = MS_O_N_P_APN_S_V;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0,
        "0 S11_CREATE_SESSION_REQUEST imsi " IMSI_64_FMT, ue_context_p->imsi);
    rc = itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
    OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
  }
  else{
    /// TODO: IMPLEMENT THIS FOR TAU?
  }
}

//------------------------------------------------------------------------------
int
mme_app_handle_nas_pdn_connectivity_req (
  itti_nas_pdn_connectivity_req_t * const nas_pdn_connectivity_req_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  imsi64_t                                imsi64 = INVALID_IMSI64;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (nas_pdn_connectivity_req_pP );
  IMSI_STRING_TO_IMSI64 ((char *)nas_pdn_connectivity_req_pP->imsi, &imsi64);
  OAILOG_DEBUG (LOG_MME_APP, "Received NAS_PDN_CONNECTIVITY_REQ from NAS Handling imsi " IMSI_64_FMT "\n", imsi64);

  if ((ue_context_p = mme_ue_context_exists_imsi (&mme_app_desc.mme_ue_contexts, imsi64)) == NULL) {
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "NAS_PDN_CONNECTIVITY_REQ Unknown imsi " IMSI_64_FMT, imsi64);
    OAILOG_ERROR (LOG_MME_APP, "That's embarrassing as we don't know this IMSI\n");
    mme_ue_context_dump_coll_keys();
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }

  /**
   * Consider the UE authenticated
   * todo: done here?!
   */
  ue_context_p->imsi_auth = IMSI_AUTHENTICATED;

  /** Not entering this state in case its not handover (assumed). */
  // Temp: save request, in near future merge wisely params in context
  memset (ue_context_p->pending_pdn_connectivity_req_imsi, 0, 16);
  AssertFatal ((nas_pdn_connectivity_req_pP->imsi_length > 0)
      && (nas_pdn_connectivity_req_pP->imsi_length < 16), "BAD IMSI LENGTH %d", nas_pdn_connectivity_req_pP->imsi_length);
  AssertFatal ((nas_pdn_connectivity_req_pP->imsi_length > 0)
      && (nas_pdn_connectivity_req_pP->imsi_length < 16), "STOP ON IMSI LENGTH %d", nas_pdn_connectivity_req_pP->imsi_length);
  memcpy (ue_context_p->pending_pdn_connectivity_req_imsi, nas_pdn_connectivity_req_pP->imsi, nas_pdn_connectivity_req_pP->imsi_length);
  ue_context_p->pending_pdn_connectivity_req_imsi_length = nas_pdn_connectivity_req_pP->imsi_length;

  // copy
  if (ue_context_p->pending_pdn_connectivity_req_apn) {
    bdestroy (ue_context_p->pending_pdn_connectivity_req_apn);
  }
  ue_context_p->pending_pdn_connectivity_req_apn =  nas_pdn_connectivity_req_pP->apn;
  nas_pdn_connectivity_req_pP->apn = NULL;

  // copy
  if (ue_context_p->pending_pdn_connectivity_req_pdn_addr) {
    bdestroy (ue_context_p->pending_pdn_connectivity_req_pdn_addr);
  }
  ue_context_p->pending_pdn_connectivity_req_pdn_addr =  nas_pdn_connectivity_req_pP->pdn_addr;
  nas_pdn_connectivity_req_pP->pdn_addr = NULL;

  ue_context_p->pending_pdn_connectivity_req_pti = nas_pdn_connectivity_req_pP->pti;
  ue_context_p->pending_pdn_connectivity_req_ue_id = nas_pdn_connectivity_req_pP->ue_id;
  copy_protocol_configuration_options (&ue_context_p->pending_pdn_connectivity_req_pco, &nas_pdn_connectivity_req_pP->pco);
  clear_protocol_configuration_options(&nas_pdn_connectivity_req_pP->pco);
#define TEMPORARY_DEBUG 1
#if TEMPORARY_DEBUG
  bstring b = protocol_configuration_options_to_xml(&ue_context_p->pending_pdn_connectivity_req_pco);
  OAILOG_DEBUG (LOG_MME_APP, "PCO %s\n", bdata(b));
  bdestroy(b);
#endif

  memcpy (&ue_context_p->pending_pdn_connectivity_req_qos, &nas_pdn_connectivity_req_pP->qos, sizeof (network_qos_t));
  ue_context_p->pending_pdn_connectivity_req_proc_data = nas_pdn_connectivity_req_pP->proc_data;
  nas_pdn_connectivity_req_pP->proc_data = NULL;
  ue_context_p->pending_pdn_connectivity_req_request_type = nas_pdn_connectivity_req_pP->request_type;
  //if ((nas_pdn_connectivity_req_pP->apn.value == NULL) || (nas_pdn_connectivity_req_pP->apn.length == 0)) {
  /*
   * TODO: Get keys...
   */
  /*
   * Now generate S6A ULR
   */
  rc =  mme_app_send_s6a_update_location_req (ue_context_p);
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}

// sent by NAS
//------------------------------------------------------------------------------
void
mme_app_handle_conn_est_cnf (
  const itti_nas_conn_est_cnf_t * const nas_conn_est_cnf_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  itti_mme_app_connection_establishment_cnf_t *establishment_cnf_p = NULL;
  bearer_context_t                       *current_bearer_p = NULL;
  ebi_t                                   bearer_id = 0;

  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received NAS_CONNECTION_ESTABLISHMENT_CNF from NAS\n");
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, nas_conn_est_cnf_pP->ue_id);

  if (ue_context_p == NULL) {
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "NAS_CONNECTION_ESTABLISHMENT_CNF Unknown ue %u", nas_conn_est_cnf_pP->ue_id);
    OAILOG_ERROR (LOG_MME_APP, "UE context doesn't exist for UE %06" PRIX32 "/dec%u\n", nas_conn_est_cnf_pP->ue_id, nas_conn_est_cnf_pP->ue_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }

  message_p = itti_alloc_new_message (TASK_MME_APP, MME_APP_CONNECTION_ESTABLISHMENT_CNF);
  establishment_cnf_p = &message_p->ittiMsg.mme_app_connection_establishment_cnf;
  memset (establishment_cnf_p, 0, sizeof (itti_mme_app_connection_establishment_cnf_t));
  memcpy (&establishment_cnf_p->nas_conn_est_cnf, nas_conn_est_cnf_pP, sizeof (itti_nas_conn_est_cnf_t));

  // Copy UE radio capabilities into message if it exists
  OAILOG_DEBUG (LOG_MME_APP, "UE radio context already cached: %s\n",
               ue_context_p->ue_radio_cap_length ? "yes" : "no");
  establishment_cnf_p->ue_radio_cap_length = ue_context_p->ue_radio_cap_length;
  if (establishment_cnf_p->ue_radio_cap_length) {
    establishment_cnf_p->ue_radio_capabilities = 
                (uint8_t*) calloc (establishment_cnf_p->ue_radio_cap_length, sizeof *establishment_cnf_p->ue_radio_capabilities);
    memcpy (establishment_cnf_p->ue_radio_capabilities,
            ue_context_p->ue_radio_capabilities,
            establishment_cnf_p->ue_radio_cap_length);
  }

  bearer_id = ue_context_p->default_bearer_id;
  current_bearer_p = mme_app_is_bearer_context_in_list(ue_context_p->mme_ue_s1ap_id, bearer_id);
  establishment_cnf_p->eps_bearer_id = bearer_id;
  establishment_cnf_p->bearer_s1u_sgw_fteid.interface_type = S1_U_SGW_GTP_U;
  establishment_cnf_p->bearer_s1u_sgw_fteid.teid = current_bearer_p->s_gw_teid;

  if ((current_bearer_p->s_gw_address.pdn_type == IPv4)
      || (current_bearer_p->s_gw_address.pdn_type == IPv4_AND_v6)) {
    establishment_cnf_p->bearer_s1u_sgw_fteid.ipv4 = 1;
    memcpy (&establishment_cnf_p->bearer_s1u_sgw_fteid.ipv4_address, current_bearer_p->s_gw_address.address.ipv4_address, 4);
  }

  if ((current_bearer_p->s_gw_address.pdn_type == IPv6)
      || (current_bearer_p->s_gw_address.pdn_type == IPv4_AND_v6)) {
    establishment_cnf_p->bearer_s1u_sgw_fteid.ipv6 = 1;
    memcpy (establishment_cnf_p->bearer_s1u_sgw_fteid.ipv6_address, current_bearer_p->s_gw_address.address.ipv6_address, 16);
  }

  establishment_cnf_p->bearer_qos_qci = current_bearer_p->qci;
  establishment_cnf_p->bearer_qos_prio_level = current_bearer_p->prio_level;
  establishment_cnf_p->bearer_qos_pre_emp_vulnerability = current_bearer_p->pre_emp_vulnerability;
  establishment_cnf_p->bearer_qos_pre_emp_capability = current_bearer_p->pre_emp_capability;
//#pragma message  "Check ue_context_p ambr"
  establishment_cnf_p->ambr.br_ul = ue_context_p->subscribed_ambr.br_ul;
  establishment_cnf_p->ambr.br_dl = ue_context_p->subscribed_ambr.br_dl;
  establishment_cnf_p->security_capabilities_encryption_algorithms =
    nas_conn_est_cnf_pP->encryption_algorithm_capabilities;
  establishment_cnf_p->security_capabilities_integrity_algorithms =
    nas_conn_est_cnf_pP->integrity_algorithm_capabilities;
  memcpy(establishment_cnf_p->kenb, nas_conn_est_cnf_pP->kenb, AUTH_KASME_SIZE);

  OAILOG_DEBUG (LOG_MME_APP, "security_capabilities_encryption_algorithms 0x%04X\n", establishment_cnf_p->security_capabilities_encryption_algorithms);
  OAILOG_DEBUG (LOG_MME_APP, "security_capabilities_integrity_algorithms  0x%04X\n", establishment_cnf_p->security_capabilities_integrity_algorithms);

  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S1AP_MME, NULL, 0,
                      "0 MME_APP_CONNECTION_ESTABLISHMENT_CNF ebi %u s1u_sgw teid %u qci %u prio level %u sea 0x%x sia 0x%x",
                      establishment_cnf_p->eps_bearer_id,
                      establishment_cnf_p->bearer_s1u_sgw_fteid.teid,
                      establishment_cnf_p->bearer_qos_qci, establishment_cnf_p->bearer_qos_prio_level, establishment_cnf_p->security_capabilities_encryption_algorithms, establishment_cnf_p->security_capabilities_integrity_algorithms);
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);

  /*
   * Move the UE to ECM Connected State.However if S1-U bearer establishment fails then we need to move the UE to idle.
   * S1 Signaling connection gets established via first DL NAS Trasnport message in some scenarios so check the state
   * first 
   */
  if (ue_context_p->ecm_state != ECM_CONNECTED)  /**< It may be that ATTACH_ACCEPT is set directly or when the UE goes back from IDLE mode to active mode.
  Else, the first downlink message sets the UE state to connected, which don't does registration, just stops any inactivity timer.
  Deactivation always should remove the ENB_ID key. */
  {
    mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts,ue_context_p,ECM_CONNECTED);
  }

  /* Start timer to wait for Initial UE Context Response from eNB
   * If timer expires treat this as failure of ongoing procedure and abort corresponding NAS procedure such as ATTACH
   * or SERVICE REQUEST. Send UE context release command to eNB
   */
  if (timer_setup (ue_context_p->initial_context_setup_rsp_timer.sec, 0, 
                TASK_MME_APP, INSTANCE_DEFAULT, TIMER_ONE_SHOT, (void *) &(ue_context_p->mme_ue_s1ap_id), &(ue_context_p->initial_context_setup_rsp_timer.id)) < 0) { 
    OAILOG_ERROR (LOG_MME_APP, "Failed to start initial context setup response timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
  } else {
    OAILOG_DEBUG (LOG_MME_APP, "MME APP : Sent Initial context Setup Request and Started guard timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

// sent by S1AP
//------------------------------------------------------------------------------
void
mme_app_handle_initial_ue_message (
  itti_mme_app_initial_ue_message_t * const initial_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  bool                                    is_guti_valid = false;
  emm_data_context_t                     *ue_nas_ctx = NULL;
  enb_s1ap_id_key_t                       enb_s1ap_id_key = INVALID_ENB_UE_S1AP_ID_KEY;
  void                                   *id = NULL;
  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received MME_APP_INITIAL_UE_MESSAGE from S1AP\n");
    
  DevAssert(INVALID_MME_UE_S1AP_ID == initial_pP->mme_ue_s1ap_id);
   
  // Check if there is any existing UE context using S-TMSI/GUTI
  if (initial_pP->is_s_tmsi_valid) 
  {
    OAILOG_DEBUG (LOG_MME_APP, "INITIAL UE Message: Valid mme_code %u and S-TMSI %u received from eNB.\n",
        initial_pP->opt_s_tmsi.mme_code, initial_pP->opt_s_tmsi.m_tmsi);
    guti_t guti = {.gummei.plmn = {0}, .gummei.mme_gid = 0, .gummei.mme_code = 0, .m_tmsi = INVALID_M_TMSI};
    is_guti_valid = mme_app_construct_guti(&(initial_pP->tai.plmn),&(initial_pP->opt_s_tmsi),&guti);
    if (is_guti_valid)  /**< Can the GUTI belong to this MME. */
    {
      ue_nas_ctx = emm_data_context_get_by_guti (&_emm_data, &guti);
      if (ue_nas_ctx) 
      {
        // Get the UE context using mme_ue_s1ap_id 
        ue_context_p =  mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts,ue_nas_ctx->ue_id);
        DevAssert(ue_context_p != NULL);
        if ((ue_context_p != NULL) && (ue_context_p->mme_ue_s1ap_id == ue_nas_ctx->ue_id)) {
          initial_pP->mme_ue_s1ap_id = ue_nas_ctx->ue_id;
          if (ue_context_p->enb_s1ap_id_key != INVALID_ENB_UE_S1AP_ID_KEY)
          {
            /*
             * Ideally this should never happen. When UE move to IDLE this key is set to INVALID.
             * Note - This can happen if eNB detects RLF late and by that time UE sends Initial NAS message via new RRC
             * connection.
             * However if this key is valid, remove the key from the hashtable.
             */

            hashtable_rc_t result_deletion = hashtable_ts_remove (mme_app_desc.mme_ue_contexts.enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)ue_context_p->enb_s1ap_id_key, (void **)&id);
            OAILOG_ERROR (LOG_MME_APP, "MME_APP_INITAIL_UE_MESSAGE. ERROR***** enb_s1ap_id_key %ld has valid value %ld. Result of deletion %d.\n" ,
                ue_context_p->enb_s1ap_id_key,
                ue_context_p->enb_ue_s1ap_id,
                result_deletion);
            ue_context_p->enb_s1ap_id_key = INVALID_ENB_UE_S1AP_ID_KEY;
          }
          // Update MME UE context with new enb_ue_s1ap_id
          ue_context_p->enb_ue_s1ap_id = initial_pP->enb_ue_s1ap_id;
          // regenerate the enb_s1ap_id_key as enb_ue_s1ap_id is changed.
          MME_APP_ENB_S1AP_ID_KEY(enb_s1ap_id_key, initial_pP->enb_id, initial_pP->enb_ue_s1ap_id);
          // Update enb_s1ap_id_key in hashtable  
          mme_ue_context_update_coll_keys( &mme_app_desc.mme_ue_contexts,
                ue_context_p,
                enb_s1ap_id_key,
                ue_nas_ctx->ue_id,
                ue_nas_ctx->_imsi64,
                ue_context_p->mme_s11_teid,
                ue_context_p->local_mme_s10_teid,
                &guti);
        }
      } else {
          OAILOG_DEBUG (LOG_MME_APP, "MME_APP_INITIAL_UE_MESSAGE with mme code %u and S-TMSI %u:"
            "no UE context found \n", initial_pP->opt_s_tmsi.mme_code, initial_pP->opt_s_tmsi.m_tmsi);
          /** Check that also no MME_APP UE context exists for the given GUTI. */
          DevAssert(mme_ue_context_exists_guti(&mme_app_desc.mme_ue_contexts, &guti) == NULL);
      }
    } else {
      OAILOG_DEBUG (LOG_MME_APP, "No MME is configured with MME code %u received in S-TMSI %u from UE.\n",
                    initial_pP->opt_s_tmsi.mme_code, initial_pP->opt_s_tmsi.m_tmsi);
      DevAssert(mme_ue_context_exists_guti(&mme_app_desc.mme_ue_contexts, &guti) == NULL);
    }
  } else {
    OAILOG_DEBUG (LOG_MME_APP, "MME_APP_INITIAL_UE_MESSAGE from S1AP,without S-TMSI. \n"); /**< Continue with new UE context establishment. */
  }
  // create a new ue context if nothing is found
  if (!(ue_context_p)) {
    OAILOG_DEBUG (LOG_MME_APP, "UE context doesn't exist -> create one \n");
    if ((ue_context_p = mme_create_new_ue_context ()) == NULL) {
      /*
       * Error during ue context malloc
       */
      DevMessage ("mme_create_new_ue_context");
      OAILOG_FUNC_OUT (LOG_MME_APP);
    }
    // Allocate new mme_ue_s1ap_id
    ue_context_p->mme_ue_s1ap_id    = mme_app_ctx_get_new_ue_id ();
    if (ue_context_p->mme_ue_s1ap_id  == INVALID_MME_UE_S1AP_ID) {
      OAILOG_CRITICAL (LOG_MME_APP, "MME_APP_INITIAL_UE_MESSAGE. MME_UE_S1AP_ID allocation Failed.\n");
      mme_remove_ue_context (&mme_app_desc.mme_ue_contexts, ue_context_p);
      OAILOG_FUNC_OUT (LOG_MME_APP);
    }
    OAILOG_DEBUG (LOG_MME_APP, "MME_APP_INITAIL_UE_MESSAGE.Allocated new MME UE context and new mme_ue_s1ap_id. %d\n",ue_context_p->mme_ue_s1ap_id);
    ue_context_p->enb_ue_s1ap_id    = initial_pP->enb_ue_s1ap_id;
    MME_APP_ENB_S1AP_ID_KEY(ue_context_p->enb_s1ap_id_key, initial_pP->enb_id, initial_pP->enb_ue_s1ap_id);
    DevAssert (mme_insert_ue_context (&mme_app_desc.mme_ue_contexts, ue_context_p) == 0);
  }
  ue_context_p->sctp_assoc_id_key = initial_pP->sctp_assoc_id;
  ue_context_p->e_utran_cgi = initial_pP->cgi;
  // Notify S1AP about the mapping between mme_ue_s1ap_id and sctp assoc id + enb_ue_s1ap_id 
  notify_s1ap_new_ue_mme_s1ap_id_association (ue_context_p);
  // Initialize timers to INVALID IDs
  ue_context_p->mobile_reachability_timer.id = MME_APP_TIMER_INACTIVE_ID;
  ue_context_p->implicit_detach_timer.id = MME_APP_TIMER_INACTIVE_ID;
  ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
  ue_context_p->initial_context_setup_rsp_timer.sec = MME_APP_INITIAL_CONTEXT_SETUP_RSP_TIMER_VALUE;

  message_p = itti_alloc_new_message (TASK_MME_APP, NAS_INITIAL_UE_MESSAGE);
  // do this because of same message types name but not same struct in different .h
  message_p->ittiMsg.nas_initial_ue_message.nas.ue_id           = ue_context_p->mme_ue_s1ap_id;
  message_p->ittiMsg.nas_initial_ue_message.nas.tai             = initial_pP->tai;
  message_p->ittiMsg.nas_initial_ue_message.nas.cgi             = initial_pP->cgi;
  message_p->ittiMsg.nas_initial_ue_message.nas.as_cause        = initial_pP->as_cause;
  if (initial_pP->is_s_tmsi_valid) {
    message_p->ittiMsg.nas_initial_ue_message.nas.s_tmsi        = initial_pP->opt_s_tmsi;
  } else {
    message_p->ittiMsg.nas_initial_ue_message.nas.s_tmsi.mme_code = 0;
    message_p->ittiMsg.nas_initial_ue_message.nas.s_tmsi.m_tmsi   = INVALID_M_TMSI;
  }
  message_p->ittiMsg.nas_initial_ue_message.nas.initial_nas_msg   =  initial_pP->nas;
  memcpy (&message_p->ittiMsg.nas_initial_ue_message.transparent, (const void*)&initial_pP->transparent, sizeof (message_p->ittiMsg.nas_initial_ue_message.transparent));
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_INITIAL_UE_MESSAGE");
  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_delete_session_rsp (
  const itti_s11_delete_session_response_t * const delete_sess_resp_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  void                                   *id = NULL;
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (delete_sess_resp_pP );
  OAILOG_DEBUG (LOG_MME_APP, "Received S11_DELETE_SESSION_RESPONSE from S+P-GW with teid " TEID_FMT "\n ",delete_sess_resp_pP->teid);
  ue_context_p = mme_ue_context_exists_s11_teid (&mme_app_desc.mme_ue_contexts, delete_sess_resp_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 DELETE_SESSION_RESPONSE local S11 teid " TEID_FMT " ", delete_sess_resp_pP->teid);
    OAILOG_WARNING (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", delete_sess_resp_pP->teid);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }

  /**
   * Object is later removed, not here. For unused keys, this is no problem, just deregistrate the tunnel ids for the MME_APP
   * UE context from the hashtable.
   * If this is not done, later at removal of the MME_APP UE context, the S11 keys will be checked and removed again if still existing.
   *
   * todo: For multi-apn, checking if more APNs exist or removing later?
   */
  hashtable_ts_remove(mme_app_desc.mme_ue_contexts.tun11_ue_context_htbl,
                      (const hash_key_t) ue_context_p->mme_s11_teid, &id);
  ue_context_p->mme_s11_teid = 0;
  ue_context_p->sgw_s11_teid = 0;

  if (delete_sess_resp_pP->cause != REQUEST_ACCEPTED) {
    OAILOG_WARNING (LOG_MME_APP, "***WARNING****S11 Delete Session Rsp: NACK received from SPGW : %08x\n", delete_sess_resp_pP->teid);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 DELETE_SESSION_RESPONSE local S11 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
    delete_sess_resp_pP->teid, ue_context_p->imsi);
  /*
   * Updating statistics
   */
  update_mme_app_stats_s1u_bearer_sub();
  update_mme_app_stats_default_bearer_sub();
  
  /**
   * No recursion needed any more. This will just inform the EMM/ESM that a PDN session has been deactivated.
   * It will determine if its a PDN Disconnectivity or detach.
   */
  message_p = itti_alloc_new_message (TASK_MME_APP, NAS_PDN_DISCONNECT_RSP);
  // do this because of same message types name but not same struct in different .h
  message_p->ittiMsg.nas_pdn_disconnect_rsp.ue_id           = ue_context_p->mme_ue_s1ap_id;
  message_p->ittiMsg.nas_pdn_disconnect_rsp.cause           = REQUEST_ACCEPTED;
  message_p->ittiMsg.nas_pdn_disconnect_rsp.pdn_default_ebi = 5; /**< An indicator!. */
//  message_p->ittiMsg.nas_pdn_disconnect_rsp.pti             = PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED; /**< todo: set the PTI received by UE (store in transaction). */
  // todo: later add default ebi id or pdn name to check which PDN that was!
  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);

  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
int
mme_app_handle_create_sess_resp (
  const itti_s11_create_session_response_t * const create_sess_resp_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  bearer_context_t                       *current_bearer_p = NULL;
  MessageDef                             *message_p = NULL;
  int16_t                                 bearer_id =0;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (create_sess_resp_pP );
  OAILOG_DEBUG (LOG_MME_APP, "Received S11_CREATE_SESSION_RESPONSE from S+P-GW\n");
  ue_context_p = mme_ue_context_exists_s11_teid (&mme_app_desc.mme_ue_contexts, create_sess_resp_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 CREATE_SESSION_RESPONSE local S11 teid " TEID_FMT " ", create_sess_resp_pP->teid);

    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", create_sess_resp_pP->teid);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 CREATE_SESSION_RESPONSE local S11 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
    create_sess_resp_pP->teid, ue_context_p->imsi);

  /* Whether SGW has created the session (IP address allocation, local GTP-U end point creation etc.) 
   * successfully or not , it is indicated by cause value in create session response message.
   * If cause value is not equal to "REQUEST_ACCEPTED" then this implies that SGW could not allocate the resources for
   * the requested session. In this case, MME-APP sends PDN Connectivity fail message to NAS-ESM with the "cause" received
   * in S11 Session Create Response message. 
   * NAS-ESM maps this "S11 cause" to "ESM cause" and sends it in PDN Connectivity Reject message to the UE.
   */

  if (create_sess_resp_pP->cause != REQUEST_ACCEPTED) {
    // todo: if handover flag was active.. terminate the forward relocation procedure with a reject + remove the contexts & tunnel endpoints.
    /**
     * Send PDN CONNECTIVITY FAIL message to NAS layer.
     * For TAU/Attach case, a reject message will be sent and the UE contexts will be terminated.
     */
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_PDN_CONNECTIVITY_FAIL);
    itti_nas_pdn_connectivity_fail_t *nas_pdn_connectivity_fail = &message_p->ittiMsg.nas_pdn_connectivity_fail;
    memset ((void *)nas_pdn_connectivity_fail, 0, sizeof (itti_nas_pdn_connectivity_fail_t));
    nas_pdn_connectivity_fail->pti = ue_context_p->pending_pdn_connectivity_req_pti;  
    nas_pdn_connectivity_fail->ue_id = ue_context_p->pending_pdn_connectivity_req_ue_id; 
    nas_pdn_connectivity_fail->cause = (pdn_conn_rsp_cause_t)(create_sess_resp_pP->cause); 
    rc = itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
    OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
  }

  /**
   * Store the S-GW teid
   */
  ue_context_p->sgw_s11_teid = create_sess_resp_pP->s11_sgw_teid.teid;
  //---------------------------------------------------------
  // Process itti_sgw_create_session_response_t.bearer_context_created
  //---------------------------------------------------------

  // todo: for handover with dedicated bearers --> iterate through bearer contexts!
  // todo: the MME will send an S10 message with the filters to the target MME --> which would then create a Create Session Request with multiple bearers..
  // todo: all the bearer contexts in the response should then be handled! (or do it via BRC // meshed PCRF).
  bearer_id = create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].eps_bearer_id /* - 5 */ ;
  /*
   * Depending on s11 result we have to send reject or accept for bearers
   */
  DevCheck ((bearer_id < BEARERS_PER_UE)
            && (bearer_id >= 0), bearer_id, BEARERS_PER_UE, 0);
  ue_context_p->default_bearer_id = bearer_id;

  if (create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].cause != REQUEST_ACCEPTED) {
    DevMessage ("Cases where bearer cause != REQUEST_ACCEPTED are not handled\n");
  }

  DevAssert (create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s1u_sgw_fteid.interface_type == S1_U_SGW_GTP_U);
  /*
   * Updating statistics
   */
  update_mme_app_stats_default_bearer_add();

  /** Try to get a new bearer context in the UE_Context. */
  if ((current_bearer_p = mme_app_create_new_bearer_context(ue_context_p, bearer_id)) == NULL) {
      // If we failed to allocate a new bearer context
      OAILOG_ERROR (LOG_MME_APP, "Failed to allocate a new bearer context with EBI %d for mmeUeS1apId:" MME_UE_S1AP_ID_FMT "\n", bearer_id, ue_context_p->mme_ue_s1ap_id);
      OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  current_bearer_p = mme_app_is_bearer_context_in_list(ue_context_p->mme_ue_s1ap_id, bearer_id);
  current_bearer_p->s_gw_teid = create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s1u_sgw_fteid.teid;

  switch (create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s1u_sgw_fteid.ipv4 +
      (create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s1u_sgw_fteid.ipv6 << 1)) {
  default:
  case 0:{
      /*
       * No address provided: impossible case
       */
      DevMessage ("No ip address for user-plane provided...\n");
    }
    break;

  case 1:{
      /*
       * Only IPv4 address
       */
      current_bearer_p->s_gw_address.pdn_type = IPv4;
      memcpy (current_bearer_p->s_gw_address.address.ipv4_address, &create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s1u_sgw_fteid.ipv4_address, 4);
    }
    break;

  case 2:{
      /*
       * Only IPv6 address
       */
      current_bearer_p->s_gw_address.pdn_type = IPv6;
      memcpy (current_bearer_p->s_gw_address.address.ipv6_address, create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s1u_sgw_fteid.ipv6_address, 16);
    }
    break;

  case 3:{
      /*
       * Both IPv4 and Ipv6
       */
      current_bearer_p->s_gw_address.pdn_type = IPv4_AND_v6;
      memcpy (current_bearer_p->s_gw_address.address.ipv4_address, &create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s1u_sgw_fteid.ipv4_address, 4);
      memcpy (current_bearer_p->s_gw_address.address.ipv6_address, create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s1u_sgw_fteid.ipv6_address, 16);
    }
    break;
  }

  current_bearer_p->p_gw_teid = create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].s5_s8_u_pgw_fteid.teid;
  memset (&current_bearer_p->p_gw_address, 0, sizeof (ip_address_t));

  if (create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].bearer_level_qos ) {
    // Bearer
    current_bearer_p->qci = create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].bearer_level_qos->qci;
    current_bearer_p->prio_level = create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].bearer_level_qos->pl;
    current_bearer_p->pre_emp_vulnerability = create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].bearer_level_qos->pvi;
    current_bearer_p->pre_emp_capability = create_sess_resp_pP->bearer_contexts_created.bearer_contexts[0].bearer_level_qos->pci;
    OAILOG_DEBUG (LOG_MME_APP, "Set qci %u in bearer %u\n", current_bearer_p->qci, ue_context_p->default_bearer_id);
  } else {
    // if null, it is not modified
    //current_bearer_p->qci                    = ue_context_p->pending_pdn_connectivity_req_qos.qci;
//#pragma message  "may force QCI here to 9"
    current_bearer_p->qci = 9;
    current_bearer_p->prio_level = 1;
    current_bearer_p->pre_emp_vulnerability = PRE_EMPTION_VULNERABILITY_ENABLED;
    current_bearer_p->pre_emp_capability = PRE_EMPTION_CAPABILITY_ENABLED;
    OAILOG_DEBUG (LOG_MME_APP, "Set qci %u in bearer %u (qos not modified by S/P-GW)\n", current_bearer_p->qci, ue_context_p->default_bearer_id);
  }

  mme_app_dump_ue_contexts (&mme_app_desc.mme_ue_contexts);
  {
    /** Check if a NAS UE context exist, if so continue, if not check if it is a S10 Handover Procedure. */
    emm_data_context_t *ue_nas_ctx = emm_data_context_get_by_imsi (&_emm_data, ue_context_p->imsi);
    if (ue_nas_ctx) {
      OAILOG_INFO (LOG_MME_APP, "Informing the NAS layer about the received CREATE_SESSION_REQUEST for UE " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->mme_ue_s1ap_id);
      //uint8_t *keNB = NULL;
      message_p = itti_alloc_new_message (TASK_MME_APP, NAS_PDN_CONNECTIVITY_RSP);
      itti_nas_pdn_connectivity_rsp_t *nas_pdn_connectivity_rsp = &message_p->ittiMsg.nas_pdn_connectivity_rsp;
      memset ((void *)nas_pdn_connectivity_rsp, 0, sizeof (itti_nas_pdn_connectivity_rsp_t));
      // moved to NAS_CONNECTION_ESTABLISHMENT_CONF, keNB not handled in NAS MME
      //derive_keNB(ue_context_p->vector_in_use->kasme, 156, &keNB);
      //memcpy(NAS_PDN_CONNECTIVITY_RSP(message_p).keNB, keNB, 32);
      //free(keNB);
      /** Check if this is a handover procedure, set the flag. Don't reset the MME_APP UE context flag till HANDOVER_NOTIFY is received. */
      // todo: states don't match for handover!
  //    if(ue_context_p->mm_state == UE_REGISTERED && (ue_context_p->handover_info != NULL)){
  //      nas_pdn_connectivity_rsp->pending_mobility = true;
  //      /**
  //       * The Handover Information will still be kept in the UE context and not used until HANDOVER_REQUEST is sent to the target ENB..
  //       * Sending CSR may only imply S1AP momentarily.. X2AP is assumed not to switch SAE-GWs (todo: not supported yet).
  //       */
  //    }
      nas_pdn_connectivity_rsp->pti = ue_context_p->pending_pdn_connectivity_req_pti;  // NAS internal ref
      nas_pdn_connectivity_rsp->ue_id = ue_context_p->pending_pdn_connectivity_req_ue_id;      // NAS internal ref

      // TO REWORK:
      if (ue_context_p->pending_pdn_connectivity_req_apn) {
        nas_pdn_connectivity_rsp->apn = bstrcpy (ue_context_p->pending_pdn_connectivity_req_apn);
        bdestroy(ue_context_p->pending_pdn_connectivity_req_apn);
        OAILOG_DEBUG (LOG_MME_APP, "SET APN FROM NAS PDN CONNECTIVITY CREATE: %s\n", bdata(nas_pdn_connectivity_rsp->apn));
      }
      //else {
      int                                     i;
      context_identifier_t                    context_identifier = ue_context_p->apn_profile.context_identifier;

      // todo: for the s1ap handover case, no apn configuration exists yet..
      for (i = 0; i < ue_context_p->apn_profile.nb_apns; i++) {
        if (ue_context_p->apn_profile.apn_configuration[i].context_identifier == context_identifier) {
          AssertFatal (ue_context_p->apn_profile.apn_configuration[i].service_selection_length > 0, "Bad APN string (len = 0)");

          if (ue_context_p->apn_profile.apn_configuration[i].service_selection_length > 0) {
            nas_pdn_connectivity_rsp->apn = blk2bstr(ue_context_p->apn_profile.apn_configuration[i].service_selection,
                ue_context_p->apn_profile.apn_configuration[i].service_selection_length);
            AssertFatal (ue_context_p->apn_profile.apn_configuration[i].service_selection_length <= APN_MAX_LENGTH, "Bad APN string length %d",
                ue_context_p->apn_profile.apn_configuration[i].service_selection_length);

            OAILOG_DEBUG (LOG_MME_APP, "SET APN FROM HSS ULA: %s\n", bdata(nas_pdn_connectivity_rsp->apn));
            break;
          }
        }
      }
      //    }
      OAILOG_DEBUG (LOG_MME_APP, "APN: %s\n", bdata(nas_pdn_connectivity_rsp->apn));
      switch (create_sess_resp_pP->paa.pdn_type) {
      case IPv4:
        nas_pdn_connectivity_rsp->pdn_addr = blk2bstr(create_sess_resp_pP->paa.ipv4_address, 4);
        DevAssert (nas_pdn_connectivity_rsp->pdn_addr);
        break;

      case IPv6:
        DevAssert (create_sess_resp_pP->paa.ipv6_prefix_length == 64);    // NAS seems to only support 64 bits
        nas_pdn_connectivity_rsp->pdn_addr = blk2bstr(create_sess_resp_pP->paa.ipv6_address, create_sess_resp_pP->paa.ipv6_prefix_length / 8);
        DevAssert (nas_pdn_connectivity_rsp->pdn_addr);
        break;

      case IPv4_AND_v6:
        DevAssert (create_sess_resp_pP->paa.ipv6_prefix_length == 64);    // NAS seems to only support 64 bits
        nas_pdn_connectivity_rsp->pdn_addr = blk2bstr(create_sess_resp_pP->paa.ipv4_address, 4 + create_sess_resp_pP->paa.ipv6_prefix_length / 8);
        DevAssert (nas_pdn_connectivity_rsp->pdn_addr);
        bcatblk(nas_pdn_connectivity_rsp->pdn_addr, create_sess_resp_pP->paa.ipv6_address, create_sess_resp_pP->paa.ipv6_prefix_length / 8);
        break;

      case IPv4_OR_v6:
        nas_pdn_connectivity_rsp->pdn_addr = blk2bstr(create_sess_resp_pP->paa.ipv4_address, 4);
        DevAssert (nas_pdn_connectivity_rsp->pdn_addr);
        break;

      default:
        DevAssert (0);
      }
      // todo: IP address strings are not cleared

      nas_pdn_connectivity_rsp->pdn_type = create_sess_resp_pP->paa.pdn_type;
      nas_pdn_connectivity_rsp->proc_data = ue_context_p->pending_pdn_connectivity_req_proc_data;      // NAS internal ref
      ue_context_p->pending_pdn_connectivity_req_proc_data = NULL;
  //#pragma message  "QOS hardcoded here"
      //memcpy(&NAS_PDN_CONNECTIVITY_RSP(message_p).qos,
      //        &ue_context_p->pending_pdn_connectivity_req_qos,
      //        sizeof(network_qos_t));
      nas_pdn_connectivity_rsp->qos.gbrUL = 64;        /* 64=64kb/s   Guaranteed Bit Rate for uplink   */
      nas_pdn_connectivity_rsp->qos.gbrDL = 120;       /* 120=512kb/s Guaranteed Bit Rate for downlink */
      nas_pdn_connectivity_rsp->qos.mbrUL = 72;        /* 72=128kb/s   Maximum Bit Rate for uplink      */
      nas_pdn_connectivity_rsp->qos.mbrDL = 135;       /*135=1024kb/s Maximum Bit Rate for downlink    */
      /*
       * Note : Above values are insignificant because bearer with QCI = 9 is NON-GBR bearer and ESM would not include GBR and MBR values
       * in Activate Default EPS Bearer Context Setup Request message
       */
      nas_pdn_connectivity_rsp->qos.qci = 9;   /* QoS Class Identifier                           */
      nas_pdn_connectivity_rsp->request_type = ue_context_p->pending_pdn_connectivity_req_request_type;        // NAS internal ref
      ue_context_p->pending_pdn_connectivity_req_request_type = 0;
      // here at this point OctetString are saved in resp, no loss of memory (apn, pdn_addr)
      nas_pdn_connectivity_rsp->ue_id = ue_context_p->mme_ue_s1ap_id;
      nas_pdn_connectivity_rsp->ebi = bearer_id;
      nas_pdn_connectivity_rsp->qci = current_bearer_p->qci;
      nas_pdn_connectivity_rsp->prio_level = current_bearer_p->prio_level;
      nas_pdn_connectivity_rsp->pre_emp_vulnerability = current_bearer_p->pre_emp_vulnerability;
      nas_pdn_connectivity_rsp->pre_emp_capability = current_bearer_p->pre_emp_capability;
      nas_pdn_connectivity_rsp->sgw_s1u_teid = current_bearer_p->s_gw_teid;
      memcpy (&nas_pdn_connectivity_rsp->sgw_s1u_address, &current_bearer_p->s_gw_address, sizeof (ip_address_t));
      nas_pdn_connectivity_rsp->ambr.br_ul = ue_context_p->subscribed_ambr.br_ul;
      nas_pdn_connectivity_rsp->ambr.br_dl = ue_context_p->subscribed_ambr.br_dl;
      copy_protocol_configuration_options (&nas_pdn_connectivity_rsp->pco, &create_sess_resp_pP->pco);
      clear_protocol_configuration_options(&create_sess_resp_pP->pco);

      MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_PDN_CONNECTIVITY_RSP sgw_s1u_teid %u ebi %u qci %u prio %u", current_bearer_p->s_gw_teid, bearer_id, current_bearer_p->qci, current_bearer_p->prio_level);

      rc = itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
      OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
    }else{
      OAILOG_INFO(LOG_MME_APP, "NO EMM_CONTEXT exists for UE " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->mme_ue_s1ap_id);
      // todo: We have the indicator of handover in the CREATE_SESSION_REQUEST operational flags.
      if(ue_context_p->pending_s10_response_trxn){
        OAILOG_INFO(LOG_MME_APP, "UE " MME_UE_S1AP_ID_FMT " is performing an S10 handover. Sending an S1AP_HANDOVER_REQUEST. \n", ue_context_p->mme_ue_s1ap_id);
        mme_app_send_s1ap_handover_request(ue_context_p->mme_ue_s1ap_id, ue_context_p->pending_handover_enb_id,
                   ue_context_p->pending_mm_ue_eps_context->ue_nc.eea,
                   ue_context_p->pending_mm_ue_eps_context->ue_nc.eia,
                   ue_context_p->pending_mm_ue_eps_context->nh,
                   ue_context_p->pending_mm_ue_eps_context->ncc);
        OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNok);
      }else{
        OAILOG_CRITICAL(LOG_MME_APP, "CREATE_SESSION_RESPONSE received for invalid UE " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->mme_ue_s1ap_id);
        /** Deallocate the ue context and remove from MME_APP map. */
        mme_remove_ue_context (&mme_app_desc.mme_ue_contexts, ue_context_p);
        /** Not sending back failure. */
        OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
      }

    }
  }
  OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNok);
}

//------------------------------------------------------------------------------
int
mme_app_handle_modify_bearer_resp (
  const itti_s11_modify_bearer_response_t * const modify_bearer_resp_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  bearer_context_t                       *current_bearer_p = NULL;
  MessageDef                             *message_p = NULL;
  int16_t                                 bearer_id =5;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (modify_bearer_resp_pP );
  OAILOG_DEBUG (LOG_MME_APP, "Received S11_MODIFY_BEARER_RESPONSE from S+P-GW\n");
  ue_context_p = mme_ue_context_exists_s11_teid (&mme_app_desc.mme_ue_contexts, modify_bearer_resp_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 MODIFY_BEARER_RESPONSE local S11 teid " TEID_FMT " ", modify_bearer_resp_pP->teid);

    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", modify_bearer_resp_pP->teid);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 MODIFY_BEARER_RESPONSE local S11 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
      modify_bearer_resp_pP->teid, ue_context_p->imsi);
  /*
   * Updating statistics
   */
  if (modify_bearer_resp_pP->cause != REQUEST_ACCEPTED) {
    /**
     * Check if it is an X2 Handover procedure, in that case send an X2 Path Switch Request Failure to the target MME.
     * In addition, perform an implicit detach in any case.
     */
    if(ue_context_p->pending_x2_handover){
      OAILOG_ERROR(LOG_MME_APP, "Error modifying SAE-GW bearers for UE with ueId: " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->mme_ue_s1ap_id);
      mme_app_send_s1ap_path_switch_request_failure(ue_context_p->mme_ue_s1ap_id, ue_context_p->enb_ue_s1ap_id, ue_context_p->sctp_assoc_id_key, SYSTEM_FAILURE);
    }
    /** Implicitly detach the UE --> If EMM context is missing, still continue with the resource removal. */
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNok);
  }
  current_bearer_p =  mme_app_is_bearer_context_in_list(ue_context_p->mme_ue_s1ap_id, ue_context_p->default_bearer_id);
  /** If it is an X2 Handover, send a path switch response back. */
  if(ue_context_p->pending_x2_handover){
    OAILOG_INFO(LOG_MME_APP, "Sending an S1AP Path Switch Request Acknowledge for for UE with ueId: " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->mme_ue_s1ap_id);
    mme_app_send_s1ap_path_switch_request_acknowledge(ue_context_p->mme_ue_s1ap_id);
  }
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}

//------------------------------------------------------------------------------
void
mme_app_handle_downlink_data_notification(const itti_s11_downlink_data_notification_t * const saegw_dl_data_ntf_pP){
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  int16_t                                 bearer_id =5;
  int                                     rc = RETURNok;

  SGWCause_t                              cause;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (saegw_dl_data_ntf_pP );
  DevAssert (saegw_dl_data_ntf_pP->trxn);

  OAILOG_DEBUG (LOG_MME_APP, "Received S11_DOWNLINK_DATA_NOTIFICATION from S+P-GW\n");
  ue_context_p = mme_ue_context_exists_s11_teid (&mme_app_desc.mme_ue_contexts, saegw_dl_data_ntf_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "DOWNLINK_DATA_NOTIFICATION FROM local S11 teid " TEID_FMT " ", saegw_dl_data_ntf_pP->teid);
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", saegw_dl_data_ntf_pP->teid);
    /** Send a DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE. */
    mme_app_send_downlink_data_notification_acknowledge(CONTEXT_NOT_FOUND, saegw_dl_data_ntf_pP->teid, saegw_dl_data_ntf_pP->trxn);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "DOWNLINK_DATA_NOTIFICATION for local S11 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
      saegw_dl_data_ntf_pP->teid, ue_context_p->imsi);

  /** Check that the UE is in idle mode!. */
  if (ECM_IDLE != ue_context_p->ecm_state) {
    OAILOG_ERROR (LOG_MME_APP, "UE_Context with IMSI " IMSI_64_FMT " and mmeUeS1apId: %d. \n is not in ECM_IDLE mode, insted %d. \n",
        ue_context_p->imsi, ue_context_p->mme_ue_s1ap_id, ue_context_p->ecm_state);
    // todo: later.. check this more granularly
    mme_app_send_downlink_data_notification_acknowledge(UE_ALREADY_REATTACHED, saegw_dl_data_ntf_pP->teid, saegw_dl_data_ntf_pP->trxn);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }

  /** UE is in idle mode. Triggering paging and responding positively. */
  /** Check if any paging_timeout timer is running, if so ignore the received request. */
  if(ue_context_p->mme_paging_timeout_timer.id != MME_APP_TIMER_INACTIVE_ID){
    // todo: ignore or respond with further result code true?!
    OAILOG_INFO(LOG_MME_APP, "MME_PAGING_TIMEOUT_TIMER %u, is still running. Ignoring further DL_DATA_NOTIFICATIONS for imsi " IMSI_64_FMT ". \n",
        ue_context_p->mme_paging_timeout_timer.id, ue_context_p->imsi);
    OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
  }
  OAILOG_INFO(LOG_MME_APP, "MME_MOBILTY_COMPLETION timer is not running. Starting paging procedure for UE with imsi " IMSI_64_FMT ". \n", ue_context_p->imsi);

  // todo: timeout to wait to ignore further DL_DATA_NOTIF messages->
  mme_app_send_downlink_data_notification_acknowledge(REQUEST_ACCEPTED, saegw_dl_data_ntf_pP->teid, saegw_dl_data_ntf_pP->trxn);

  /** Start the paging timeout timer. */
  if (timer_setup (mme_config.mme_paging_timeout_timer, 0,
                TASK_MME_APP, INSTANCE_DEFAULT, TIMER_ONE_SHOT, (void *) &(ue_context_p->mme_ue_s1ap_id), &(ue_context_p->mme_mobility_completion_timer.id)) < 0) {
    OAILOG_ERROR (LOG_MME_APP, "Failed to start initial context setup response timer for UE id  %d for duration %d \n", ue_context_p->mme_ue_s1ap_id, mme_config.mme_mobility_completion_timer);
    ue_context_p->mme_paging_timeout_timer.id = MME_APP_TIMER_INACTIVE_ID;
    // todo: do some appropriate error handling..
  } else {
    OAILOG_DEBUG (LOG_MME_APP, "MME APP : Handled Downlink Data Notification message from SAE-GW. "
        "Activated the MME paging completion timer UE id  %d. Waiting for UE to go back from IDLE mode to ACTIVE mode.. Timer Id %u. Timer duration %d \n",
        ue_context_p->mme_ue_s1ap_id, ue_context_p->mme_paging_timeout_timer.id, mme_config.mme_paging_timeout_timer);
    /** Upon expiration, invalidate the timer.. no flag needed. */
  }

  // todo: no downlink data notification failure and just removing the UE?

  /** Do paging on S1AP interface. */
  message_p = itti_alloc_new_message (TASK_MME_APP, S1AP_PAGING);
  DevAssert (message_p != NULL);
  itti_s1ap_paging_t *s1ap_paging_p = &message_p->ittiMsg.s1ap_paging;

  memset (s1ap_paging_p, 0, sizeof (itti_s1ap_paging_t));
  s1ap_paging_p->mme_ue_s1ap_id = ue_context_p->mme_ue_s1ap_id; /**< Just MME_UE_S1AP_ID. */
  s1ap_paging_p->ue_identity_index = (ue_context_p->imsi %1024) & 0xFFFF; /**< Just MME_UE_S1AP_ID. */
  s1ap_paging_p->tmsi = ue_context_p->guti.m_tmsi;
  // todo: these ones may differ from GUTI?
  s1ap_paging_p->tai.plmn = ue_context_p->guti.gummei.plmn;
  s1ap_paging_p->tai.tac  = *mme_config.served_tai.tac;

  /** S1AP Paging. */
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);

  OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
}

void
mme_app_send_downlink_data_notification_acknowledge(SGWCause_t cause, teid_t saegw_s11_teid, void *trxn){
  OAILOG_FUNC_IN (LOG_MME_APP);

  /** Send a Downlink Data Notification Acknowledge with cause. */
  MessageDef * message_p = itti_alloc_new_message (TASK_MME_APP, S11_DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE);
  DevAssert (message_p != NULL);

  itti_s11_downlink_data_notification_acknowledge_t *downlink_data_notification_ack_p = &message_p->ittiMsg.s11_downlink_data_notification_acknowledge;
  memset ((void*)downlink_data_notification_ack_p, 0, sizeof (itti_s11_downlink_data_notification_acknowledge_t));
  // todo: s10 TEID set every time?
  downlink_data_notification_ack_p->teid = saegw_s11_teid; // todo: ue_context_pP->mme_s10_teid;
  /** No Local TEID exists yet.. no local S10 tunnel is allocated. */
  // todo: currently only just a single MME is allowed.
  downlink_data_notification_ack_p->peer_ip = mme_config.ipv4.sgw_s11;

  downlink_data_notification_ack_p->cause = cause;
  downlink_data_notification_ack_p->trxn  = trxn;

  /** Deallocate the contaier in the FORWARD_RELOCATION_REQUEST.  */
  // todo: how is this deallocated

  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "MME_APP Sending S11 DOWNLINK_DATA_NOTIFICATION_ACK");

  /** Sending a message to S10. */
  itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);

  OAILOG_FUNC_OUT (LOG_MME_APP);
}


//------------------------------------------------------------------------------
void
mme_app_handle_initial_context_setup_rsp (
  const itti_mme_app_initial_context_setup_rsp_t * const initial_ctxt_setup_rsp_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received MME_APP_INITIAL_CONTEXT_SETUP_RSP from S1AP\n");
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, initial_ctxt_setup_rsp_pP->mme_ue_s1ap_id);

  if (ue_context_p == NULL) {
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this mme_ue_s1ap_id in list of UE: %08x %d(dec)\n", initial_ctxt_setup_rsp_pP->mme_ue_s1ap_id, initial_ctxt_setup_rsp_pP->mme_ue_s1ap_id);
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "MME_APP_INITIAL_CONTEXT_SETUP_RSP Unknown ue %u", initial_ctxt_setup_rsp_pP->mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  // Stop Initial context setup process guard timer,if running 
  if (ue_context_p->initial_context_setup_rsp_timer.id != MME_APP_TIMER_INACTIVE_ID) {
    if (timer_remove(ue_context_p->initial_context_setup_rsp_timer.id)) {
      OAILOG_ERROR (LOG_MME_APP, "Failed to stop Initial Context Setup Rsp timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    } 
    ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
  }
  /** Save the bearer information as pending or send it directly if UE is registered. */
  if(ue_context_p->mm_state == UE_REGISTERED){
    /** Send the DL-GTP Tunnel Information to the SAE-GW. */
    message_p = itti_alloc_new_message (TASK_MME_APP, S11_MODIFY_BEARER_REQUEST);
    AssertFatal (message_p , "itti_alloc_new_message Failed");
    itti_s11_modify_bearer_request_t *s11_modify_bearer_request = &message_p->ittiMsg.s11_modify_bearer_request;
    memset ((void *)s11_modify_bearer_request, 0, sizeof (*s11_modify_bearer_request));
    s11_modify_bearer_request->peer_ip = mme_config.ipv4.sgw_s11;
    s11_modify_bearer_request->teid = ue_context_p->sgw_s11_teid;
    s11_modify_bearer_request->local_teid = ue_context_p->mme_s11_teid;
    /*
     * Delay Value in integer multiples of 50 millisecs, or zero
     */
    // todo: multiple bearers!
    s11_modify_bearer_request->delay_dl_packet_notif_req = 0;  // TO DO
    s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id = initial_ctxt_setup_rsp_pP->eps_bearer_id;
    memcpy (&s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].s1_eNB_fteid,
        &initial_ctxt_setup_rsp_pP->bearer_s1u_enb_fteid,
        sizeof (s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].s1_eNB_fteid));
    s11_modify_bearer_request->bearer_contexts_to_be_modified.num_bearer_context = 1;

    s11_modify_bearer_request->bearer_contexts_to_be_removed.num_bearer_context = 0;

    s11_modify_bearer_request->mme_fq_csid.node_id_type = GLOBAL_UNICAST_IPv4; // TO DO
    s11_modify_bearer_request->mme_fq_csid.csid = 0;   // TO DO ...
    memset(&s11_modify_bearer_request->indication_flags, 0, sizeof(s11_modify_bearer_request->indication_flags));   // TO DO
    s11_modify_bearer_request->rat_type = RAT_EUTRAN;
    /*
     * S11 stack specific parameter. Not used in standalone epc mode
     */
    s11_modify_bearer_request->trxn = NULL;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S11_MME ,
        NULL, 0, "0 S11_MODIFY_BEARER_REQUEST teid %u ebi %u", s11_modify_bearer_request->teid,
        s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id);
    itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
  }else{
    OAILOG_INFO(LOG_MME_APP, "IMSI " IMSI_64_FMT " is not registered yet. Waiting the UE to register to send the MBR.\n", ue_context_p->imsi);
    memcpy(&ue_context_p->pending_s1u_downlink_bearer, &initial_ctxt_setup_rsp_pP->bearer_s1u_enb_fteid, sizeof(FTeid_t));
    ue_context_p->pending_s1u_downlink_bearer_ebi = initial_ctxt_setup_rsp_pP->eps_bearer_id;
  }

  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
// HANDOVER MESSAGING ------------------------------------------------------------------------------
void
mme_app_handle_path_switch_req(
  const itti_mme_app_path_switch_req_t * const path_switch_req_pP
  )
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received MME_APP_PATH_SWITCH_REQ from S1AP\n");
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, path_switch_req_pP->mme_ue_s1ap_id);

  if (ue_context_p == NULL) {
    OAILOG_ERROR (LOG_MME_APP, "We didn't find this mme_ue_s1ap_id in list of UE: %08x %d(dec)\n", path_switch_req_pP->mme_ue_s1ap_id, path_switch_req_pP->mme_ue_s1ap_id);
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "MME_APP_PATH_SWITCH_REQ Unknown ue %u", path_switch_req_pP->mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  enb_s1ap_id_key_t                       enb_s1ap_id_key = INVALID_ENB_UE_S1AP_ID_KEY;

  /** Update the ENB_ID_KEY. */
  MME_APP_ENB_S1AP_ID_KEY(enb_s1ap_id_key, path_switch_req_pP->enb_id, path_switch_req_pP->enb_ue_s1ap_id);
  // Update enb_s1ap_id_key in hashtable
  mme_ue_context_update_coll_keys( &mme_app_desc.mme_ue_contexts,
      ue_context_p,
      enb_s1ap_id_key,
      ue_context_p->mme_ue_s1ap_id,
      ue_context_p->imsi,
      ue_context_p->mme_s11_teid,
      ue_context_p->local_mme_s10_teid,
      &ue_context_p->guti);

  // Set the handover flag, check that no handover exists.
  ue_context_p->enb_ue_s1ap_id    = path_switch_req_pP->enb_ue_s1ap_id;
  ue_context_p->sctp_assoc_id_key = path_switch_req_pP->sctp_assoc_id;
  //  sctp_stream_id_t        sctp_stream;
  uint16_t encryption_algorithm_capabilities;
  uint16_t integrity_algorithm_capabilities;
  // todo: update them from the X2 message!
  if(emm_data_context_update_security_parameters(path_switch_req_pP->mme_ue_s1ap_id, &encryption_algorithm_capabilities, &integrity_algorithm_capabilities) != RETURNok){
    OAILOG_ERROR(LOG_MME_APP, "Error updating AS security parameters for UE with ueId: " MME_UE_S1AP_ID_FMT ". \n", path_switch_req_pP->mme_ue_s1ap_id);
    mme_app_send_s1ap_path_switch_request_failure(path_switch_req_pP->mme_ue_s1ap_id, path_switch_req_pP->enb_ue_s1ap_id, path_switch_req_pP->sctp_assoc_id, SYSTEM_FAILURE);
    /** Implicitly detach the UE --> If EMM context is missing, still continue with the resource removal. */
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
 OAILOG_INFO(LOG_MME_APP, "Successfully updated AS security parameters for UE with ueId: " MME_UE_S1AP_ID_FMT " for X2 handover. \n", path_switch_req_pP->mme_ue_s1ap_id);

 // Stop Initial context setup process guard timer,if running todo: path switch request?
  if (ue_context_p->path_switch_req_timer.id != MME_APP_TIMER_INACTIVE_ID) {
    if (timer_remove(ue_context_p->path_switch_req_timer.id)) {
      OAILOG_ERROR (LOG_MME_APP, "Failed to stop Path Switch Request timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    }
    ue_context_p->path_switch_req_timer.id = MME_APP_TIMER_INACTIVE_ID;
  }
  message_p = itti_alloc_new_message (TASK_MME_APP, S11_MODIFY_BEARER_REQUEST);
  AssertFatal (message_p , "itti_alloc_new_message Failed");
  itti_s11_modify_bearer_request_t *s11_modify_bearer_request = &message_p->ittiMsg.s11_modify_bearer_request;
  memset ((void *)s11_modify_bearer_request, 0, sizeof (*s11_modify_bearer_request));
  s11_modify_bearer_request->peer_ip = mme_config.ipv4.sgw_s11;
  s11_modify_bearer_request->teid = ue_context_p->sgw_s11_teid;
  s11_modify_bearer_request->local_teid = ue_context_p->mme_s11_teid;
  /*
   * Delay Value in integer multiples of 50 millisecs, or zero
   */
  s11_modify_bearer_request->delay_dl_packet_notif_req = 0;  // TO DO
  s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id = path_switch_req_pP->eps_bearer_id;
  memcpy (&s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].s1_eNB_fteid,
      &path_switch_req_pP->bearer_s1u_enb_fteid,
      sizeof (s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].s1_eNB_fteid));
  s11_modify_bearer_request->bearer_contexts_to_be_modified.num_bearer_context = 1;

  s11_modify_bearer_request->bearer_contexts_to_be_removed.num_bearer_context = 0;

  s11_modify_bearer_request->mme_fq_csid.node_id_type = GLOBAL_UNICAST_IPv4; // TO DO
  s11_modify_bearer_request->mme_fq_csid.csid = 0;   // TO DO ...
  memset(&s11_modify_bearer_request->indication_flags, 0, sizeof(s11_modify_bearer_request->indication_flags));   // TO DO
  s11_modify_bearer_request->rat_type = RAT_EUTRAN;
  /*
   * S11 stack specific parameter. Not used in standalone epc mode
   */
  s11_modify_bearer_request->trxn = NULL;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S11_MME ,
                      NULL, 0, "0 S11_MODIFY_BEARER_REQUEST teid %u ebi %u", s11_modify_bearer_request->teid,
                      s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id);
  itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);

  // todo: since PSReq is already received from B-COM just set a flag (ask Lionel how to do it better).
  ue_context_p->pending_x2_handover = true;
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_handover_required(
     const itti_s1ap_handover_required_t * const handover_required_pP
    )   {
  OAILOG_FUNC_IN (LOG_MME_APP);

  emm_data_context_t                     *ue_nas_ctx = NULL;
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;

  OAILOG_DEBUG (LOG_MME_APP, "Received S1AP_HANDOVER_REQUIRED from S1AP\n");
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, handover_required_pP->mme_ue_s1ap_id);

  if (ue_context_p == NULL) {
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this mme_ue_s1ap_id in list of UE: %08x %d(dec)\n", handover_required_pP->mme_ue_s1ap_id, handover_required_pP->mme_ue_s1ap_id);
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "S1AP_HANDOVER_REQUIRED Unknown ue %u", handover_required_pP->mme_ue_s1ap_id);
    mme_app_send_s1ap_handover_preparation_failure(handover_required_pP->mme_ue_s1ap_id, handover_required_pP->enb_ue_s1ap_id, handover_required_pP->sctp_assoc_id, CONTEXT_NOT_FOUND);
    /** Remove the allocated resources in the ITTI message (bstrings). */
    bdestroy(handover_required_pP->eutran_source_to_target_container);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  if (ue_context_p->mm_state != UE_REGISTERED) {
    OAILOG_ERROR (LOG_MME_APP, "UE with ue_id " MME_UE_S1AP_ID_FMT " is not in UE_REGISTERED state. "
        "Rejecting the Handover Preparation. \n", ue_context_p->mme_ue_s1ap_id);
    mme_app_send_s1ap_handover_preparation_failure(handover_required_pP->mme_ue_s1ap_id, handover_required_pP->enb_ue_s1ap_id, handover_required_pP->sctp_assoc_id, REQUEST_REJECTED);
    /** No change in the UE context needed. */
    /** Remove the allocated resources in the ITTI message (bstrings). */
    bdestroy(handover_required_pP->eutran_source_to_target_container);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  /**
   * Staying in the same state (UE_REGISTERED).
   * If the GUTI is not found, first send a preparation failure, then implicitly detach.
   */
  ue_nas_ctx = emm_data_context_get_by_guti (&_emm_data, &ue_context_p->guti);
  /** Check that the UE NAS context != NULL. */
  if (!ue_nas_ctx || ue_nas_ctx->_emm_fsm_status != EMM_REGISTERED) {
    OAILOG_ERROR (LOG_MME_APP, "EMM context for UE with ue_id " MME_UE_S1AP_ID_FMT " IMSI " IMSI_64_FMT " is not in EMM_REGISTERED state or not existing. "
        "Rejecting the Handover Preparation. \n", handover_required_pP->mme_ue_s1ap_id, (ue_nas_ctx) ? ue_nas_ctx->_imsi64 : "NULL");
    mme_app_send_s1ap_handover_preparation_failure(handover_required_pP->mme_ue_s1ap_id, handover_required_pP->enb_ue_s1ap_id, handover_required_pP->sctp_assoc_id, SYSTEM_FAILURE);
    /** Implicitly detach the UE --> If EMM context is missing, still continue with the resource removal. */
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
    /** Remove the allocated resources in the ITTI message (bstrings). */
    bdestroy(handover_required_pP->eutran_source_to_target_container);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  /** Set the target TAI and enb_id, to use them if a Handover-Cancel message comes. */
  memcpy(&ue_context_p->pending_handover_target_tai, &handover_required_pP->selected_tai, sizeof(tai_t));
  ue_context_p->pending_handover_enb_id = handover_required_pP->global_enb_id.cell_identity.enb_id;

  /** Check if the destination eNodeB is attached at the same or another MME. */
  if (mme_app_check_ta_local(&handover_required_pP->selected_tai.plmn, handover_required_pP->selected_tai.tac)) {
    /** Check if the eNB with the given eNB-ID is served. */
    if(s1ap_is_enb_id_in_list(handover_required_pP->global_enb_id.cell_identity.enb_id) != NULL){
      OAILOG_DEBUG (LOG_MME_APP, "Target ENB_ID %d of target TAI " TAI_FMT " is served by current MME. \n", handover_required_pP->global_enb_id.cell_identity.enb_id, handover_required_pP->selected_tai);
      /** Get the updated security parameters from EMM layer directly. Else new states and ITTI messages are necessary. */
      uint16_t encryption_algorithm_capabilities;
      uint16_t integrity_algorithm_capabilities;
      if(emm_data_context_update_security_parameters(handover_required_pP->mme_ue_s1ap_id, &encryption_algorithm_capabilities, &integrity_algorithm_capabilities) != RETURNok){
        OAILOG_ERROR(LOG_MME_APP, "Error updating AS security parameters for UE with ueId: " MME_UE_S1AP_ID_FMT ". \n", handover_required_pP->mme_ue_s1ap_id);
        mme_app_send_s1ap_handover_preparation_failure(handover_required_pP->mme_ue_s1ap_id, handover_required_pP->enb_ue_s1ap_id, handover_required_pP->sctp_assoc_id, SYSTEM_FAILURE);
        /** Implicitly detach the UE --> If EMM context is missing, still continue with the resource removal. */
        message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
        DevAssert (message_p != NULL);
        message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
        MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
        itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
        /** Remove the allocated resources in the ITTI message (bstrings). */
        bdestroy(handover_required_pP->eutran_source_to_target_container);
        OAILOG_FUNC_OUT (LOG_MME_APP);
      }else{
        OAILOG_INFO(LOG_MME_APP, "Successfully updated AS security parameters for UE with ueId: " MME_UE_S1AP_ID_FMT ". \n", handover_required_pP->mme_ue_s1ap_id);
        /** Prepare a Handover Request, keep the transparent container for now, it will be purged together with the free method of the S1AP message. */
        mme_app_send_s1ap_handover_request(handover_required_pP->mme_ue_s1ap_id, handover_required_pP->global_enb_id.cell_identity.enb_id,
            encryption_algorithm_capabilities,
            integrity_algorithm_capabilities,
            ue_nas_ctx->_vector[ue_nas_ctx->_security.vector_index].nh_conj,
            ue_nas_ctx->_security.ncc);
        OAILOG_FUNC_OUT (LOG_MME_APP);
      }
    }else{
      /** The target eNB-ID is not served by this MME. */
      OAILOG_DEBUG (LOG_MME_APP, "Target ENB_ID %d of target TAI " TAI_FMT " is NOT served by current MME. \n", handover_required_pP->global_enb_id.cell_identity.enb_id, handover_required_pP->selected_tai);
      /** Send a Handover Preparation Failure back. */
      mme_app_send_s1ap_handover_preparation_failure(handover_required_pP->mme_ue_s1ap_id, handover_required_pP->enb_ue_s1ap_id, handover_required_pP->sctp_assoc_id, SYSTEM_FAILURE);
      bdestroy(handover_required_pP->eutran_source_to_target_container);
      OAILOG_FUNC_OUT (LOG_MME_APP);
    }
  }
  OAILOG_DEBUG (LOG_MME_APP, "Target TA  "TAI_FMT " is NOT served by current MME. Searching for a neighboring MME. \n", handover_required_pP->selected_tai);
  if(!TAIS_ARE_EQUAL(handover_required_pP->selected_tai, mme_config.nghMme.nghMme[0].ngh_mme_tai)){
    OAILOG_DEBUG (LOG_MME_APP, "The selected TAI " TAI_FMT " is not configured as an S10 MME neighbor. "
        "Not proceeding with the handover formme_ue_s1ap_id in list of UE: %08x %d(dec)\n",
        handover_required_pP->selected_tai, handover_required_pP->mme_ue_s1ap_id, handover_required_pP->mme_ue_s1ap_id);
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "S1AP_HANDOVER_REQUIRED Unknown ue %u", handover_required_pP->mme_ue_s1ap_id);
    /** Send a Handover Preparation Failure back. */
    mme_app_send_s1ap_handover_preparation_failure(handover_required_pP->mme_ue_s1ap_id, handover_required_pP->enb_ue_s1ap_id, handover_required_pP->sctp_assoc_id, SYSTEM_FAILURE);
    bdestroy(handover_required_pP->eutran_source_to_target_container);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  /** Prepare a forward relocation message to the TARGET-MME. */
  message_p = itti_alloc_new_message (TASK_MME_APP, S10_FORWARD_RELOCATION_REQUEST);
  DevAssert (message_p != NULL);
  itti_s10_forward_relocation_request_t *forward_relocation_request_p = &message_p->ittiMsg.s10_forward_relocation_request;
  memset ((void*)forward_relocation_request_p, 0, sizeof (itti_s10_forward_relocation_request_t));
  forward_relocation_request_p->teid = 0;
  forward_relocation_request_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr;
  /** IMSI. */
  IMSI64_TO_STRING (ue_context_p->imsi, (char *)forward_relocation_request_p->imsi.digit);
  // message content was set to 0
  forward_relocation_request_p->imsi.length = strlen ((const char *)forward_relocation_request_p->imsi.digit);
  // message content was set to 0
  /** Set the Source MME_S10_FTEID the same as in S11. */
  OAI_GCC_DIAG_OFF(pointer-to-int-cast);
  forward_relocation_request_p->s10_source_mme_teid.teid = (teid_t) ue_context_p;
  OAI_GCC_DIAG_ON(pointer-to-int-cast);
  forward_relocation_request_p->s10_source_mme_teid.interface_type = S10_MME_GTP_C;
  mme_config_read_lock (&mme_config);
  forward_relocation_request_p->s10_source_mme_teid.ipv4_address = mme_config.ipv4.s10;
  mme_config_unlock (&mme_config);
  forward_relocation_request_p->s10_source_mme_teid.ipv4 = 1;

  /**
   * Update the local_s10_key.
   * Not setting the key directly in the  ue_context structure. Only over this function!
   */
  mme_ue_context_update_coll_keys (&mme_app_desc.mme_ue_contexts, ue_context_p,
      ue_context_p->enb_s1ap_id_key,
      ue_context_p->mme_ue_s1ap_id,
      ue_context_p->imsi,
      ue_context_p->mme_s11_teid,       // mme_s11_teid is new
      forward_relocation_request_p->s10_source_mme_teid.teid,       // set with forward_relocation_request!
      &ue_context_p->guti);

  /** Set the SGW_S11_FTEID the same as in S11. */
  OAI_GCC_DIAG_OFF(pointer-to-int-cast);
  forward_relocation_request_p->s11_sgw_teid.teid = ue_context_p->sgw_s11_teid;
  OAI_GCC_DIAG_ON(pointer-to-int-cast);
  forward_relocation_request_p->s11_sgw_teid.interface_type = S11_MME_GTP_C;
  mme_config_read_lock (&mme_config);
  forward_relocation_request_p->s11_sgw_teid.ipv4_address = mme_config.ipv4.s11;
  mme_config_unlock (&mme_config);
  forward_relocation_request_p->s11_sgw_teid.ipv4 = 1;

  /** Set the F-Cause. */
  forward_relocation_request_p->f_cause.fcause_type      = FCAUSE_S1AP;
  forward_relocation_request_p->f_cause.fcause_s1ap_type = FCAUSE_S1AP_RNL;
  forward_relocation_request_p->f_cause.fcause_value     = (uint8_t)handover_required_pP->f_cause_value;

  /** Set the target identification. */
  forward_relocation_request_p->target_identification.target_type = 1; /**< Macro eNodeB. */
  /** Set the MCC. */
  forward_relocation_request_p->target_identification.mcc[0]  = handover_required_pP->selected_tai.plmn.mcc_digit1;
  forward_relocation_request_p->target_identification.mcc[1]  = handover_required_pP->selected_tai.plmn.mcc_digit2;
  forward_relocation_request_p->target_identification.mcc[2]  = handover_required_pP->selected_tai.plmn.mcc_digit3;
  /** Set the MNC. */
  forward_relocation_request_p->target_identification.mnc[0]  = handover_required_pP->selected_tai.plmn.mnc_digit1;
  forward_relocation_request_p->target_identification.mnc[1]  = handover_required_pP->selected_tai.plmn.mnc_digit2;
  forward_relocation_request_p->target_identification.mnc[2]  = handover_required_pP->selected_tai.plmn.mnc_digit3;
  /** Set the Target Id. */
  forward_relocation_request_p->target_identification.target_id.macro_enb_id.tac    = handover_required_pP->selected_tai.tac;
  forward_relocation_request_p->target_identification.target_id.macro_enb_id.enb_id = handover_required_pP->global_enb_id.cell_identity.enb_id;

  /** todo: Set the TAI and and the global-eNB-Id. */
  // memcpy(&forward_relocation_request_p->selected_tai, &handover_required_pP->selected_tai, sizeof(handover_required_pP->selected_tai));
  // memcpy(&forward_relocation_request_p->global_enb_id, &handover_required_pP->global_enb_id, sizeof(handover_required_pP->global_enb_id));

  /** Set the PDN connections. */

  /** Set the PDN_CONNECTIONS IE. */
  DevAssert(mme_app_set_pdn_connections(&forward_relocation_request_p->pdn_connections, ue_context_p) == RETURNok);

  /** Set the MM_UE_EPS_CONTEXT. */
  DevAssert(mme_app_set_ue_eps_mm_context(&forward_relocation_request_p->ue_eps_mm_context, ue_context_p, ue_nas_ctx) == RETURNok);

  /** Put the E-Utran transparent container. */
  forward_relocation_request_p->eutran_container.container_type = 3;
  forward_relocation_request_p->eutran_container.container_value = handover_required_pP->eutran_source_to_target_container;
  if (forward_relocation_request_p->eutran_container.container_value == NULL){
    OAILOG_ERROR (LOG_MME_APP, " NULL UE transparent container\n" );
    OAILOG_FUNC_OUT (LOG_MME_APP);
    // todo: does it set the size parameter?
  }
  /** Will be deallocated later after S10 message is encoded. */
  /** Send the Forward Relocation Message to S11. */
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S10_MME ,
      NULL, 0, "0 NAS_UE_RELOCATION_REQ for UE %d \n", handover_required_pP->mme_ue_s1ap_id);
  itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);

  /** No need to start/stop a timer on the source MME side. */
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_handover_cancel(
     const itti_s1ap_handover_cancel_t * const handover_cancel_pP
    )   {
  OAILOG_FUNC_IN (LOG_MME_APP);

  emm_data_context_t                     *ue_nas_ctx = NULL;
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;

  OAILOG_DEBUG (LOG_MME_APP, "Received S1AP_HANDOVER_CANCEL from S1AP\n");
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, handover_cancel_pP->mme_ue_s1ap_id);
  if (ue_context_p == NULL) {
    OAILOG_ERROR (LOG_MME_APP, "We didn't find this mme_ue_s1ap_id in list of UE: %08x %d(dec)\n", handover_cancel_pP->mme_ue_s1ap_id, handover_cancel_pP->mme_ue_s1ap_id);
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "S1AP_HANDOVER_CANCEL Unknown ue %u", handover_cancel_pP->mme_ue_s1ap_id);
    /** Ignoring the message. */
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  if (ue_context_p->mm_state != UE_REGISTERED) {
    OAILOG_ERROR (LOG_MME_APP, "UE with ue_id " MME_UE_S1AP_ID_FMT " is not in UE_REGISTERED state. "
        "Sending Cancel Acknowledgement and implicitly removing the UE. \n", ue_context_p->mme_ue_s1ap_id);
    mme_app_send_s1ap_handover_cancel_acknowledge(handover_cancel_pP->mme_ue_s1ap_id, handover_cancel_pP->enb_ue_s1ap_id, handover_cancel_pP->assoc_id);
    /** Purge the invalid UE context. */
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
    /** Remove the allocated resources in the ITTI message (bstrings). */
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  /**
   * Staying in the same state (UE_REGISTERED).
   * If the GUTI is not found, first send a preparation failure, then implicitly detach.
   */
  ue_nas_ctx = emm_data_context_get_by_guti (&_emm_data, &ue_context_p->guti);
  /** Check that the UE NAS context != NULL. */
  if (!ue_nas_ctx || ue_nas_ctx->_emm_fsm_status != EMM_REGISTERED) {
    OAILOG_ERROR (LOG_MME_APP, "EMM context for UE with ue_id " MME_UE_S1AP_ID_FMT " IMSI " IMSI_64_FMT " is not in EMM_REGISTERED state or not existing. "
        "Sending Cancel Acknowledge back and implicitly detaching the UE. \n", handover_cancel_pP->mme_ue_s1ap_id, (ue_nas_ctx) ? ue_nas_ctx->_imsi64 : INVALID_IMSI64);
    mme_app_send_s1ap_handover_cancel_acknowledge(handover_cancel_pP->mme_ue_s1ap_id, handover_cancel_pP->enb_ue_s1ap_id, handover_cancel_pP->assoc_id);
    /** Implicitly detach the UE --> If EMM context is missing, still continue with the resource removal. */
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
    /** Remove the allocated resources in the ITTI message (bstrings). */
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  /**
   * UE will always stay in EMM-REGISTERED mode until S10 Handover is completed (CANCEL_LOCATION_REQUEST).
   * Just checking S10 is not enough. The UE may have handovered to the target-MME and then handovered to another eNB in the TARGET-MME.
   * Check if there is a target-TAI registered for the UE is in this or another MME.
   */
  /** Check if the destination eNodeB is attached at the same or another MME. */
  if (mme_app_check_ta_local(&ue_context_p->pending_handover_target_tai.plmn, ue_context_p->pending_handover_target_tai.tac)){
    /** Check if the eNB with the given eNB-ID is served. */
    if(s1ap_is_enb_id_in_list(ue_context_p->pending_handover_enb_id) != NULL){
      OAILOG_DEBUG (LOG_MME_APP, "Target ENB_ID %d of target TAI " TAI_FMT " is served by current MME. \n",
          ue_context_p->pending_handover_enb_id, ue_context_p->pending_handover_target_tai);
      /**
       * Check if there already exists a UE-Reference to the target cell.
       * If so, this means that HANDOVER_REQUEST_ACKNOWLEDGE is already received.
       * It is so far gone in the handover process. We will send CANCEL-ACK and implicitly detach the UE.
       */
      ue_description_t * ue_reference = s1ap_is_enb_ue_s1ap_id_in_list_per_enb(ue_context_p->enb_ue_s1ap_id, ue_context_p->pending_handover_enb_id);
      if(ue_reference == NULL){
        /** No UE Reference to the target eNB found. Sending a UE Context Release to the target MME BEFORE a HANDOVER_REQUEST_ACK arrives. */
        mme_app_itti_ue_context_release (ue_context_p, S1AP_HANDOVER_CANCELLED);
        /**
         * An S1AP UE Context Release Command is sent. We wait for the response.
         * If a REMOVE_COMPLETE arrives on time, we will send the CANCEL-ACK back to the source MME and leave the UE context connected.
         * Else, if no REMOVE_COMPLETE arrives, we will purge the UE context without sending CANCEL_ACK back.
         */
        bdestroy(ue_context_p->pending_s1ap_source_to_target_handover_container);
        OAILOG_INFO(LOG_MME_APP, "Successfully sent UE-Context-Release-Cmd to the target eNB %d for the UE-ID " MME_UE_S1AP_ID_FMT " Waiting for the resource removal to complete to send the "
            "CANCEL_ACK back. \n.", ue_context_p->pending_handover_enb_id, ue_context_p->mme_ue_s1ap_id);
        OAILOG_FUNC_OUT (LOG_MME_APP);
      }else{
        /**
         * A UE Reference to the target eNB found.
         * Sending a CANCEL_ACK back, release the resources at the target eNB and immediately perform an implicit detach.
         * This situation is too mixed up.
         */
        mme_app_itti_ue_context_release (ue_context_p, S1AP_HANDOVER_CANCELLED);

        /** Send a HO-CANCEL-ACK to the source-MME. */
        mme_app_send_s1ap_handover_cancel_acknowledge(handover_cancel_pP->mme_ue_s1ap_id, handover_cancel_pP->enb_ue_s1ap_id, handover_cancel_pP->assoc_id);

        /** Implicitly detach the UE --> If EMM context is missing, still continue with the resource removal. */
        message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
        DevAssert (message_p != NULL);
        message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
        MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
        itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
        /** Remove the allocated resources in the ITTI message (bstrings). */
        OAILOG_ERROR(LOG_MME_APP, "Successfully sent UE-Context-Release-Cmd to the target eNB %d for the UE-ID " MME_UE_S1AP_ID_FMT "."
            "Afterwards immediately performing implicit detach, since 2 UE-References existed. HO-CANCEL after HO-REQ-ACK is not supported. \n",
            ue_context_p->pending_handover_enb_id, ue_context_p->mme_ue_s1ap_id);
        OAILOG_FUNC_OUT (LOG_MME_APP);
      }
    }else{
      OAILOG_ERROR(LOG_MME_APP, "No registered eNB found with target eNB-ID %d in target-TAI " TAI_FMT ". "
          "Cannot release resources in the target-ENB for UE-ID " MME_UE_S1AP_ID_FMT "."
          "Sending CANCEL-ACK back and leaving the UE as it is. \n",
          ue_context_p->pending_handover_enb_id, ue_context_p->pending_handover_target_tai, ue_context_p->mme_ue_s1ap_id);
      //todo: eventually perform an implicit detach!
      mme_app_send_s1ap_handover_cancel_acknowledge(handover_cancel_pP->mme_ue_s1ap_id, handover_cancel_pP->enb_ue_s1ap_id, handover_cancel_pP->assoc_id);
      OAILOG_FUNC_OUT (LOG_MME_APP);
    }
  }else{
    /**
     * Target-TAI was not in the current MME. Sending a S10 Context Release Request.
     */
    if(ue_context_p->remote_mme_s10_teid == 0){
      /**
       * Send a CANCEL-ACK back and perform an implicit detach.
       */
      OAILOG_WARNING(LOG_MME_APP, "Error, the remote MME-TEID is not set yet for UE_CONTEXT " MME_UE_S1AP_ID_FMT ". "
          "Sending CANCEL-ACK back to source-ENB and performing an implicit detach. \n. ", ue_context_p->mme_ue_s1ap_id);
      mme_app_send_s1ap_handover_cancel_acknowledge(handover_cancel_pP->mme_ue_s1ap_id, handover_cancel_pP->enb_ue_s1ap_id, handover_cancel_pP->assoc_id);
      /** Implicitly detach the UE --> If EMM context is missing, still continue with the resource removal. */
      message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
      DevAssert (message_p != NULL);
      message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
      MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
      itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
      /** Remove the allocated resources in the ITTI message (bstrings). */
      OAILOG_ERROR(LOG_MME_APP, "Successfully sent UE-Context-Release-Cmd to the target eNB %d for the UE-ID " MME_UE_S1AP_ID_FMT "."
          "Afterwards immediately performing implicit detach, since 2 UE-Refernces existed. HO-CANCEL after HO-REQ-ACK is not supported. \n",
          ue_context_p->pending_handover_enb_id, ue_context_p->mme_ue_s1ap_id);
      OAILOG_FUNC_OUT (LOG_MME_APP);
    }else{
      /**
       * It may be that, the TEID is some other (the old MME it was handovered before from here.
       * So we need to check the TAI and find the correct neighboring MME.#
       * todo: to skip this step, we might set it back to 0 after S10-Complete for the previous Handover.
       */
      // todo: currently only a single neighboring MME supported.
      itti_s10_relocation_cancel_request_t *relocation_cancel_request_p = &message_p->ittiMsg.s10_relocation_cancel_request;
      memset ((void*)relocation_cancel_request_p, 0, sizeof (itti_s10_relocation_cancel_request_t));
      relocation_cancel_request_p->teid = 0;
      relocation_cancel_request_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr;
      /** IMSI. */
      IMSI64_TO_STRING (ue_context_p->imsi, (char *)relocation_cancel_request_p->imsi.digit);
      // message content was set to 0
      relocation_cancel_request_p->imsi.length = strlen ((const char *)relocation_cancel_request_p->imsi.digit);
      MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "0 RELOCATION_CANCEL_REQUEST_MESSAGE");
      itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
      /** Remove the allocated resources in the ITTI message (bstrings). */
      OAILOG_DEBUG(LOG_MME_APP, "Successfully sent S10 RELOCATION_CANCEL_REQUEST to the target MME for the TARGET-TAI " TAI_FMT " for the UE with IMSI " IMSI_64_FMT ". "
          "Waiting for S10 RELOCATION_CANCEL_REQUEST to complete the HO-CANCEL PROCEDURE. \n", ue_context_p->pending_handover_target_tai, ue_context_p->imsi);
      /**
       * If the S10 Relocation Cancel Request arrives in time, just send the S10 CANCEL LOCATION ACKNOWLEDGEMENT.
       * If a timeout occurs, perform an IMPLICIT DETACH after sending the S10 CANCEL LOCATION ACKNOWLEDGEMENT.
       */
      OAILOG_FUNC_OUT (LOG_MME_APP);
    }
  }
}

static
 bool mme_app_check_ta_local(const plmn_t * target_plmn, const tac_t target_tac){
  if(TA_LIST_AT_LEAST_ONE_MATCH == mme_app_compare_plmn(target_plmn)){
    if(TA_LIST_AT_LEAST_ONE_MATCH == mme_app_compare_tac(target_tac)){
      OAILOG_DEBUG (LOG_MME_APP, "TAC and PLMN are matching. \n");
      return true;
    }
  }
  OAILOG_DEBUG (LOG_MME_APP, "TAC or PLMN are not matching. \n");
  return;
}

static
  int
mme_app_compare_plmn (
  const plmn_t * const plmn)
{
  int                                     i = 0;
  uint16_t                                mcc = 0;
  uint16_t                                mnc = 0;
  uint16_t                                mnc_len = 0;

  DevAssert (plmn != NULL);
  /** Get the integer values from the PLMN. */
  PLMN_T_TO_MCC_MNC ((*plmn), mcc, mnc, mnc_len);

  mme_config_read_lock (&mme_config);

  for (i = 0; i < mme_config.served_tai.nb_tai; i++) {
    OAILOG_TRACE (LOG_MME_APP, "Comparing plmn_mcc %d/%d, plmn_mnc %d/%d plmn_mnc_len %d/%d\n",
        mme_config.served_tai.plmn_mcc[i], mcc, mme_config.served_tai.plmn_mnc[i], mnc, mme_config.served_tai.plmn_mnc_len[i], mnc_len);

    if ((mme_config.served_tai.plmn_mcc[i] == mcc) &&
        (mme_config.served_tai.plmn_mnc[i] == mnc) &&
        (mme_config.served_tai.plmn_mnc_len[i] == mnc_len))
      /*
       * There is a matching plmn
       */
      return TA_LIST_AT_LEAST_ONE_MATCH;
  }

  mme_config_unlock (&mme_config);
  return TA_LIST_NO_MATCH;
}

/* @brief compare a TAC
*/
static
  int
mme_app_compare_tac (
  uint16_t tac_value)
{
  int                                     i = 0;

  mme_config_read_lock (&mme_config);

  for (i = 0; i < mme_config.served_tai.nb_tai; i++) {
    OAILOG_TRACE (LOG_MME_APP, "Comparing config tac %d, received tac = %d\n", mme_config.served_tai.tac[i], tac_value);

    if (mme_config.served_tai.tac[i] == tac_value)
      return TA_LIST_AT_LEAST_ONE_MATCH;
  }

  mme_config_unlock (&mme_config);
  return TA_LIST_NO_MATCH;
}

//------------------------------------------------------------------------------
void
mme_app_handle_forward_relocation_request(
     const itti_s10_forward_relocation_request_t * const forward_relocation_request_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 struct ue_context_s                    *ue_context_p1 = NULL;


 MessageDef                             *message_p = NULL;
 uint64_t                                imsi = 0;
 int                                     rc = RETURNok;

 OAILOG_FUNC_IN (LOG_MME_APP);

 IMSI_STRING_TO_IMSI64 (&forward_relocation_request_pP->imsi, &imsi);
 OAILOG_DEBUG (LOG_MME_APP, "Handling FORWARD_RELOCATION REQUEST for imsi " IMSI_64_FMT ". \n", imsi);

 /** Check that the UE does not exist. */
 ue_context_p = mme_ue_context_exists_imsi(&mme_app_desc.mme_ue_contexts, imsi);
 if (ue_context_p != NULL) {
   OAILOG_ERROR(LOG_MME_APP, "An UE MME context for the UE with IMSI " IMSI_64_FMT " already exists. \n", imsi);
   MSC_LOG_EVENT (MSC_MMEAPP_MME, "S10_FORWARD_RELOCATION_REQUEST. Already existing UE " IMSI_64_FMT, imsi);
   mme_app_send_s10_forward_relocation_response_err(forward_relocation_request_pP->s10_source_mme_teid.teid, forward_relocation_request_pP->s10_source_mme_teid.ipv4, RELOCATION_FAILURE);
   // todo: check the specification, if an ongoing handover procedure is there, aborting the current one and continuing with the new one?
   bdestroy(forward_relocation_request_pP->eutran_container.container_value);
   ue_context_p->ue_context_rel_cause = S1AP_IMPLICIT_CONTEXT_RELEASE;
   message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
   DevAssert (message_p != NULL);
   itti_nas_implicit_detach_ue_ind_t *nas_implicit_detach_ue_ind_p = &message_p->ittiMsg.nas_implicit_detach_ue_ind;
   memset ((void*)nas_implicit_detach_ue_ind_p, 0, sizeof (itti_nas_implicit_detach_ue_ind_t));
   message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
   itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 OAILOG_INFO(LOG_MME_APP, "Received a FORWARD_RELOCATION_REQUEST for new UE with IMSI " IMSI_64_FMT ". \n", imsi);

 /** Check that NO NAS/EMM context is existing. */
 emm_data_context_t *ue_nas_ctx = emm_data_context_get_by_imsi (&_emm_data, &imsi);
 if (ue_nas_ctx) {
   OAILOG_ERROR(LOG_MME_APP, "A NAS EMM context already exists for this IMSI "IMSI_64_FMT " already exists. \n", imsi);
   mme_app_send_s10_forward_relocation_response_err(forward_relocation_request_pP->s10_source_mme_teid.teid, forward_relocation_request_pP->s10_source_mme_teid.ipv4, RELOCATION_FAILURE);
   bdestroy(forward_relocation_request_pP->eutran_container.container_value);
   /** UE has illegal state. Perform an implicit detach? Or aborting current handover procedure and continuing with handover? . */
   OAILOG_ERROR(LOG_MME_APP, "UE existing in the MME is requested for handover with IMSI " IMSI_64_FMT " and mmeUeS1apId " MME_UE_S1AP_ID_FMT ". \n", ue_nas_ctx->_imsi64, ue_nas_ctx->ue_id);
   ue_context_p->ue_context_rel_cause = S1AP_IMPLICIT_CONTEXT_RELEASE;
   message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
   DevAssert (message_p != NULL);
   itti_nas_implicit_detach_ue_ind_t *nas_implicit_detach_ue_ind_p = &message_p->ittiMsg.nas_implicit_detach_ue_ind;
   memset ((void*)nas_implicit_detach_ue_ind_p, 0, sizeof (itti_nas_implicit_detach_ue_ind_t));
   message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
   itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Get and handle the PDN Connection element as pending PDN connection element. */
 pdn_connection_t* pdn_conn_pP = forward_relocation_request_pP->pdn_connections.pdn_connection;
 /** Get the PDN Connections IE and set the IP addresses. */
 if(pdn_conn_pP->ip_address.present != 0x0){
   OAILOG_ERROR(LOG_MME_APP, "Received IP PDN type for IMSI  " IMSI_64_FMT " is not IPv4. Only IPv4 is accepted. \n", imsi);
   /**
    * Abort the Context Response procedure since the given IP is not supported.
    * No changes in the source MME side should occur.
    */
   mme_app_send_s10_forward_relocation_response_err(forward_relocation_request_pP->s10_source_mme_teid.teid, forward_relocation_request_pP->s10_source_mme_teid.ipv4, RELOCATION_FAILURE);
   bdestroy(forward_relocation_request_pP->eutran_container.container_value);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Everything stack to this point. */
 /** Check that the TAI & PLMN are actually served. */
 tai_t target_tai;
 memset(&target_tai, 0, sizeof (tai_t));
 target_tai.plmn.mcc_digit1 = forward_relocation_request_pP->target_identification.mcc[0];
 target_tai.plmn.mcc_digit2 = forward_relocation_request_pP->target_identification.mcc[1];
 target_tai.plmn.mcc_digit3 = forward_relocation_request_pP->target_identification.mcc[2];
 target_tai.plmn.mnc_digit1 = forward_relocation_request_pP->target_identification.mnc[0];
 target_tai.plmn.mnc_digit2 = forward_relocation_request_pP->target_identification.mnc[1];
 target_tai.plmn.mnc_digit3 = forward_relocation_request_pP->target_identification.mnc[2];
 if (mme_app_check_ta_local(&target_tai.plmn, forward_relocation_request_pP->target_identification.target_id.macro_enb_id.tac)) {
   /** The target PLMN and TAC are served by this MME. */
   OAILOG_DEBUG (LOG_MME_APP, "Target TAC " TAC_FMT " is served by current MME. \n", forward_relocation_request_pP->target_identification.target_id.macro_enb_id.tac);
   /**
    * Currently only a single TA will be served by each MME and we are expecting TAU from the UE side.
    * Check that the eNB is also served, that an SCTP association exists for the eNB.
    */
   if(s1ap_is_enb_id_in_list(forward_relocation_request_pP->target_identification.target_id.macro_enb_id.enb_id) != NULL){
     OAILOG_DEBUG (LOG_MME_APP, "Target ENB_ID %u is served by current MME. \n", forward_relocation_request_pP->target_identification.target_id.macro_enb_id.enb_id);
     /** Continue with the handover establishment. */
   }else{
     /** The target PLMN and TAC are not served by this MME. */
     OAILOG_ERROR(LOG_MME_APP, "Target ENB_ID %u is NOT served by the current MME. \n", forward_relocation_request_pP->target_identification.target_id.macro_enb_id.enb_id);
     mme_app_send_s10_forward_relocation_response_err(forward_relocation_request_pP->s10_source_mme_teid.teid, forward_relocation_request_pP->s10_source_mme_teid.ipv4, RELOCATION_FAILURE);
     bdestroy(forward_relocation_request_pP->eutran_container.container_value);
     OAILOG_FUNC_OUT (LOG_MME_APP);
   }
 }else{
   /** The target PLMN and TAC are not served by this MME. */
   OAILOG_ERROR(LOG_MME_APP, "TARGET TAC " TAC_FMT " is NOT served by current MME. \n", forward_relocation_request_pP->target_identification.target_id.macro_enb_id.tac);
   mme_app_send_s10_forward_relocation_response_err(forward_relocation_request_pP->s10_source_mme_teid.teid, forward_relocation_request_pP->s10_source_mme_teid.ipv4, RELOCATION_FAILURE);
   bdestroy(forward_relocation_request_pP->eutran_container.container_value);
   /** No UE context or tunnel endpoint is allocated yet. */
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }

 /** Establish the UE context. */
 OAILOG_DEBUG (LOG_MME_APP, "Creating a new UE context for the UE with incoming S1AP Handover via S10 for IMSI " IMSI_64_FMT ". \n", imsi);
 if ((ue_context_p = mme_create_new_ue_context ()) == NULL) {
   /** Send a negative response before crashing. */
   mme_app_send_s10_forward_relocation_response_err(forward_relocation_request_pP->s10_source_mme_teid.teid, forward_relocation_request_pP->s10_source_mme_teid.ipv4, SYSTEM_FAILURE);
   bdestroy(forward_relocation_request_pP->eutran_container.container_value);
   /**
    * Error during UE context malloc
    */
   DevMessage ("Error while mme_create_new_ue_context");
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Update the pending PDN connection information from the received PDN-Connection. */
 memset (&(ue_context_p->pending_pdn_connectivity_req_imsi), 0, 16); /**< IMSI in create session request. */
 memcpy (&(ue_context_p->pending_pdn_connectivity_req_imsi), &(forward_relocation_request_pP->imsi.digit), forward_relocation_request_pP->imsi.length);
 ue_context_p->pending_pdn_connectivity_req_imsi_length = forward_relocation_request_pP->imsi.length;
 /**
  * Set the trx (like in S10 Context Request).
  * We need to set the trxId somewhere. The trx is get via trxId.
  */
 ue_context_p->pending_s10_response_trxn = forward_relocation_request_pP->trxn;
 ue_context_p->remote_mme_s10_teid = forward_relocation_request_pP->s10_source_mme_teid.teid;
 /** Use the received PDN connectivity information. */
 mme_app_handle_pending_pdn_connectivity_information(ue_context_p, pdn_conn_pP);
 ue_context_p->mme_ue_s1ap_id = mme_app_ctx_get_new_ue_id ();
 if (ue_context_p->mme_ue_s1ap_id == INVALID_MME_UE_S1AP_ID) {
   OAILOG_CRITICAL (LOG_MME_APP, "MME_APP_FORWARD_RELOCATION_REQUEST. MME_UE_S1AP_ID allocation Failed.\n");
   /** Deallocate the ue context and remove from MME_APP map. */
   mme_remove_ue_context (&mme_app_desc.mme_ue_contexts, ue_context_p);
   /** Send back failure. */
   mme_app_send_s10_forward_relocation_response_err(forward_relocation_request_pP->s10_source_mme_teid.teid, forward_relocation_request_pP->s10_source_mme_teid.ipv4, RELOCATION_FAILURE);
   bdestroy(forward_relocation_request_pP->eutran_container.container_value);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 OAILOG_DEBUG (LOG_MME_APP, "MME_APP_INITIAL_UE_MESSAGE. Allocated new MME UE context and new mme_ue_s1ap_id. " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->mme_ue_s1ap_id);
 /** Register the new MME_UE context into the map. */
 DevAssert (mme_insert_ue_context (&mme_app_desc.mme_ue_contexts, ue_context_p) == 0);
 /** Set the target information as pending. */
 memcpy(&ue_context_p->pending_handover_target_tai, &target_tai, sizeof(tai_t));
 ue_context_p->pending_handover_enb_id = forward_relocation_request_pP->target_identification.target_id.macro_enb_id.enb_id;
 /**
  * Leave the UE context in UNREGISTERED state.
  * No subscription information at this point.
  * Not informing the NAS layer at this point. It will be done at the TAU step later on.
  * We also did not receive any NAS message until yet.
  *
  * Just store the received pending MM_CONTEXT and PDN information as pending.
  * Will check on  them @TAU, before sending S10_CONTEXT_REQUEST to source MME.
  * The pending TAU information is already stored.
  */
 /** Set the MM EPS Context as pending. */
 ue_context_p->pending_mm_ue_eps_context = calloc (1, sizeof (mm_context_eps_t));
 memcpy((void*)ue_context_p->pending_mm_ue_eps_context, (void*)&forward_relocation_request_pP->ue_eps_mm_context, sizeof(mm_context_eps_t));

 /**
  * Update the coll_keys with the IMSI.
  */
 mme_ue_context_update_coll_keys (&mme_app_desc.mme_ue_contexts, ue_context_p,
     ue_context_p->enb_s1ap_id_key,
     ue_context_p->mme_ue_s1ap_id,
     imsi,      /**< New IMSI. */
     ue_context_p->mme_s11_teid,
     ue_context_p->local_mme_s10_teid,
     &ue_context_p->guti);

 /**
  * No message needs to be sent to the NAS layer.
  * Directly continuing with the S11 Create Session Request.
  */
 if(mme_app_send_s11_create_session_req_from_handover_tau(ue_context_p->mme_ue_s1ap_id) != RETURNok){
   OAILOG_CRITICAL (LOG_MME_APP, "MME_APP_FORWARD_RELOCATION_REQUEST. Sending CSR to SAE-GW failed for UE " MME_UE_S1AP_ID_FMT ". \n", ue_context_p->mme_ue_s1ap_id);
   /** Deallocate the ue context and remove from MME_APP map. */
   mme_remove_ue_context (&mme_app_desc.mme_ue_contexts, ue_context_p);
   /** Send back failure. */
   mme_app_send_s10_forward_relocation_response_err(forward_relocation_request_pP->s10_source_mme_teid.teid, forward_relocation_request_pP->s10_source_mme_teid.ipv4, RELOCATION_FAILURE);
   bdestroy(forward_relocation_request_pP->eutran_container.container_value);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Copy the container. */
 ue_context_p->pending_s1ap_source_to_target_handover_container = forward_relocation_request_pP->eutran_container.container_value;

 /** Start the S10 MME Handover Completion timer. */
// if (timer_setup (mme_config.mme_s10_handover_completion_timer, 0,
//     TASK_MME_APP, INSTANCE_DEFAULT, TIMER_ONE_SHOT, (void *) &(ue_context_p->mme_ue_s1ap_id), &(ue_context_p->mme_s10_handover_completion_timer.id)) < 0) {
//   OAILOG_ERROR (LOG_MME_APP, "Failed to start the MME S10 Handover Completion timer for UE id " MME_UE_S1AP_ID_FMT " for duration %d \n", ue_context_p->mme_ue_s1ap_id, mme_config.mme_mobility_completion_timer);
//   ue_context_p->mme_paging_timeout_timer.id = MME_APP_TIMER_INACTIVE_ID;
//   /**
//    * UE will be implicitly detached, if this timer runs out. It should be manually removed.
//    * S10 FW Relocation Complete removes this timer.
//    */
// } else {
//   OAILOG_DEBUG (LOG_MME_APP, "MME APP : Activated the MME S10 Handover Completion timer UE id  " MME_UE_S1AP_ID_FMT ". Waiting for UE to go back from IDLE mode to ACTIVE mode.. Timer Id %u. "
//       "Timer duration %d \n", ue_context_p->mme_ue_s1ap_id, ue_context_p->mme_paging_timeout_timer.id, mme_config.mme_paging_timeout_timer);
//   /** Upon expiration, invalidate the timer.. no flag needed. */
// }
 /** No initialization of timers here. */
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Callback method called if UE is registered.
 * This method could be also put somewhere else.
 */
int EmmCbS1apDeregistered(mme_ue_s1ap_id_t ueId){

  MessageDef                    *message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);

  OAILOG_INFO(LOG_MME_APP, "Entered callback handler for UE-DEREGISTERED state of UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT ". Not implicitly removing resources with state change "
      "(must send an EMM_AS signal with ESTABLISH_REJ.. etc.). \n", ueId);
  OAILOG_FUNC_OUT (LOG_MME_APP);

}

/**
 * Callback method called if UE is registered.
 * This method could be also put somewhere else.
 */
int EmmCbS1apRegistered(mme_ue_s1ap_id_t ueId){

  MessageDef                    *message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);

  /** Find the UE context. */
  ue_context_t * ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, ueId);
  DevAssert(ue_context_p); /**< Should always exist. Any mobility issue in which this could occur? */

  OAILOG_INFO(LOG_MME_APP, "Entered callback handler for UE-REGISTERED state of UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT ". \n", ueId);
  /** Trigger a Create Session Request. */
  imsi64_t                                imsi64 = INVALID_IMSI64;
  int                                     rc = RETURNok;

  /**
   * Consider the UE authenticated. */
  ue_context_p->imsi_auth = IMSI_AUTHENTICATED;

  /** Check if there is a pending deactivation flag is set. */
  if(ue_context_p->pending_bearer_deactivation){
    OAILOG_INFO(LOG_MME_APP, "After UE entered UE_REGISTERED state, initiating bearer deactivation for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT ". \n", ueId);
    ue_context_p->pending_bearer_deactivation = false;
    ue_context_p->ue_context_rel_cause = S1AP_NAS_NORMAL_RELEASE;
    /** Reset any pending downlink bearers. */
    memset(&ue_context_p->pending_s1u_downlink_bearer, 0, sizeof(ue_context_p)->pending_s1u_downlink_bearer);
    ue_context_p->pending_s1u_downlink_bearer_ebi = 0;

    // Notify S1AP to send UE Context Release Command to eNB.
    mme_app_itti_ue_context_release (ue_context_p, ue_context_p->ue_context_rel_cause);
  }else{
    /** No pending bearer deactivation. Check if there is a pending downlink bearer and send the DL-GTP Tunnel Information to the SAE-GW. */
    message_p = itti_alloc_new_message (TASK_MME_APP, S11_MODIFY_BEARER_REQUEST);
    AssertFatal (message_p , "itti_alloc_new_message Failed");
    itti_s11_modify_bearer_request_t *s11_modify_bearer_request = &message_p->ittiMsg.s11_modify_bearer_request;
    memset ((void *)s11_modify_bearer_request, 0, sizeof (itti_s11_modify_bearer_request_t));
    s11_modify_bearer_request->peer_ip = mme_config.ipv4.sgw_s11;
    s11_modify_bearer_request->teid = ue_context_p->sgw_s11_teid;
    s11_modify_bearer_request->local_teid = ue_context_p->mme_s11_teid;
    /*
     * Delay Value in integer multiples of 50 millisecs, or zero
     */
    // todo: multiple bearers!
    s11_modify_bearer_request->delay_dl_packet_notif_req = 0;  // TO DO
    s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id = ue_context_p->pending_s1u_downlink_bearer_ebi;
    memcpy (&s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].s1_eNB_fteid,
        &ue_context_p->pending_s1u_downlink_bearer,
        sizeof (ue_context_p->pending_s1u_downlink_bearer));
    s11_modify_bearer_request->bearer_contexts_to_be_modified.num_bearer_context = 1;

    s11_modify_bearer_request->bearer_contexts_to_be_removed.num_bearer_context = 0;

    s11_modify_bearer_request->mme_fq_csid.node_id_type = GLOBAL_UNICAST_IPv4; // TO DO
    s11_modify_bearer_request->mme_fq_csid.csid = 0;   // TO DO ...
    memset(&s11_modify_bearer_request->indication_flags, 0, sizeof(s11_modify_bearer_request->indication_flags));   // TO DO
    s11_modify_bearer_request->rat_type = RAT_EUTRAN;
    /*
     * S11 stack specific parameter. Not used in standalone epc mode
     */
    s11_modify_bearer_request->trxn = NULL;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S11_MME ,
        NULL, 0, "0 S11_MODIFY_BEARER_REQUEST teid %u ebi %u", s11_modify_bearer_request->teid,
        s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id);
    itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);

    /** Reset any pending downlink bearers. */
    memset(&ue_context_p->pending_s1u_downlink_bearer, 0, sizeof(ue_context_p)->pending_s1u_downlink_bearer);
    ue_context_p->pending_s1u_downlink_bearer_ebi = 0;
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Send an S1AP Handover Request.
 */
static
void mme_app_send_s1ap_handover_request(mme_ue_s1ap_id_t mme_ue_s1ap_id,
    uint32_t                enb_id,
    uint16_t                encryption_algorithm_capabilities,
    uint16_t                integrity_algorithm_capabilities,
    uint8_t                 nh[AUTH_NH_SIZE],
    uint8_t                 ncc){

  MessageDef                *message_p = NULL;
  ue_context_t              *ue_context_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);

  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, mme_ue_s1ap_id);
  DevAssert(ue_context_p); /**< Should always exist. Any mobility issue in which this could occur? */

  /** Get the EMM Context. */
  message_p = itti_alloc_new_message (TASK_MME_APP, S1AP_HANDOVER_REQUEST);

  itti_s1ap_handover_request_t *handover_request_p = &message_p->ittiMsg.s1ap_handover_request;
  /** UE_ID. */
  handover_request_p->ue_id = mme_ue_s1ap_id;
  handover_request_p->macro_enb_id = enb_id;
  /** Handover Type & Cause will be set in the S1AP layer. */
  /** Set the AMBR Parameters. */
  handover_request_p->ambr.br_ul = ue_context_p->subscribed_ambr.br_ul;
  handover_request_p->ambr.br_dl = ue_context_p->subscribed_ambr.br_dl;
  /** Set all active bearers to be setup. */
  handover_request_p->bearer_ctx_to_be_setup_list.n_bearers   = ue_context_p->nb_ue_bearer_ctxs;
  handover_request_p->bearer_ctx_to_be_setup_list.bearer_ctxs = (void*)&ue_context_p->bearer_ctxs;

  hash_table_ts_t * bearer_contexts1 = (hash_table_ts_t*)handover_request_p->bearer_ctx_to_be_setup_list.bearer_ctxs;

  /** Set the Security Capabilities. */
  handover_request_p->security_capabilities_encryption_algorithms = encryption_algorithm_capabilities;
  handover_request_p->security_capabilities_integrity_algorithms  = integrity_algorithm_capabilities;
  /** Set the Security Context. */
  handover_request_p->ncc = ncc;
  memcpy(handover_request_p->nh, nh, AUTH_NH_SIZE);
  /** Set the Source-to-Target Transparent container from the pending information, which will be removed from the UE_Context. */
  handover_request_p->source_to_target_eutran_container = ue_context_p->pending_s1ap_source_to_target_handover_container;
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
  OAILOG_DEBUG (LOG_MME_APP, "Sending S1AP Handover Request message for UE "MME_UE_S1AP_ID_FMT ". \n.", mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Send an S1AP Handover Preparation Failure to the S1AP layer.
 * Not triggering release of resources, everything will stay as it it.
 * The MME_APP ITTI message elements though need to be deallocated.
 */
static
void mme_app_send_s1ap_handover_preparation_failure(mme_ue_s1ap_id_t mme_ue_s1ap_id, enb_ue_s1ap_id_t enb_ue_s1ap_id, sctp_assoc_id_t assoc_id, MMECause_t mmeCause){
  OAILOG_FUNC_IN (LOG_MME_APP);
  /** Send a S1AP HANDOVER PREPARATION FAILURE TO THE SOURCE ENB. */
  MessageDef * message_p = itti_alloc_new_message (TASK_MME_APP, S1AP_HANDOVER_PREPARATION_FAILURE);
  DevAssert (message_p != NULL);
  DevAssert(mmeCause != REQUEST_ACCEPTED);

  itti_s1ap_handover_preparation_failure_t *s1ap_handover_preparation_failure_p = &message_p->ittiMsg.s1ap_handover_preparation_failure;
  memset ((void*)s1ap_handover_preparation_failure_p, 0, sizeof (itti_s1ap_handover_preparation_failure_t));

  /** Set the identifiers. */
  s1ap_handover_preparation_failure_p->mme_ue_s1ap_id = mme_ue_s1ap_id;
  s1ap_handover_preparation_failure_p->enb_ue_s1ap_id = enb_ue_s1ap_id;
  s1ap_handover_preparation_failure_p->assoc_id = assoc_id;
  /** Set the negative cause. */
  s1ap_handover_preparation_failure_p->cause = mmeCause;

  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "MME_APP Sending S1AP HANDOVER_PREPARATION_FAILURE");
  /** Sending a message to S1AP. */
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Send an S1AP Path Switch Request Failure to the S1AP layer.
 * Not triggering release of resources, everything will stay as it it.
 * The MME_APP ITTI message elements though need to be deallocated.
 */
static
void mme_app_send_s1ap_path_switch_request_failure(mme_ue_s1ap_id_t mme_ue_s1ap_id, enb_ue_s1ap_id_t enb_ue_s1ap_id, sctp_assoc_id_t assoc_id, MMECause_t mmeCause){
  OAILOG_FUNC_IN (LOG_MME_APP);
  /** Send a S1AP Path Switch Request Failure TO THE TARGET ENB. */
  MessageDef * message_p = itti_alloc_new_message (TASK_MME_APP, S1AP_PATH_SWITCH_REQUEST_FAILURE);
  DevAssert (message_p != NULL);
  DevAssert(mmeCause != REQUEST_ACCEPTED);

  itti_s1ap_path_switch_request_failure_t *s1ap_path_switch_request_failure_p = &message_p->ittiMsg.s1ap_path_switch_request_failure;
  memset ((void*)s1ap_path_switch_request_failure_p, 0, sizeof (itti_s1ap_path_switch_request_failure_t));

  /** Set the identifiers. */
  s1ap_path_switch_request_failure_p->mme_ue_s1ap_id = mme_ue_s1ap_id;
  s1ap_path_switch_request_failure_p->enb_ue_s1ap_id = enb_ue_s1ap_id;
  s1ap_path_switch_request_failure_p->assoc_id = assoc_id; /**< To whatever the new SCTP association is. */
  /** Set the negative cause. */
  s1ap_path_switch_request_failure_p->cause = mmeCause;

  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "MME_APP Sending S1AP PATH_SWITCH_REQUEST_FAILURE");
  /** Sending a message to S1AP. */
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Method to send the handover command to the source-eNB.
 * Will not make any changes in the UE context.
 * No F-Container will/needs to be stored temporarily.
 * No timer to be started.
 */
static
void mme_app_send_s1ap_handover_command(mme_ue_s1ap_id_t mme_ue_s1ap_id, enb_ue_s1ap_id_t enb_ue_s1ap_id, bstring target_to_source_cont){
  MessageDef * message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  /**
   * Prepare a S1AP ITTI message without changing the UE context.
   */
  message_p = itti_alloc_new_message (TASK_MME_APP, S1AP_HANDOVER_COMMAND);
  DevAssert (message_p != NULL);
  itti_s1ap_handover_command_t *handover_command_p = &message_p->ittiMsg.s1ap_handover_command;
  memset (handover_command_p, 0, sizeof (itti_s1ap_handover_command_t));
  handover_command_p->mme_ue_s1ap_id = mme_ue_s1ap_id;
  handover_command_p->enb_ue_s1ap_id = enb_ue_s1ap_id; /**< Just ENB_UE_S1AP_ID. */
  /** Set the E-UTRAN Target-To-Source-Transparent-Container. */
  handover_command_p->eutran_target_to_source_container = target_to_source_cont;
  // todo: what will the enb_ue_s1ap_ids for single mme s1ap handover will be.. ?
  OAILOG_INFO(LOG_MME_APP, "Sending S1AP handover command to the source eNodeB for UE " MME_UE_S1AP_ID_FMT ". \n", mme_ue_s1ap_id);
  /** The ENB_ID/Stream information in the UE_Context are still the ones for the source-ENB and the SCTP-UE_ID association is not set yet for the new eNB. */
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S1AP_MME, NULL, 0, "MME_APP Sending S1AP HANDOVER_COMMAND.");
  /** Sending a message to S1AP. */
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Method to send the path switch request acknowledge to the target-eNB.
 * Will not make any changes in the UE context.
 * No timer to be started.
 */
static
void mme_app_send_s1ap_path_switch_request_acknowledge(mme_ue_s1ap_id_t mme_ue_s1ap_id){
  MessageDef * message_p = NULL;
  bearer_context_t                       *current_bearer_p = NULL;
  ebi_t                                   bearer_id = 0;
  ue_context_t                           *ue_context_p = NULL;
  emm_data_context_t                     *ue_nas_ctx = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, mme_ue_s1ap_id);

  if (ue_context_p == NULL) {
    OAILOG_ERROR (LOG_MME_APP, "UE context doesn't exist for UE %06" PRIX32 "/dec%u\n", mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  /** Get the EMM Context too for the AS security parameters. */
  ue_nas_ctx = emm_data_context_get(&_emm_data, mme_ue_s1ap_id);
  if(!ue_nas_ctx || ue_nas_ctx->_tai_list.n_tais == 0){
    DevMessage(" No EMM Data Context exists for UE with mmeUeS1apId " + mme_ue_s1ap_id + ".\n");
  }

  /**
   * Prepare a S1AP ITTI message without changing the UE context.
   */
  message_p = itti_alloc_new_message (TASK_MME_APP, S1AP_PATH_SWITCH_REQUEST_ACKNOWLEDGE);
  DevAssert (message_p != NULL);
  itti_s1ap_path_switch_request_ack_t *path_switch_req_ack_p = &message_p->ittiMsg.s1ap_path_switch_request_ack;
  memset (path_switch_req_ack_p, 0, sizeof (itti_s1ap_path_switch_request_ack_t));
  path_switch_req_ack_p->ue_id= mme_ue_s1ap_id;
  OAILOG_INFO(LOG_MME_APP, "Sending S1AP Path Switch Request Acknowledge to the target eNodeB for UE " MME_UE_S1AP_ID_FMT ". \n", mme_ue_s1ap_id);
  /** The ENB_ID/Stream information in the UE_Context are still the ones for the source-ENB and the SCTP-UE_ID association is not set yet for the new eNB. */
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S1AP_MME, NULL, 0, "MME_APP Sending S1AP PATH_SWITCH_REQUEST_ACKNOWLEDGE.");

  bearer_id = ue_context_p->default_bearer_id;
  current_bearer_p =  mme_app_is_bearer_context_in_list(ue_context_p->mme_ue_s1ap_id, bearer_id);
  path_switch_req_ack_p->eps_bearer_id = bearer_id;
  path_switch_req_ack_p->bearer_s1u_sgw_fteid.interface_type = S1_U_SGW_GTP_U;
  path_switch_req_ack_p->bearer_s1u_sgw_fteid.teid = current_bearer_p->s_gw_teid;

  if ((current_bearer_p->s_gw_address.pdn_type == IPv4)
      || (current_bearer_p->s_gw_address.pdn_type == IPv4_AND_v6)) {
    path_switch_req_ack_p->bearer_s1u_sgw_fteid.ipv4 = 1;
    memcpy (&path_switch_req_ack_p->bearer_s1u_sgw_fteid.ipv4_address, current_bearer_p->s_gw_address.address.ipv4_address, 4);
   }

  if ((current_bearer_p->s_gw_address.pdn_type == IPv6)
      || (current_bearer_p->s_gw_address.pdn_type == IPv4_AND_v6)) {
    path_switch_req_ack_p->bearer_s1u_sgw_fteid.ipv6 = 1;
    memcpy (path_switch_req_ack_p->bearer_s1u_sgw_fteid.ipv6_address, current_bearer_p->s_gw_address.address.ipv6_address, 16);
  }

  uint16_t encryption_algorithm_capabilities = 0;
  uint16_t integrity_algorithm_capabilities = 0;

  emm_data_context_get_security_parameters(mme_ue_s1ap_id, &encryption_algorithm_capabilities, &integrity_algorithm_capabilities);
  /** Set the new security parameters. */
  path_switch_req_ack_p->security_capabilities_encryption_algorithms = encryption_algorithm_capabilities;
  path_switch_req_ack_p->security_capabilities_integrity_algorithms  = integrity_algorithm_capabilities;

  /** Set the next hop value and the NCC value. */
  memcpy(path_switch_req_ack_p->nh, ue_nas_ctx->_security.nh_conj, AUTH_NH_SIZE);
  path_switch_req_ack_p->ncc = ue_nas_ctx->_security.ncc;

  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S1AP_MME, NULL, 0,
      "0 S1AP_PATH_SWITCH_REQUEST_ACKNOWLEDGE ebi %u s1u_sgw teid %u sea 0x%x sia 0x%x ncc %d",
      path_switch_req_ack_p->eps_bearer_id,
      path_switch_req_ack_p->bearer_s1u_sgw_fteid.teid,
      path_switch_req_ack_p->security_capabilities_encryption_algorithms, path_switch_req_ack_p->security_capabilities_integrity_algorithms,
      path_switch_req_ack_p->ncc);
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);

  /**
   * Change the ECM state to connected.
   * AN UE_Reference should already be created with Path_Switch_Request.
   */
  mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts, ue_context_p, ECM_CONNECTED);

  // todo: timer for path switch request
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Method to send the S1AP MME Status Transfer to the target-eNB.
 * Will not make any changes in the UE context.
 * No F-Container will/needs to be stored temporarily.
 */
static
void mme_app_send_s1ap_mme_status_transfer(mme_ue_s1ap_id_t mme_ue_s1ap_id, enb_ue_s1ap_id_t enb_ue_s1ap_id, uint32_t enb_id, bstring source_to_target_cont){
  MessageDef * message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  /**
   * Prepare a S1AP ITTI message without changing the UE context.
   */
  message_p = itti_alloc_new_message (TASK_MME_APP, S1AP_MME_STATUS_TRANSFER);
  DevAssert (message_p != NULL);
  itti_s1ap_status_transfer_t *status_transfer_p = &message_p->ittiMsg.s1ap_mme_status_transfer;
  memset (status_transfer_p, 0, sizeof (itti_s1ap_status_transfer_t));
  status_transfer_p->mme_ue_s1ap_id = mme_ue_s1ap_id;
  status_transfer_p->enb_ue_s1ap_id = enb_ue_s1ap_id; /**< Just ENB_UE_S1AP_ID. */
  /** Set the current enb_id. */
  status_transfer_p->enb_id = enb_id;
  /** Set the E-UTRAN Target-To-Source-Transparent-Container. */
  status_transfer_p->bearerStatusTransferList_buffer = source_to_target_cont;
  // todo: what will the enb_ue_s1ap_ids for single mme s1ap handover will be.. ?
  OAILOG_INFO(LOG_MME_APP, "Sending S1AP MME_STATUS_TRANSFER command to the target eNodeB for UE " MME_UE_S1AP_ID_FMT ". \n", mme_ue_s1ap_id);
  /** The ENB_ID/Stream information in the UE_Context are still the ones for the source-ENB and the SCTP-UE_ID association is not set yet for the new eNB. */
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S1AP_MME, NULL, 0, "MME_APP Sending S1AP MME_STATUS_TRANSFER.");
  /** Sending a message to S1AP. */
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Send an S10 Forward Relocation response with error cause.
 * It shall not trigger creating a local S10 tunnel.
 * Parameter is the TEID & IP of the SOURCE-MME.
 */
static
void mme_app_send_s10_forward_relocation_response_err(teid_t mme_source_s10_teid, uint32_t mme_source_ipv4_address, MMECause_t mmeCause){
  OAILOG_FUNC_IN (LOG_MME_APP);

  /** Send a Forward Relocation RESPONSE with error cause: RELOCATION_FAILURE. */
  MessageDef * message_p = itti_alloc_new_message (TASK_MME_APP, S10_FORWARD_RELOCATION_RESPONSE);
  DevAssert (message_p != NULL);

  itti_s10_forward_relocation_response_t *forward_relocation_response_p = &message_p->ittiMsg.s10_forward_relocation_response;
  memset ((void*)forward_relocation_response_p, 0, sizeof (itti_s10_forward_relocation_response_t));

  /**
   * Set the TEID of the source MME.
   * No need to set local_teid since no S10 tunnel will be created in error case.
   */
  forward_relocation_response_p->teid = mme_source_s10_teid;
  /** Set the IPv4 address of the source MME. */
  forward_relocation_response_p->peer_ip = mme_source_ipv4_address;
  forward_relocation_response_p->cause = mmeCause;

  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "MME_APP Sending S10 FORWARD_RELOCATION_RESPONSE_ERR");

  /** Sending a message to S10. */
  itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);

  OAILOG_FUNC_OUT (LOG_MME_APP);
}

void
mme_app_handle_forward_relocation_response(
    const itti_s10_forward_relocation_response_t* const forward_relocation_response_pP
    )
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  uint64_t                                imsi = 0;
  int16_t                                 bearer_id =0;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (forward_relocation_response_pP );

  ue_context_p = mme_ue_context_exists_s10_teid (&mme_app_desc.mme_ue_contexts, forward_relocation_response_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 S10_FORWARD_RELOCATION_RESPONSE local S11 teid " TEID_FMT " ", forward_relocation_response_pP->teid);
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", forward_relocation_response_pP->teid);
    /**
     * The HANDOVER_NOTIFY timeout will purge any UE_Contexts, if exists.
     * Not manually purging anything.
     * todo: Not sending anything to the target side? (RELOCATION_FAILURE?)
     */
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 S10_FORWARD_RELOCATION_RESPONSE local S11 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
      forward_relocation_response_pP->teid, ue_context_p->imsi);
  /**
   * Check that the UE_Context is in correct (EMM_REGISTERED) state.
   */
  if(ue_context_p->mm_state != UE_REGISTERED){
    /** Deal with the error case. */
    OAILOG_ERROR(LOG_MME_APP, "UE MME context with IMSI " IMSI_64_FMT " and mmeS1apUeId " MME_UE_S1AP_ID_FMT " is not in REGISTERED state, instead %d. Doing an implicit detach. \n",
        ue_context_p->imsi, ue_context_p->mme_ue_s1ap_id, ue_context_p->mm_state);
    /** Purge the container. */
    bdestroy(forward_relocation_response_pP->eutran_container.container_value);

    /**
     * Don't send an S10 Relocation Failure to the target side. Let the target side do an implicit detach with timeout.
     * RCR will be sent only with HANDOVER_CANCELLATION.
     */
    /** Perform an implicit detach. Wrong UE state to send a preparation failure. */
    ue_context_p->ue_context_rel_cause = S1AP_IMPLICIT_CONTEXT_RELEASE;
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    itti_nas_implicit_detach_ue_ind_t *nas_implicit_detach_ue_ind_p = &message_p->ittiMsg.nas_implicit_detach_ue_ind;
    memset ((void*)nas_implicit_detach_ue_ind_p, 0, sizeof (itti_nas_implicit_detach_ue_ind_t));
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }

  if (forward_relocation_response_pP->cause != REQUEST_ACCEPTED) {
    /** Purge the container. */
    bdestroy(forward_relocation_response_pP->eutran_container.container_value);

    /**
     * We are in EMM-REGISTERED state, so we don't need to perform an implicit detach.
     * In the target side, we won't do anything. We assumed everything is taken care of (No Relocation Cancel Request to be sent).
     * No handover timers in the source-MME side exist.
     * We will only send an Handover Preparation message and leave the UE context as it is (including the S10 tunnel endpoint at the source-MME side).
     * The handover notify timer is only at the target-MME side. That's why, its not in the method below.
     */
    mme_app_send_s1ap_handover_preparation_failure(ue_context_p->mme_ue_s1ap_id,
        ue_context_p->enb_ue_s1ap_id, ue_context_p->sctp_assoc_id_key, RELOCATION_FAILURE);
    OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
  }
  /** We are the source-MME side. Store the counterpart as target-MME side. */
  ue_context_p->remote_mme_s10_teid = forward_relocation_response_pP->s10_target_mme_teid.teid;
  //---------------------------------------------------------
  // Process itti_s10_forward_relocation_response_t.bearer_context_admitted
  //---------------------------------------------------------

  /**
   * Iterate through the admitted bearer items.
   * Currently only EBI received.. but nothing is done with that.
   * todo: check that the bearer exists? bearer id may change? used for data forwarding?
   * todo: must check if any bearer exist at all? todo: must check that the number bearers is as expected?
   * todo: DevCheck ((bearer_id < BEARERS_PER_UE) && (bearer_id >= 0), bearer_id, BEARERS_PER_UE, 0);
   */
  bearer_id = forward_relocation_response_pP->list_of_bearers.bearer_contexts[0].eps_bearer_id /* - 5 */ ;
  // todo: what is the dumping doing? printing? needed for s10?

   /**
    * Not doing/storing anything in the NAS layer. Just sending handover command back.
    * Send a S1AP Handover Command to the source eNodeB.
    */
   OAILOG_INFO(LOG_MME_APP, "MME_APP UE context is in REGISTERED state. Sending a Handover Command to the source-ENB with enbId: %d for UE with mmeUeS1APId : " MME_UE_S1AP_ID_FMT " and IMSI " IMSI_64_FMT " after S10 Forward Relocation Response. \n",
       ue_context_p->e_utran_cgi.cell_identity.enb_id, ue_context_p->mme_ue_s1ap_id, ue_context_p->imsi);
   /** Send a Handover Command. */
   mme_app_send_s1ap_handover_command(ue_context_p->mme_ue_s1ap_id, ue_context_p->enb_ue_s1ap_id, forward_relocation_response_pP->eutran_container.container_value);
   /**
    * No new UE identifier. We don't update the coll_keys.
    * As the specification said, we will leave the UE_CONTEXT as it is. Not checking further parameters.
    * No timers are started. Only timers are in the source-ENB and the custom new timer in the source MME.
    * ********************************************
    * The ECM state will not be changed.
    */
   OAILOG_FUNC_OUT (LOG_MME_APP);
}

void
mme_app_handle_forward_access_context_notification(
    const itti_s10_forward_access_context_notification_t* const forward_access_context_notification_pP
    )
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  uint64_t                                imsi = 0;
  int16_t                                 bearer_id =0;

  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received S10_FORWARD_ACCESS_CONTEXT_NOTIFICATION from S10. \n");
  DevAssert (forward_access_context_notification_pP );

  /** Here it checks the local TEID. */
  ue_context_p = mme_ue_context_exists_s10_teid (&mme_app_desc.mme_ue_contexts, forward_access_context_notification_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "0 S10_FORWARD_ACCESS_CONTEXT_NOTIFICATION local S11 teid " TEID_FMT " ", forward_access_context_notification_pP->teid);
    /** We cannot send an S10 reject, since we don't have the destination TEID. */
    /**
     * todo: lionel
     * If we ignore the request (for which a transaction exits), and a second request arrives, there is a dev_assert..
     * therefore removing the transaction?
     */
    /** Not performing an implicit detach. The handover timeout should erase the context (incl. the S10 Tunnel Endpoint, which we don't erase here in the error case). */
    OAILOG_ERROR(LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", forward_access_context_notification_pP->teid);
    bdestroy(forward_access_context_notification_pP->eutran_container.container_value);
    OAILOG_FUNC_OUT (LOG_MME_APP);

  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "0 S10_FORWARD_ACCESS_CONTEXT_NOTIFICATION local S10 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
      forward_access_context_notification_pP->teid, ue_context_p->imsi);
  /** Send a S1AP MME Status Transfer Message the target eNodeB. */
  message_p = itti_alloc_new_message (TASK_MME_APP, S10_FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE);
  DevAssert (message_p != NULL);
  itti_s10_forward_access_context_acknowledge_t *s10_mme_forward_access_context_acknowledge_p =
      &message_p->ittiMsg.s10_forward_access_context_acknowledge;
  s10_mme_forward_access_context_acknowledge_p->teid        = ue_context_p->remote_mme_s10_teid;  /**< Set the target TEID. */
  s10_mme_forward_access_context_acknowledge_p->local_teid  = ue_context_p->local_mme_s10_teid;   /**< Set the local TEID. */
  s10_mme_forward_access_context_acknowledge_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr; /**< Set the target TEID. */
  s10_mme_forward_access_context_acknowledge_p->trxn = forward_access_context_notification_pP->trxn; /**< Set the target TEID. */
  /** Check that there is a pending handover process. */
  if(ue_context_p->mm_state != UE_UNREGISTERED){
    /** Deal with the error case. */
    OAILOG_ERROR(LOG_MME_APP, "UE MME context with IMSI " IMSI_64_FMT " and mmeS1apUeId " MME_UE_S1AP_ID_FMT " is not in UNREGISTERED state. "
        "Sending reject back and performing an implicit detach. \n",
        ue_context_p->imsi, ue_context_p->mme_ue_s1ap_id);
    s10_mme_forward_access_context_acknowledge_p->cause =  SYSTEM_FAILURE;
    bdestroy(forward_access_context_notification_pP->eutran_container.container_value);
    itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
    /** Sending 2 ITTI messages back to back to perform an implicit detach on the target-MME side. */
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  s10_mme_forward_access_context_acknowledge_p->cause = REQUEST_ACCEPTED;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "MME_APP Sending S10 FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE.");
  itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);

  /** Send a S1AP MME Status Transfer Message the target eNodeB. */
  mme_app_send_s1ap_mme_status_transfer(ue_context_p->mme_ue_s1ap_id, ue_context_p->enb_ue_s1ap_id, ue_context_p->pending_handover_enb_id, forward_access_context_notification_pP->eutran_container.container_value);
  /**
   * Todo: Lionel
   * Setting the ECM state with the first message to the ENB (HANDOVER_REQUEST - no enb_ue_s1ap_id exists yet then) or with this one?
   */
  if (ue_context_p->ecm_state != ECM_CONNECTED)
  {
    OAILOG_DEBUG (LOG_MME_APP, "MME_APP:MME_STATUS_TRANSFER. Establishing S1 sig connection. mme_ue_s1ap_id = %d,enb_ue_s1ap_id = %d \n", ue_context_p->mme_ue_s1ap_id,
        ue_context_p->pending_handover_enb_ue_s1ap_id);
    mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts, ue_context_p, ECM_CONNECTED);
  }

  OAILOG_INFO(LOG_MME_APP, "Sending S1AP MME Status transfer to the target eNodeB for UE "
      "with enb_ue_s1ap_id: %d, mme_ue_s1ap_id. %d. \n", ue_context_p->pending_handover_enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_forward_access_context_acknowledge(
    const itti_s10_forward_access_context_acknowledge_t* const forward_access_context_acknowledge_pP
    )
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  uint64_t                                imsi = 0;
  int16_t                                 bearer_id =0;

  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received S10_FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE from S10. \n");
  DevAssert (forward_access_context_acknowledge_pP );

  /** Here it checks the local TEID. */
  ue_context_p = mme_ue_context_exists_s10_teid (&mme_app_desc.mme_ue_contexts, forward_access_context_acknowledge_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "0 S10_FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE local S11 teid " TEID_FMT " ", forward_access_context_acknowledge_pP->teid);
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", forward_access_context_acknowledge_pP->teid);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "0 S10_FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE local S11 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
      forward_access_context_acknowledge_pP->teid, ue_context_p->imsi);

  /** Check that there is a pending handover process. */
  if(ue_context_p->mm_state != UE_REGISTERED){
    /** Deal with the error case. */
    OAILOG_ERROR(LOG_MME_APP, "UE MME context with IMSI " IMSI_64_FMT " and mmeS1apUeId: " MME_UE_S1AP_ID_FMT " is not in UE_REGISTERED state, instead %d, when S10_FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE is received. "
        "Ignoring the error and waiting remove the UE contexts triggered by HSS. \n",
        ue_context_p->imsi, ue_context_p->mme_ue_s1ap_id, ue_context_p->mm_state);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_handover_request_acknowledge(
     const itti_s1ap_handover_request_acknowledge_t * const handover_request_acknowledge_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;

 OAILOG_FUNC_IN (LOG_MME_APP);
 OAILOG_DEBUG (LOG_MME_APP, "Received S1AP_HANDOVER_REQUEST_ACKNOWLEDGE from S10. \n");
 /** Just get the S1U-ENB-FTEID. */
 ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, handover_request_acknowledge_pP->mme_ue_s1ap_id);
 if (ue_context_p == NULL) {
   OAILOG_ERROR(LOG_MME_APP, "No MME_APP UE context for the UE with mmeUeS1APId : " MME_UE_S1AP_ID_FMT ". \n", handover_request_acknowledge_pP->mme_ue_s1ap_id);
   MSC_LOG_EVENT (MSC_MMEAPP_MME, "S1AP_HANDOVER_FAILURE. No UE existing mmeS1apUeId %d. \n", handover_request_acknowledge_pP->mme_ue_s1ap_id);
   /** Ignore the message. */
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }

 /** Set the pending enb_id (main Ue_reference will be changed to target only with handover_notify). */
 ue_context_p->pending_handover_enb_ue_s1ap_id = handover_request_acknowledge_pP->enb_ue_s1ap_id;
 /**
  * Set the downlink bearers as pending.
  * Will be forwarded to the SAE-GW after the HANDOVER_NOTIFY/S10_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE.
  * todo: currently only a single bearer will be set.
  */
 memcpy(&ue_context_p->pending_s1u_downlink_bearer, &handover_request_acknowledge_pP->bearer_s1u_enb_fteid, sizeof(FTeid_t));
 ue_context_p->pending_s1u_downlink_bearer_ebi = handover_request_acknowledge_pP->eps_bearer_id;

 /** Check if the UE is EMM-REGISTERED or not. */
 if(ue_context_p->mm_state == UE_REGISTERED){
   /**
    * UE is registered, we assume in this case that the source-MME is also attached to the current Send a handover command to the source-ENB.
    * The SCTP-assoc to MME_UE_S1AP_ID association is still to the old one, continue using it.
    */
   OAILOG_INFO(LOG_MME_APP, "No MME_APP UE context is in REGISTERED state. Sending a Handover Command to the source-ENB with enbId: %d for UE with mmeUeS1APId : " MME_UE_S1AP_ID_FMT ". \n",
       handover_request_acknowledge_pP->mme_ue_s1ap_id, ue_context_p->e_utran_cgi.cell_identity.enb_id);
   /** Send a Handover Command. */
   mme_app_send_s1ap_handover_command(handover_request_acknowledge_pP->mme_ue_s1ap_id, handover_request_acknowledge_pP->enb_ue_s1ap_id, handover_request_acknowledge_pP->target_to_source_eutran_container);
   /**
    * Save the new ENB_UE_S1AP_ID
    * Don't update the coll_keys with the new enb_ue_s1ap_id.
    */
   /**
    * As the specification said, we will leave the UE_CONTEXT as it is. Not checking further parameters.
    * No timers are started. Only timers are in the source-ENB.
    * ********************************************
    * The ECM state will be left as ECM-IDLE (the one from the created ue_reference).
    * With the first S1AP message to the eNB (MME_STATUS) or with the received HANDOVER_NOTIFY, we will set to ECM_CONNECTED.
    */
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }

 /**
  * UE is in UE_UNREGISTERED state. Assuming inter-MME S1AP Handover was triggered.
  * Sending FW_RELOCATION_RESPONSE.
  */
 message_p = itti_alloc_new_message (TASK_MME_APP, S10_FORWARD_RELOCATION_RESPONSE);
 DevAssert (message_p != NULL);
 itti_s10_forward_relocation_response_t *forward_relocation_response_p = &message_p->ittiMsg.s10_forward_relocation_response;
 memset ((void*)forward_relocation_response_p, 0, sizeof (itti_s10_forward_relocation_response_t));
 /** Set the target S10 TEID. */
 forward_relocation_response_p->teid    = ue_context_p->remote_mme_s10_teid; /**< Only a single target-MME TEID can exist at a time. */
 /**
  * todo: Get the MME from the origin TAI.
  * Currently only one MME is supported.
  */
 forward_relocation_response_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr; /**< todo: Check this is correct. */
 /**
  * Trxn is the only object that has the last seqNum, but we can only search the TRXN in the RB-Tree with the seqNum.
  * We need to store the last seqNum locally.
  * todo: Lionel, any better ideas on this one?
  */
 forward_relocation_response_p->trxn    = ue_context_p->pending_s10_response_trxn;
 /** Set the cause. */
 forward_relocation_response_p->cause = REQUEST_ACCEPTED;
 // todo: no indicator set on the number of modified bearer contexts
 /** Not updating anything in the EMM/ESM layer. No new timers needed. */
 forward_relocation_response_p->list_of_bearers.bearer_contexts[0].eps_bearer_id = ue_context_p->pending_s1u_downlink_bearer_ebi;
 forward_relocation_response_p->list_of_bearers.num_bearer_context = 1;

 /** Set the Source MME_S10_FTEID the same as in S11. */
 OAI_GCC_DIAG_OFF(pointer-to-int-cast);
 forward_relocation_response_p->s10_target_mme_teid.teid = (teid_t) ue_context_p; /**< This one also sets the context pointer. */
 OAI_GCC_DIAG_ON(pointer-to-int-cast);
 forward_relocation_response_p->s10_target_mme_teid.interface_type = S10_MME_GTP_C;
 mme_config_read_lock (&mme_config);
 forward_relocation_response_p->s10_target_mme_teid.ipv4_address = mme_config.ipv4.s10;
 mme_config_unlock (&mme_config);
 forward_relocation_response_p->s10_target_mme_teid.ipv4 = 1;

 /**
  * Update the local_s10_key.
  * Leave the enb_ue_s1ap_id_key as it is. enb_ue_s1ap_id_key will be updated with HANDOVER_NOTIFY and then the registration will be updated.
  * Not setting the key directly in the  ue_context structure. Only over this function!
  */
 mme_ue_context_update_coll_keys (&mme_app_desc.mme_ue_contexts, ue_context_p,
     ue_context_p->enb_s1ap_id_key,   /**< Not updated. */
     ue_context_p->mme_ue_s1ap_id,
     ue_context_p->imsi,
     ue_context_p->mme_s11_teid,       // mme_s11_teid is new
     forward_relocation_response_p->s10_target_mme_teid.teid,       // set with forward_relocation_response!
     &ue_context_p->guti);            /**< No guti exists
 /** Set S10 F-Cause. */
 forward_relocation_response_p->f_cause.fcause_type      = FCAUSE_S1AP;
 forward_relocation_response_p->f_cause.fcause_s1ap_type = FCAUSE_S1AP_RNL;
 forward_relocation_response_p->f_cause.fcause_value     = 0; // todo: set these values later.. currently just RNL

 /** Set the E-UTRAN container. */
 forward_relocation_response_p->eutran_container.container_type = 3;
 /** Just link the bstring. Will be purged in the S10 message. */
 forward_relocation_response_p->eutran_container.container_value = handover_request_acknowledge_pP->target_to_source_eutran_container;

 MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "MME_APP Sending S10 FORWARD_RELOCATION_RESPONSE");

 /**
  * Sending a message to S10.
  * No changes in the contexts, flags, timers, etc.. needed.
  */
 itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_handover_failure (
     const itti_s1ap_handover_failure_t * const handover_failure_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;
 uint64_t                                imsi = 0;

 OAILOG_FUNC_IN (LOG_MME_APP);

 OAILOG_DEBUG (LOG_MME_APP, "Received S1AP_HANDOVER_FAILURE from target eNB for UE_ID " MME_UE_S1AP_ID_FMT ". \n", handover_failure_pP->mme_ue_s1ap_id);

 /** Check that the UE does exist (in both S1AP cases). */
 ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, handover_failure_pP->mme_ue_s1ap_id);
 if (ue_context_p == NULL) {
   OAILOG_ERROR(LOG_MME_APP, "An UE MME context does not exist for UE with mmeS1apUeId %d. \n", handover_failure_pP->mme_ue_s1ap_id);
   MSC_LOG_EVENT (MSC_MMEAPP_MME, "S1AP_HANDOVER_FAILURE. No UE existing mmeS1apUeId %d. \n", handover_failure_pP->mme_ue_s1ap_id);
   /** Ignore the message. */
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Check if the UE is EMM-REGISTERED or not. */
 if(ue_context_p->mm_state == UE_REGISTERED){
   /**
    * UE is registered, we assume in this case that the source-MME is also attached to the current.
    * In this case, we need to re-notify the MME_UE_S1AP_ID<->SCTP association, because it might be removed with the error handling.
    */
   notify_s1ap_new_ue_mme_s1ap_id_association (ue_context_p);
   /** We assume a valid enb & sctp id in the UE_Context. */
   mme_app_send_s1ap_handover_preparation_failure(ue_context_p->mme_ue_s1ap_id, ue_context_p->enb_ue_s1ap_id, ue_context_p->sctp_assoc_id_key, S1AP_HANDOVER_FAILED);
   /**
    * As the specification said, we will leave the UE_CONTEXT as it is. Not checking further parameters.
    * No timers are started. Only timers are in the source-ENB.
    */
   /** In case a system error has occurred, purge the E-UTRAN container. */
   bdestroy(ue_context_p->pending_s1ap_source_to_target_handover_container);

   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /**
  * UE is in UE_UNREGISTERED state. Assuming inter-MME S1AP Handover was triggered.
  * Sending FW_RELOCATION_RESPONSE with error code and implicit detach.
  */

 // Initiate Implicit Detach for the UE
 message_p = itti_alloc_new_message (TASK_MME_APP, S10_FORWARD_RELOCATION_RESPONSE);
 DevAssert (message_p != NULL);
 itti_s10_forward_relocation_response_t *forward_relocation_response_p = &message_p->ittiMsg.s10_forward_relocation_response;
 memset ((void*)forward_relocation_response_p, 0, sizeof (itti_s10_forward_relocation_response_t));
 /** Set the target S10 TEID. */
 forward_relocation_response_p->teid    = ue_context_p->remote_mme_s10_teid; /**< Only a single target-MME TEID can exist at a time. */
 /** Get the MME from the origin TAI. */
 forward_relocation_response_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr; /**< todo: Check this is correct. */
 /**
  * Trxn is the only object that has the last seqNum, but we can only search the TRXN in the RB-Tree with the seqNum.
  * We need to store the last seqNum locally.
  */
 forward_relocation_response_p->trxn    = ue_context_p->pending_s10_response_trxn;
 /** Set the cause. */
 forward_relocation_response_p->cause = RELOCATION_FAILURE;

 /** Perform an implicit detach. */
 ue_context_p->ue_context_rel_cause = S1AP_IMPLICIT_CONTEXT_RELEASE;
 message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
 DevAssert (message_p != NULL);
 itti_nas_implicit_detach_ue_ind_t *nas_implicit_detach_ue_ind_p = &message_p->ittiMsg.nas_implicit_detach_ue_ind;
 memset ((void*)nas_implicit_detach_ue_ind_p, 0, sizeof (itti_nas_implicit_detach_ue_ind_t));
 message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
 itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);

 /** No timers, etc. is needed. */
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_enb_status_transfer(
     const itti_s1ap_status_transfer_t * const s1ap_status_transfer_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;

 OAILOG_FUNC_IN (LOG_MME_APP);
 OAILOG_DEBUG (LOG_MME_APP, "Received S1AP_ENB_STATUS_TRANSFER from S1AP. \n");

 /** Check that the UE does exist. */
 ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, s1ap_status_transfer_pP->mme_ue_s1ap_id);
 if (ue_context_p == NULL) {
   OAILOG_ERROR(LOG_MME_APP, "An UE MME context does not exist for UE with mmeS1apUeId %d. \n", s1ap_status_transfer_pP->mme_ue_s1ap_id);
   MSC_LOG_EVENT (MSC_MMEAPP_MME, "S1AP_ENB_STATUS_TRANSFER. No UE existing mmeS1apUeId %d. \n", s1ap_status_transfer_pP->mme_ue_s1ap_id);
   /**
    * We don't really expect an error at this point. Just ignore the message.
    */
   bdestroy(s1ap_status_transfer_pP->bearerStatusTransferList_buffer);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Check if the destination eNodeB is attached at the same or another MME. */
 if (mme_app_check_ta_local(&ue_context_p->pending_handover_target_tai.plmn, ue_context_p->pending_handover_target_tai.tac)) {
   /** Check if the eNB with the given eNB-ID is served. */
   if(s1ap_is_enb_id_in_list(ue_context_p->pending_handover_enb_id) != NULL){
     OAILOG_DEBUG (LOG_MME_APP, "Target ENB_ID %d of target TAI " TAI_FMT " is served by current MME. \n", ue_context_p->pending_handover_enb_id, ue_context_p->pending_handover_target_tai);
     /**
      * Set the ENB of the pending target-eNB.
      * Even if the HANDOVER_NOTIFY messaged is received simultaneously, the pending enb_ue_s1ap_id field should stay.
      * We do not check that the target-eNB exists. We did not modify any contexts.
      */
     mme_app_send_s1ap_mme_status_transfer(ue_context_p->mme_ue_s1ap_id, ue_context_p->pending_handover_enb_ue_s1ap_id, ue_context_p->e_utran_cgi.cell_identity.enb_id, s1ap_status_transfer_pP->bearerStatusTransferList_buffer);
     OAILOG_FUNC_OUT (LOG_MME_APP);
   }else{
     /** The target eNB-ID is not served by this MME. */
     OAILOG_DEBUG (LOG_MME_APP, "Target ENB_ID %d of target TAI " TAI_FMT " is NOT served by current MME. \n", ue_context_p->pending_handover_enb_id, ue_context_p->pending_handover_target_tai);
     bdestroy(s1ap_status_transfer_pP->bearerStatusTransferList_buffer);
     OAILOG_FUNC_OUT (LOG_MME_APP);
   }
 }
 OAILOG_DEBUG (LOG_MME_APP, "Target ENB_ID %d of target TAI " TAI_FMT " is served by neighboring MME. \n", ue_context_p->pending_handover_enb_id, ue_context_p->pending_handover_target_tai);
 /* UE is DEREGISTERED. Assuming that it came from S10 inter-MME handover. Forwarding the eNB status information to the target-MME via Forward Access Context Notification. */
 message_p = itti_alloc_new_message (TASK_MME_APP, S10_FORWARD_ACCESS_CONTEXT_NOTIFICATION);
 DevAssert (message_p != NULL);
 itti_s10_forward_access_context_notification_t *forward_access_context_notification_p = &message_p->ittiMsg.s10_forward_access_context_notification;
 memset ((void*)forward_access_context_notification_p, 0, sizeof (itti_s10_forward_access_context_notification_t));
 /** Set the target S10 TEID. */
 forward_access_context_notification_p->teid       = ue_context_p->remote_mme_s10_teid; /**< Only a single target-MME TEID can exist at a time. */
 forward_access_context_notification_p->local_teid = ue_context_p->local_mme_s10_teid; /**< Only a single target-MME TEID can exist at a time. */
 forward_access_context_notification_p->peer_ip    = mme_config.nghMme.nghMme[0].ipAddr;
 /** Set the E-UTRAN container. */
 forward_access_context_notification_p->eutran_container.container_type = 3;
 forward_access_context_notification_p->eutran_container.container_value = s1ap_status_transfer_pP->bearerStatusTransferList_buffer;
 if (forward_access_context_notification_p->eutran_container.container_value == NULL){
   OAILOG_ERROR (LOG_MME_APP, " NULL UE transparent container\n" );
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "MME_APP Sending S10 FORWARD_ACCESS_CONTEXT_NOTIFICATION to TARGET-MME with TEID " TEID_FMT,
     forward_access_context_notification_p->teid);
 /**
  * Sending a message to S10.
  * Although eNB-Status message is not mandatory, if it is received, it should be forwarded.
  * That's why, we start a timer for the Forward Access Context Acknowledge.
  */
 itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_s1ap_handover_notify(
     const itti_s1ap_handover_notify_t * const handover_notify_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;
 enb_s1ap_id_key_t                       enb_s1ap_id_key = INVALID_ENB_UE_S1AP_ID_KEY;

 OAILOG_FUNC_IN (LOG_MME_APP);
 OAILOG_DEBUG (LOG_MME_APP, "Received S1AP_HANDOVER_NOTIFY from S1AP. \n");

 /** Check that the UE does exist. */
 ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, handover_notify_pP->mme_ue_s1ap_id);
 if (ue_context_p == NULL) {
   OAILOG_ERROR(LOG_MME_APP, "An UE MME context does not exist for UE with mmeS1apUeId %d. \n", handover_notify_pP->mme_ue_s1ap_id);
   MSC_LOG_EVENT (MSC_MMEAPP_MME, "S1AP_HANDOVER_NOTIFY. No UE existing mmeS1apUeId %d. \n", handover_notify_pP->mme_ue_s1ap_id);
   // todo: appropriate error handling for this case.. removing the UE? continuing with the handover or aborting?
   // todo: removing the S1ap context directly or via NOTIFY?
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /**
  * No need to signal the NAS layer the completion of the handover.
  * The ECGI & TAI will also be sent with TAU if its UPLINK_NAS_TRANSPORT.
  * Here we just update the MME_APP UE_CONTEXT parameters.
  */

 /** Set the values to the old source enb as pending (enb_id, enb_ue_s1ap_id). */
 if(ue_context_p->mm_state == UE_REGISTERED && (ue_context_p->e_utran_cgi.cell_identity.enb_id != 0)){
   ue_context_p->pending_handover_enb_id = ue_context_p->e_utran_cgi.cell_identity.enb_id;
   ue_context_p->pending_handover_enb_ue_s1ap_id = ue_context_p->enb_ue_s1ap_id;
 }
 /**
  * When Handover Notify is received, we update the eNB associations (SCTP, enb_ue_s1ap_id, enb_id,..). The main eNB is the new ENB now.
  * ToDo: If this has an error with 2 eNBs, we need to remove the first eNB first (and send the UE Context Release Command only with MME_UE_S1AP_ID).
  * Update the coll-keys.
  */
 ue_context_p->sctp_assoc_id_key = handover_notify_pP->assoc_id;
 ue_context_p->e_utran_cgi = handover_notify_pP->cgi;
 /** Update the enbUeS1apId. */
 ue_context_p->enb_ue_s1ap_id = handover_notify_pP->enb_ue_s1ap_id;
 // regenerate the enb_s1ap_id_key as enb_ue_s1ap_id is changed.
 MME_APP_ENB_S1AP_ID_KEY(enb_s1ap_id_key, handover_notify_pP->cgi.cell_identity.enb_id, handover_notify_pP->enb_ue_s1ap_id);

 /**
  * Update the coll_keys with the new s1ap parameters.
  */
 mme_ue_context_update_coll_keys (&mme_app_desc.mme_ue_contexts, ue_context_p,
     enb_s1ap_id_key,     /**< New key. */
     ue_context_p->mme_ue_s1ap_id,
     ue_context_p->imsi,
     ue_context_p->mme_s11_teid,
     ue_context_p->local_mme_s10_teid,
     &ue_context_p->guti);

 /**
  * This will overwrite the association towards the old eNB if single MME S1AP handover.
  * The old eNB will be referenced by the enb_ue_s1ap_id.
  */
 notify_s1ap_new_ue_mme_s1ap_id_association (ue_context_p);

 /**
  * Check the UE status:
  *
  * If we are in UE_REGISTERED state (intra-MME HO), start the timer for UE resource deallocation at the source eNB.
  * todo: if TAU is performed, same timer should be checked and not restarted if its already running.
  * The registration to the new MME is performed with the TAU (UE is in UE_UNREGISTERED/EMM_DEREGISTERED states).
  * If the timer runs up and no S6A_CLReq is received from the MME, we assume an intra-MME handover and just remove the resources in the source eNB, else we perform an implicit detach (we don't check the MME UE status).
  * We need to store now the enb_ue_s1ap_id and the enb_id towards the source enb as pending.
  * No timers to stop in this step.
  *
  * If we are in UE_UNREGISTERED state, we assume an inter-MME handover. Again update all enb related information and send an S10_FORWARD_RELOCATION_COMPLETE_NOTIFICATION
  * towards the source MME. No timer will be started on the target-MME side.
  */
 if(ue_context_p->mm_state == UE_REGISTERED){
   OAILOG_DEBUG(LOG_MME_APP, "UE MME context with imsi " IMSI_64_FMT " and mmeS1apUeId " MME_UE_S1AP_ID_FMT " has successfully completed intra-MME handover process after HANDOVER_NOTIFY. \n",
       ue_context_p->imsi, handover_notify_pP->mme_ue_s1ap_id);
   /**
    * Send the MBR to the SAE-GW.
    * Handle the MBResp normally.
    * S1AP F-TEID's received beforehand in HO_REQ_ACK.
    */
   message_p = itti_alloc_new_message (TASK_MME_APP, S11_MODIFY_BEARER_REQUEST);
   AssertFatal (message_p , "itti_alloc_new_message Failed");
   itti_s11_modify_bearer_request_t *s11_modify_bearer_request = &message_p->ittiMsg.s11_modify_bearer_request;
   memset ((void *)s11_modify_bearer_request, 0, sizeof (*s11_modify_bearer_request));
   s11_modify_bearer_request->peer_ip    = mme_config.ipv4.sgw_s11;
   s11_modify_bearer_request->teid       = ue_context_p->sgw_s11_teid;
   s11_modify_bearer_request->local_teid = ue_context_p->mme_s11_teid;
   s11_modify_bearer_request->trxn       = NULL;

   /** Delay Value in integer multiples of 50 millisecs, or zero. */
   s11_modify_bearer_request->delay_dl_packet_notif_req = 0;  // TO DO
   s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id = ue_context_p->pending_s1u_downlink_bearer_ebi;
   memcpy (&s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].s1_eNB_fteid,
       &ue_context_p->pending_s1u_downlink_bearer, sizeof (ue_context_p->pending_s1u_downlink_bearer));
   s11_modify_bearer_request->bearer_contexts_to_be_modified.num_bearer_context = 1;

   s11_modify_bearer_request->bearer_contexts_to_be_removed.num_bearer_context = 0;

   s11_modify_bearer_request->mme_fq_csid.node_id_type = GLOBAL_UNICAST_IPv4; // TO DO
   s11_modify_bearer_request->mme_fq_csid.csid = 0;   // TO DO ...
   memset(&s11_modify_bearer_request->indication_flags, 0, sizeof(s11_modify_bearer_request->indication_flags));   // TO DO
   s11_modify_bearer_request->rat_type = RAT_EUTRAN;
   /*
    * S11 stack specific parameter. Not used in standalone epc mode
    */
   MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S11_MME ,
       NULL, 0, "0 S11_MODIFY_BEARER_REQUEST teid %u ebi %u", s11_modify_bearer_request->teid,
       s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id);
   itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
   /**
    * Start timer to wait the handover/TAU procedure to complete.
    * This will only be started in the source MME, not in the target MME.
    */
   if (timer_setup (mme_config.mme_mobility_completion_timer, 0,
                 TASK_MME_APP, INSTANCE_DEFAULT, TIMER_ONE_SHOT, (void *) &(ue_context_p->mme_ue_s1ap_id), &(ue_context_p->mme_mobility_completion_timer.id)) < 0) {
     OAILOG_ERROR (LOG_MME_APP, "Failed to start mme_mobility_completion timer for UE id  %d for duration %d \n", ue_context_p->mme_ue_s1ap_id, mme_config.mme_mobility_completion_timer);
     ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
   } else {
     OAILOG_DEBUG (LOG_MME_APP, "MME APP : Completed Handover Procedure at (source) MME side after handling S1AP_HANDOVER_NOTIFY. "
         "Activated the MME mobilty timer UE id  %d. Removing source eNB resources after timer.. Timer Id %u. Timer duration %d \n",
         ue_context_p->mme_ue_s1ap_id, ue_context_p->mme_mobility_completion_timer.id, mme_config.mme_mobility_completion_timer);
   }
 }else{
   /**
    * UE came from S10 inter-MME handover. Not clear the pending_handover state yet.
    * Sending Forward Relocation Complete Notification and waiting for acknowledgment.
    */
   message_p = itti_alloc_new_message (TASK_MME_APP, S10_FORWARD_RELOCATION_COMPLETE_NOTIFICATION);
   DevAssert (message_p != NULL);
   itti_s10_forward_relocation_complete_notification_t *forward_relocation_complete_notification_p = &message_p->ittiMsg.s10_forward_relocation_complete_notification;
   memset ((void*)forward_relocation_complete_notification_p, 0, sizeof (itti_s10_forward_relocation_complete_notification_t));
   /** Set the destination TEID. */
   forward_relocation_complete_notification_p->teid = ue_context_p->remote_mme_s10_teid;       /**< Target S10-MME TEID. todo: what if multiple? */
   /** Set the local TEID. */
   forward_relocation_complete_notification_p->local_teid = ue_context_p->local_mme_s10_teid;        /**< Local S10-MME TEID. */
   forward_relocation_complete_notification_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr; /**< Set the target TEID. */
   OAILOG_INFO(LOG_MME_APP, "Sending FW_RELOC_COMPLETE_NOTIF TO %X with remote S10-TEID " TEID_FMT ". \n.", forward_relocation_complete_notification_p->peer_ip, forward_relocation_complete_notification_p->teid);

   // todo: remove this and set at correct position!
   mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts, ue_context_p, ECM_CONNECTED);

   /**
    * Sending a message to S10. Not changing any context information!
    * This message actually implies that the handover is finished. Resetting the flags and statuses here of after Forward Relocation Complete AcknowledgE?! (MBR)
    */
   itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
 }
 OAILOG_DEBUG(LOG_MME_APP, "UE MME context with imsi " IMSI_64_FMT " and mmeUeS1apId " MME_UE_S1AP_ID_FMT " has successfully handled HANDOVER_NOTIFY. \n",
     ue_context_p->imsi, handover_notify_pP->mme_ue_s1ap_id);
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_forward_relocation_complete_notification(
     const itti_s10_forward_relocation_complete_notification_t* const forward_relocation_complete_notification_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;

 OAILOG_FUNC_IN (LOG_MME_APP);
 OAILOG_DEBUG (LOG_MME_APP, "Received S10_FORWARD_RELOCATION_COMPLETE_NOTIFICATION from S10. \n");

 /** Check that the UE does exist. */
 ue_context_p = mme_ue_context_exists_s10_teid (&mme_app_desc.mme_ue_contexts, forward_relocation_complete_notification_pP->teid); /**< Get the UE context from the local TEID. */
 if (ue_context_p == NULL) {
   MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "0 FORWARD_RELOCATION_COMPLETE_NOTIFICATION local S10 teid " TEID_FMT,
       forward_relocation_complete_notification_pP->teid);
   OAILOG_ERROR (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", forward_relocation_complete_notification_pP->teid);
   OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
 }
 MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "0 FORWARD_RELOCATION_COMPLETE_NOTIFICATION local S10 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
     forward_relocation_complete_notification_pP->teid, ue_context_p->imsi);

 /** Check that there is a pending handover process. */
 if(ue_context_p->mm_state != UE_REGISTERED){
   /** Deal with the error case. */
   OAILOG_ERROR(LOG_MME_APP, "UE MME context with IMSI " IMSI_64_FMT " and mmeS1apUeId: " MME_UE_S1AP_ID_FMT " is not in UE_REGISTERED state, instead %d, when S10_FORWARD_RELOCATION_COMPLETE_NOTIFICATION is received. "
       "Ignoring the error, responding with ACK and still starting the timer to remove the UE context triggered by HSS. \n",
       ue_context_p->imsi, ue_context_p->mme_ue_s1ap_id, ue_context_p->mm_state);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }

 /** Send S10 Forward Relocation Complete Notification. */
 /**< Will stop all existing NAS timers.. todo: Any other timers than NAS timers? What about the UE transactions? */
 message_p = itti_alloc_new_message (TASK_MME_APP, S10_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE);
 DevAssert (message_p != NULL);
 itti_s10_forward_relocation_complete_acknowledge_t *forward_relocation_complete_acknowledge_p = &message_p->ittiMsg.s10_forward_relocation_complete_acknowledge;
 memset ((void*)forward_relocation_complete_acknowledge_p, 0, sizeof (itti_s10_forward_relocation_complete_acknowledge_t));
 /** Set the destination TEID. */
 forward_relocation_complete_acknowledge_p->teid       = ue_context_p->remote_mme_s10_teid;      /**< Target S10-MME TEID. */
 /** Set the local TEID. */
 forward_relocation_complete_acknowledge_p->local_teid = ue_context_p->local_mme_s10_teid;      /**< Local S10-MME TEID. */
 /** Set the cause. */
 forward_relocation_complete_acknowledge_p->cause      = REQUEST_ACCEPTED;                       /**< Check the cause.. */
 /** Set the peer IP. */
 forward_relocation_complete_acknowledge_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr; /**< Set the target TEID. */
 /** Set the transaction. */
 forward_relocation_complete_acknowledge_p->trxn = forward_relocation_complete_notification_pP->trxn; /**< Set the target TEID. */
 itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
 /** ECM is in connected state.. UE will be detached implicitly. */
 ue_context_p->ue_context_rel_cause = S1AP_SUCCESSFUL_HANDOVER; /**< How mapped to correct radio-Network cause ?! */

 /**
  * Start timer to wait the handover/TAU procedure to complete.
  * A Clear_Location_Request message received from the HSS will cause the resources to be removed.
  * If it was not a handover but a context request/response (TAU), the MME_MOBILITY_COMPLETION timer will be started here, else @ FW-RELOC-COMPLETE @ Handover.
  * Resources will not be removed if that is not received (todo: may it not be received or must it always come
  * --> TS.23.401 defines for SGSN "remove after CLReq" explicitly).
  */
 if (timer_setup (mme_config.mme_mobility_completion_timer, 0,
               TASK_MME_APP, INSTANCE_DEFAULT, TIMER_ONE_SHOT, (void *) &(ue_context_p->mme_ue_s1ap_id), &(ue_context_p->mme_mobility_completion_timer.id)) < 0) {
   OAILOG_ERROR (LOG_MME_APP, "Failed to start initial context setup response timer for UE id  %d for duration %d \n", ue_context_p->mme_ue_s1ap_id, mme_config.mme_mobility_completion_timer);
   ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
 } else {
   OAILOG_DEBUG (LOG_MME_APP, "MME APP : Completed Handover Procedure at source MME side after handling S10_CONTEXT_REQUEST. "
       "Activated the MME mobilty timer UE id  %d. Waiting for CANCEL_LOCATION_REQUEST from HSS.. Timer Id %u. Timer duration %d \n",
       ue_context_p->mme_ue_s1ap_id, ue_context_p->mme_mobility_completion_timer.id, mme_config.mme_mobility_completion_timer);
   /** Upon expiration, invalidate the timer.. no flag needed. */
 }
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_forward_relocation_complete_acknowledge(
     const itti_s10_forward_relocation_complete_acknowledge_t * const forward_relocation_complete_acknowledgement_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;

 OAILOG_FUNC_IN (LOG_MME_APP);
 OAILOG_DEBUG (LOG_MME_APP, "Received S10_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGEMENT from S10. \n");

 /** Check that the UE does exist. */
 ue_context_p = mme_ue_context_exists_s10_teid(&mme_app_desc.mme_ue_contexts, forward_relocation_complete_acknowledgement_pP->teid);
 if (ue_context_p == NULL) {
   OAILOG_ERROR(LOG_MME_APP, "An UE MME context does not exist for UE with s10 teid %d. \n", forward_relocation_complete_acknowledgement_pP->teid);
   MSC_LOG_EVENT (MSC_MMEAPP_MME, "S10_FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGEMENT. No UE existing teid %d. \n", forward_relocation_complete_acknowledgement_pP->teid);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }

 /** Stop the MME S10 Handover Completion timer. */
 if (ue_context_p->mme_s10_handover_completion_timer.id != MME_APP_TIMER_INACTIVE_ID) {
   if (timer_remove(ue_context_p->mme_s10_handover_completion_timer.id)) {
     OAILOG_ERROR (LOG_MME_APP, "Failed to stop MME S10 Handover Completion timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
   }
   ue_context_p->mme_s10_handover_completion_timer.id = MME_APP_TIMER_INACTIVE_ID;
 }

 /**
  * S1AP inter-MME handover is complete now. Modify the bearers with the new downlink tunnel IDs of the MME.
  */
 message_p = itti_alloc_new_message (TASK_MME_APP, S11_MODIFY_BEARER_REQUEST);
 AssertFatal (message_p , "itti_alloc_new_message Failed");
 itti_s11_modify_bearer_request_t *s11_modify_bearer_request = &message_p->ittiMsg.s11_modify_bearer_request;
 memset ((void *)s11_modify_bearer_request, 0, sizeof (*s11_modify_bearer_request));
 s11_modify_bearer_request->peer_ip    = mme_config.ipv4.sgw_s11;
 s11_modify_bearer_request->teid       = ue_context_p->sgw_s11_teid;
 s11_modify_bearer_request->local_teid = ue_context_p->mme_s11_teid;
 s11_modify_bearer_request->trxn       = NULL;

 /** Delay Value in integer multiples of 50 millisecs, or zero. */
 s11_modify_bearer_request->delay_dl_packet_notif_req = 0;  // TO DO
 s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id = ue_context_p->pending_s1u_downlink_bearer_ebi;
 memcpy (&s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].s1_eNB_fteid,
     &ue_context_p->pending_s1u_downlink_bearer, sizeof (ue_context_p->pending_s1u_downlink_bearer));
 s11_modify_bearer_request->bearer_contexts_to_be_modified.num_bearer_context = 1;

 s11_modify_bearer_request->bearer_contexts_to_be_removed.num_bearer_context = 0;

 s11_modify_bearer_request->mme_fq_csid.node_id_type = GLOBAL_UNICAST_IPv4; // TO DO
 s11_modify_bearer_request->mme_fq_csid.csid = 0;   // TO DO ...
 memset(&s11_modify_bearer_request->indication_flags, 0, sizeof(s11_modify_bearer_request->indication_flags));   // TO DO
 s11_modify_bearer_request->rat_type = RAT_EUTRAN;

 /**
  * S11 stack specific parameter. Not used in standalone epc mode
  * todo: what is this? MBR trxn not set? should also be set to NULL for S10 messages?! */
 s11_modify_bearer_request->trxn = NULL;
 MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S11_MME ,
     NULL, 0, "0 S11_MODIFY_BEARER_REQUEST after FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE teid %u ebi %u", s11_modify_bearer_request->teid,
     s11_modify_bearer_request->bearer_contexts_to_be_modified.bearer_contexts[0].eps_bearer_id);
 itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
//  DevAssert(mme_app_complete_inter_mme_handover(ue_context_p, REQUEST_ACCEPTED) == RETURNok); /**< todo: later make this un-crash.*/

 /** S1AP inter-MME handover is complete. */
 OAILOG_INFO(LOG_MME_APP, "UE_Context with IMSI " IMSI_64_FMT " and mmeUeS1apId: " MME_UE_S1AP_ID_FMT " successfully completed handover procedure! \n",
     ue_context_p->imsi, ue_context_p->mme_ue_s1ap_id);
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_release_access_bearers_resp (
  const itti_s11_release_access_bearers_response_t * const rel_access_bearers_rsp_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  ue_context_p = mme_ue_context_exists_s11_teid (&mme_app_desc.mme_ue_contexts, rel_access_bearers_rsp_pP->teid);

  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 RELEASE_ACCESS_BEARERS_RESPONSE local S11 teid " TEID_FMT " ",
    		rel_access_bearers_rsp_pP->teid);
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %" PRIX32 "\n", rel_access_bearers_rsp_pP->teid);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 RELEASE_ACCESS_BEARERS_RESPONSE local S11 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
    rel_access_bearers_rsp_pP->teid, ue_context_p->imsi);
  /*
   * Updating statistics
   */
  update_mme_app_stats_s1u_bearer_sub();

  // Send UE Context Release Command
  mme_app_itti_ue_context_release(ue_context_p, ue_context_p->ue_context_rel_cause);
  if (ue_context_p->ue_context_rel_cause == S1AP_SCTP_SHUTDOWN_OR_RESET) {
    // Just cleanup the MME APP state associated with s1.
    mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts, ue_context_p, ECM_IDLE);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_mobile_reachability_timer_expiry (struct ue_context_s *ue_context_p) 
{
  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ue_context_p != NULL);
  ue_context_p->mobile_reachability_timer.id = MME_APP_TIMER_INACTIVE_ID;
  OAILOG_INFO (LOG_MME_APP, "Expired- Mobile Reachability Timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  // Start Implicit Detach timer 
  if (timer_setup (ue_context_p->implicit_detach_timer.sec, 0, 
                TASK_MME_APP, INSTANCE_DEFAULT, TIMER_ONE_SHOT, (void *)&(ue_context_p->mme_ue_s1ap_id), &(ue_context_p->implicit_detach_timer.id)) < 0) { 
    OAILOG_ERROR (LOG_MME_APP, "Failed to start Implicit Detach timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    ue_context_p->implicit_detach_timer.id = MME_APP_TIMER_INACTIVE_ID;
  } else {
    OAILOG_DEBUG (LOG_MME_APP, "Started Implicit Detach timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_implicit_detach_timer_expiry (struct ue_context_s *ue_context_p) 
{
  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ue_context_p != NULL);
  MessageDef                             *message_p = NULL;
  OAILOG_INFO (LOG_MME_APP, "Expired- Implicit Detach timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  ue_context_p->implicit_detach_timer.id = MME_APP_TIMER_INACTIVE_ID;
  
  // Initiate Implicit Detach for the UE
  message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
  DevAssert (message_p != NULL);
  message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_mme_mobility_completion_timer_expiry (struct ue_context_s *ue_context_p)
{
  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ue_context_p != NULL);
  MessageDef                             *message_p = NULL;
  OAILOG_INFO (LOG_MME_APP, "Expired- MME Mobility Completion timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  ue_context_p->mme_mobility_completion_timer.id = MME_APP_TIMER_INACTIVE_ID;
  ue_context_p->ue_context_rel_cause = S1AP_NAS_DETACH;

  /** Check if the CLR flag has been set. */
  if(ue_context_p->pending_clear_location_request){
    OAILOG_INFO (LOG_MME_APP, "Implicitly detaching the UE due CLR flag @ completion of MME_MOBILITY timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  }else{
    OAILOG_INFO (LOG_MME_APP, "Perform S1AP UE context release, since no CLR flag @ completion of MME_MOBILITY timer for UE id  %d (performing UE context release). \n", ue_context_p->mme_ue_s1ap_id);
    // todo: check that the UE is registered!
    // todo: perform UE context release towards the source enb!

  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_mme_s10_handover_completion_timer_expiry (struct ue_context_s *ue_context_p)
{
  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ue_context_p != NULL);
  MessageDef                             *message_p = NULL;
  OAILOG_INFO (LOG_MME_APP, "Expired- MME S10 Handover Completion timer for UE " MME_UE_S1AP_ID_FMT " run out. Implicit detach (no matter what the status is). \n", ue_context_p->mme_ue_s1ap_id);
  ue_context_p->mme_mobility_completion_timer.id = MME_APP_TIMER_INACTIVE_ID;
  ue_context_p->ue_context_rel_cause = S1AP_NAS_DETACH;
  /** Check if the CLR flag has been set. */
  message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
  DevAssert (message_p != NULL);
  message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_mme_paging_timeout_timer_expiry (struct ue_context_s *ue_context_p)
{
  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ue_context_p != NULL);
  MessageDef                             *message_p = NULL;
  OAILOG_INFO (LOG_MME_APP, "Expired- MME Paging Timeout timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  ue_context_p->mme_paging_timeout_timer.id = MME_APP_TIMER_INACTIVE_ID;
  ue_context_p->ue_context_rel_cause = S1AP_NAS_DETACH;

  if(ue_context_p->ecm_state != ECM_CONNECTED){
    OAILOG_INFO (LOG_MME_APP, "Implicitly detaching the UE since UE was not in ECM_CONNECTED state after paging timeout expired for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  }else{
    OAILOG_INFO (LOG_MME_APP, "Leaving UE %d with imsi " IMSI_64_FMT "as registered since its in ECM_CONNECTED state before paging timeout expired. \n", ue_context_p->mme_ue_s1ap_id, ue_context_p->imsi);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_initial_context_setup_rsp_timer_expiry (struct ue_context_s *ue_context_p)
{
  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ue_context_p != NULL);
  MessageDef                             *message_p = NULL;
  OAILOG_INFO (LOG_MME_APP, "Expired- Initial context setup rsp timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
  /* *********Abort the ongoing procedure*********
   * Check if UE is registered already that implies service request procedure is active. If so then release the S1AP
   * context and move the UE back to idle mode. Otherwise if UE is not yet registered that implies attach procedure is
   * active. If so,then abort the attach procedure and release the UE context. 
   */
  ue_context_p->ue_context_rel_cause = S1AP_INITIAL_CONTEXT_SETUP_FAILED;
  if (ue_context_p->mm_state == UE_UNREGISTERED) {
    // Initiate Implicit Detach for the UE
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  } else {
    // Release S1-U bearer and move the UE to idle mode 
    mme_app_send_s11_release_access_bearers_req(ue_context_p);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_initial_context_setup_failure (
  const itti_mme_app_initial_context_setup_failure_t * const initial_ctxt_setup_failure_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  OAILOG_DEBUG (LOG_MME_APP, "Received MME_APP_INITIAL_CONTEXT_SETUP_FAILURE from S1AP\n");
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, initial_ctxt_setup_failure_pP->mme_ue_s1ap_id);

  if (ue_context_p == NULL) {
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this mme_ue_s1ap_id in list of UE: %d \n", initial_ctxt_setup_failure_pP->mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  // Stop Initial context setup process guard timer,if running 
  if (ue_context_p->initial_context_setup_rsp_timer.id != MME_APP_TIMER_INACTIVE_ID) {
    if (timer_remove(ue_context_p->initial_context_setup_rsp_timer.id)) {
      OAILOG_ERROR (LOG_MME_APP, "Failed to stop Initial Context Setup Rsp timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    } 
    ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
  }
  /* *********Abort the ongoing procedure*********
   * Check if UE is registered already that implies service request procedure is active. If so then release the S1AP
   * context and move the UE back to idle mode. Otherwise if UE is not yet registered that implies attach procedure is
   * active. If so,then abort the attach procedure and release the UE context. 
   */
  ue_context_p->ue_context_rel_cause = S1AP_INITIAL_CONTEXT_SETUP_FAILED;
  if (ue_context_p->mm_state == UE_UNREGISTERED) {
    // Initiate Implicit Detach for the UE
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  } else {
    // Release S1-U bearer and move the UE to idle mode 
    mme_app_send_s11_release_access_bearers_req(ue_context_p);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
static bool mme_app_construct_guti(const plmn_t * const plmn_p, const as_stmsi_t * const s_tmsi_p,  guti_t * const guti_p)
{
  /*
   * This is a helper function to construct GUTI from S-TMSI. It uses PLMN id and MME Group Id of the serving MME for
   * this purpose.
   *
   */

  bool                                    is_guti_valid = false; // Set to true if serving MME is found and GUTI is constructed
  uint8_t                                 num_mme       = 0;     // Number of configured MME in the MME pool
  guti_p->m_tmsi = s_tmsi_p->m_tmsi;
  guti_p->gummei.mme_code = s_tmsi_p->mme_code;
  // Create GUTI by using PLMN Id and MME-Group Id of serving MME
  OAILOG_DEBUG (LOG_MME_APP,
                "Construct GUTI using S-TMSI received form UE and MME Group Id and PLMN id from MME Conf: %u, %u \n",
                s_tmsi_p->m_tmsi, s_tmsi_p->mme_code);
  mme_config_read_lock (&mme_config);
  /*
   * Check number of MMEs in the pool.
   * At present it is assumed that one MME is supported in MME pool but in case there are more
   * than one MME configured then search the serving MME using MME code.
   * Assumption is that within one PLMN only one pool of MME will be configured
   */
  if (mme_config.gummei.nb > 1)
  {
    OAILOG_DEBUG (LOG_MME_APP, "More than one MMEs are configured. \n");
  }
  for (num_mme = 0; num_mme < mme_config.gummei.nb; num_mme++)
  {
    /*Verify that the MME code within S-TMSI is same as what is configured in MME conf*/
    if ((plmn_p->mcc_digit2 == mme_config.gummei.gummei[num_mme].plmn.mcc_digit2) &&
        (plmn_p->mcc_digit1 == mme_config.gummei.gummei[num_mme].plmn.mcc_digit1) &&
        (plmn_p->mnc_digit3 == mme_config.gummei.gummei[num_mme].plmn.mnc_digit3) &&
        (plmn_p->mcc_digit3 == mme_config.gummei.gummei[num_mme].plmn.mcc_digit3) &&
        (plmn_p->mnc_digit2 == mme_config.gummei.gummei[num_mme].plmn.mnc_digit2) &&
        (plmn_p->mnc_digit1 == mme_config.gummei.gummei[num_mme].plmn.mnc_digit1) &&
        (guti_p->gummei.mme_code == mme_config.gummei.gummei[num_mme].mme_code))
    {
      break;
    }
  }
  if (num_mme >= mme_config.gummei.nb)
  {
    OAILOG_DEBUG (LOG_MME_APP, "No MME serves this UE");
  }
  else
  {
    guti_p->gummei.plmn = mme_config.gummei.gummei[num_mme].plmn;
    guti_p->gummei.mme_gid = mme_config.gummei.gummei[num_mme].mme_gid;
    is_guti_valid = true;
  }
  mme_config_unlock (&mme_config);
  return is_guti_valid;
}

//------------------------------------------------------------------------------
static void notify_s1ap_new_ue_mme_s1ap_id_association (struct ue_context_s *ue_context_p)
{
  MessageDef                             *message_p = NULL;
  itti_mme_app_s1ap_mme_ue_id_notification_t *notification_p = NULL;
  
  OAILOG_FUNC_IN (LOG_MME_APP);
  if (ue_context_p == NULL) {
    OAILOG_ERROR (LOG_MME_APP, " NULL UE context ptr\n" );
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  message_p = itti_alloc_new_message (TASK_MME_APP, MME_APP_S1AP_MME_UE_ID_NOTIFICATION);
  notification_p = &message_p->ittiMsg.mme_app_s1ap_mme_ue_id_notification;
  memset (notification_p, 0, sizeof (itti_mme_app_s1ap_mme_ue_id_notification_t)); 
  notification_p->enb_ue_s1ap_id = ue_context_p->enb_ue_s1ap_id; 
  notification_p->mme_ue_s1ap_id = ue_context_p->mme_ue_s1ap_id;
  notification_p->sctp_assoc_id  = ue_context_p->sctp_assoc_id_key;

  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
  OAILOG_DEBUG (LOG_MME_APP, " Sent MME_APP_S1AP_MME_UE_ID_NOTIFICATION to S1AP for UE Id %u\n", notification_p->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

