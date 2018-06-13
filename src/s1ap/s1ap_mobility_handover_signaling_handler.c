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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include "bstrlib.h"

#include "hashtable.h"
#include "log.h"
#include "msc.h"
#include "3gpp_requirements_36.413.h"
#include "assertions.h"
#include "conversions.h"
#include "intertask_interface.h"
#include "timer.h"
#include "dynamic_memory_check.h"
#include "mme_config.h"
#include "s1ap_common.h"
#include "s1ap_ies_defs.h"
#include "s1ap_mme_encoder.h"
#include "s1ap_mme_nas_procedures.h"
#include "s1ap_mme_itti_messaging.h"
#include "s1ap_mme.h"
#include "s1ap_mme_ta.h"
#include "s1ap_mme_handlers.h"
#include "s1ap_handover_signaling_handler.h"
////////////////////////////////////////////////////////////////////////////////
//************************ Handover signalling *******************************//
////////////////////////////////////////////////////////////////////////////////

//------------------------------------------------------------------------------
int
s1ap_mme_handle_path_switch_request (
    __attribute__((unused)) const sctp_assoc_id_t assoc_id,
    __attribute__((unused)) const sctp_stream_id_t stream,
    struct s1ap_message_s *message)
{
  S1ap_PathSwitchRequestIEs_t            *pathSwitchRequest_p = NULL;
  S1ap_E_RABToBeSwitchedDLItemIEs_t      *eRABToBeSwitchedDlItemIEs_p = NULL;

  ue_description_t                       *ue_ref_p = NULL;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;
  mme_ue_s1ap_id_t                        mme_ue_s1ap_id = 0;
  MessageDef                             *message_p = NULL;
  int                                     rc = RETURNok;

  //  todo: The MME shall verify that the UE security
  //  capabilities received from the eNB are the same as the UE security capabilities that the MME has stored. If
  //  there is a mismatch, the MME may log the event and may take additional measures, such as raising an alarm.

  //Request IEs:
  //S1ap-ENB-UE-S1AP-ID
  //S1ap-E-RABToBeSwitchedDLList
  //S1ap-MME-UE-S1AP-ID
  //S1ap-EUTRAN-CGI
  //S1ap-TAI
  //S1ap-UESecurityCapabilities

  //Acknowledge IEs:
  //S1ap-MME-UE-S1AP-ID
  //S1ap-ENB-UE-S1AP-ID
  //S1ap-E-RABToBeSwitchedULList

  OAILOG_FUNC_IN (LOG_S1AP);
  pathSwitchRequest_p = &message->msg.s1ap_PathSwitchRequestIEs;
  // eNB UE S1AP ID is limited to 24 bits
  enb_ue_s1ap_id = (enb_ue_s1ap_id_t) (pathSwitchRequest_p->eNB_UE_S1AP_ID & ENB_UE_S1AP_ID_MASK);
  mme_ue_s1ap_id = pathSwitchRequest_p->sourceMME_UE_S1AP_ID;
  OAILOG_DEBUG (LOG_S1AP, "Path Switch Request message received from eNB UE S1AP ID: " ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);

  if ((ue_ref_p = s1ap_is_ue_mme_id_in_list (mme_ue_s1ap_id)) == NULL) {
    /*
     * The MME UE S1AP ID provided by eNB doesn't point to any valid UE.
     * * * * MME replies with a PATH SWITCH REQUEST FAILURE message and start operation
     * * * * as described in TS 36.413 [11].
     * * * * TODO
     */
    OAILOG_DEBUG (LOG_S1AP, "MME UE S1AP ID provided by eNB doesn't point to any valid UE: " MME_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
    s1ap_send_path_switch_request_failure(assoc_id, stream, mme_ue_s1ap_id, enb_ue_s1ap_id);
  } else {
    /** The enb_ue_s1ap_id will change! **/

    OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ OLD UE DESCRIPTION AFTER PSR %x \n", ue_ref_p);
    OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ OLD UE DESCRIPTION AFTER PSR %p \n", ue_ref_p);
    OAILOG_DEBUG(LOG_S1AP, "SET ENB_UE_S1AP_ID (0)   @ OLD UE DESCRIPTION AFTER PSR %d \n", ue_ref_p->enb_ue_s1ap_id);


    if (pathSwitchRequest_p->e_RABToBeSwitchedDLList.s1ap_E_RABToBeSwitchedDLItem.count != 1) {
      OAILOG_DEBUG (LOG_S1AP, "E-RAB switch has failed\n");
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }

    /** Try to remove the old s1ap UE context --> ue_reference. */
    OAILOG_DEBUG (LOG_S1AP, "Removed old ue_reference before handover for MME UE S1AP ID " MME_UE_S1AP_ID_FMT "\n", (uint32_t) ue_ref_p->mme_ue_s1ap_id);
    s1ap_remove_ue (ue_ref_p);

    /*
       * This UE eNB Id has currently no known s1 association.
       * * * * Create new UE context by associating new mme_ue_s1ap_id.
       * * * * Update eNB UE list.
       * * * * Forward message to NAS.
       */
    if ((ue_ref_p = s1ap_new_ue (assoc_id, enb_ue_s1ap_id)) == NULL) {
        // If we failed to allocate a new UE return -1
        OAILOG_ERROR (LOG_S1AP, "S1AP:Initial UE Message- Failed to allocate S1AP UE Context, eNBUeS1APId:" ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
        OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }

    // todo: starting a timer?
//    ue_ref_p->s1_ue_state     = S1AP_UE_HANDOVER_X2;

    ue_ref_p->enb_ue_s1ap_id = enb_ue_s1ap_id;
    // Will be allocated by NAS
    ue_ref_p->mme_ue_s1ap_id = mme_ue_s1ap_id;

    OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ NEW UE DESCRIPTION AFTER PSR %x \n", ue_ref_p);
    OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ NEW UE DESCRIPTION AFTER PSR %p \n", ue_ref_p);
    OAILOG_DEBUG(LOG_S1AP, "SET ENB_UE_S1AP_ID (0)   @ NEW UE DESCRIPTION AFTER PSR %d \n", ue_ref_p->enb_ue_s1ap_id);

    ue_ref_p->s1ap_ue_context_rel_timer.id  = S1AP_TIMER_INACTIVE_ID;
    ue_ref_p->s1ap_ue_context_rel_timer.sec = S1AP_UE_CONTEXT_REL_COMP_TIMER;

    ue_ref_p->s1ap_handover_completion_timer.id  = S1AP_TIMER_INACTIVE_ID;
    ue_ref_p->s1ap_handover_completion_timer.sec = S1AP_HANDOVER_COMPLETION_TIMER;

    // On which stream we received the message
    ue_ref_p->sctp_stream_recv = stream;
    ue_ref_p->sctp_stream_send = ue_ref_p->enb->next_sctp_stream;

    /*
     * Increment the sctp stream for the eNB association.
     * If the next sctp stream is >= instream negociated between eNB and MME, wrap to first stream.
     * TODO: search for the first available stream instead.
     */

    /*
     * TODO task#15456359.
     * Below logic seems to be incorrect , revisit it.
     */
    ue_ref_p->enb->next_sctp_stream += 1;
    if (ue_ref_p->enb->next_sctp_stream >= ue_ref_p->enb->instreams) {
      ue_ref_p->enb->next_sctp_stream = 1;
    }


      /** Set the new association and the new stream. */
      ue_ref_p->enb->sctp_assoc_id = assoc_id;
      ue_ref_p->enb->next_sctp_stream = stream;

      // set the new enb id
      ue_ref_p->enb_ue_s1ap_id = enb_ue_s1ap_id;




//      message_p = itti_alloc_new_message (TASK_S1AP, MME_APP_INITIAL_CONTEXT_SETUP_RSP);
      message_p = itti_alloc_new_message (TASK_S1AP, S1AP_PATH_SWITCH_REQUEST);
      AssertFatal (message_p != NULL, "itti_alloc_new_message Failed");
      memset ((void *)&message_p->ittiMsg.s1ap_path_switch_request, 0, sizeof (itti_s1ap_path_switch_request_t));
      /*
       * Bad, very bad cast...
       */
      eRABToBeSwitchedDlItemIEs_p = (S1ap_E_RABToBeSwitchedDLItemIEs_t *)
        pathSwitchRequest_p->e_RABToBeSwitchedDLList.s1ap_E_RABToBeSwitchedDLItem.array[0];
      S1AP_PATH_SWITCH_REQUEST (message_p).mme_ue_s1ap_id = ue_ref_p->mme_ue_s1ap_id;
      S1AP_PATH_SWITCH_REQUEST (message_p).enb_ue_s1ap_id = ue_ref_p->enb_ue_s1ap_id;
      S1AP_PATH_SWITCH_REQUEST (message_p).enb_ue_s1ap_id = ue_ref_p->enb_ue_s1ap_id;
      S1AP_PATH_SWITCH_REQUEST (message_p).sctp_assoc_id  = assoc_id;
      S1AP_PATH_SWITCH_REQUEST (message_p).sctp_stream    = stream;
      S1AP_PATH_SWITCH_REQUEST (message_p).enb_id         = ue_ref_p->enb->enb_id;
      S1AP_PATH_SWITCH_REQUEST (message_p).eps_bearer_id = eRABToBeSwitchedDlItemIEs_p->e_RABToBeSwitchedDLItem.e_RAB_ID;
      S1AP_PATH_SWITCH_REQUEST (message_p).bearer_s1u_enb_fteid.ipv4 = 1;  // TO DO
      S1AP_PATH_SWITCH_REQUEST (message_p).bearer_s1u_enb_fteid.ipv6 = 0;  // TO DO
      S1AP_PATH_SWITCH_REQUEST (message_p).bearer_s1u_enb_fteid.interface_type = S1_U_ENODEB_GTP_U;
      S1AP_PATH_SWITCH_REQUEST (message_p).bearer_s1u_enb_fteid.teid = htonl ( *((uint32_t *) eRABToBeSwitchedDlItemIEs_p->e_RABToBeSwitchedDLItem.gTP_TEID.buf));
      memcpy (&S1AP_PATH_SWITCH_REQUEST (message_p).bearer_s1u_enb_fteid.ipv4_address, eRABToBeSwitchedDlItemIEs_p->e_RABToBeSwitchedDLItem.transportLayerAddress.buf, 4);
      MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                          MSC_MMEAPP_MME,
                          NULL, 0,
                          "0 S1AP_PATH_SWITCH_REQUEST mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " ebi %u s1u enb teid %u",
                          S1AP_PATH_SWITCH_REQUEST (message_p).mme_ue_s1ap_id,
                          S1AP_PATH_SWITCH_REQUEST (message_p).eps_bearer_id,
                          S1AP_PATH_SWITCH_REQUEST (message_p).bearer_s1u_enb_fteid.teid);
      rc =  itti_send_msg_to_task (TASK_MME_APP, INSTANCE_DEFAULT, message_p);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
  }
}

//------------------------------------------------------------------------------
int
s1ap_send_path_switch_request_failure (
    const sctp_assoc_id_t assoc_id,
    const sctp_stream_id_t stream,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id)
{
  int                                     enc_rval = 0;
  S1ap_PathSwitchRequestFailureIEs_t     *pathSwitchRequestFailure_p = NULL;
  s1ap_message                            message = { 0 };
  uint8_t                                *buffer = NULL;
  uint32_t                                length = 0;
  int                                     rc = RETURNok;

  /*
   * Mandatory IEs:
   * S1ap-MME-UE-S1AP-ID
   * S1ap-ENB-UE-S1AP-ID
   * S1ap-Cause
   */

  OAILOG_FUNC_IN (LOG_S1AP);

  pathSwitchRequestFailure_p = &message.msg.s1ap_PathSwitchRequestFailureIEs;
  s1ap_mme_set_cause(&pathSwitchRequestFailure_p->cause, S1ap_Cause_PR_misc, 4);
  pathSwitchRequestFailure_p->eNB_UE_S1AP_ID = enb_ue_s1ap_id;
  pathSwitchRequestFailure_p->mme_ue_s1ap_id = mme_ue_s1ap_id;

  message.procedureCode = S1ap_ProcedureCode_id_PathSwitchRequest;
  message.direction = S1AP_PDU_PR_unsuccessfulOutcome;
  enc_rval = s1ap_mme_encode_pdu (&message, &buffer, &length);

  // Failed to encode
  if (enc_rval < 0) {
    OAILOG_ERROR (LOG_S1AP, "Error encoding path switch request failure.\n");
//    free_s1ap_pathswitchrequestfailure(pathSwitchRequestFailure_p);
  }

  bstring b = blk2bstr(buffer, length);
  free(buffer);
  rc = s1ap_mme_itti_send_sctp_request (&b, assoc_id, 0, INVALID_MME_UE_S1AP_ID);

//  free_s1ap_pathswitchrequestfailure(pathSwitchRequestFailure_p);

  OAILOG_FUNC_RETURN (LOG_S1AP, rc);
}

//------------------------------------------------------------------------------
void
s1ap_handle_path_switch_req_ack(
  const itti_s1ap_path_switch_request_ack_t * const path_switch_req_ack_pP)
{
  /*
   * We received modify bearer response from S-GW on S11 interface abstraction.
   * It could be a handover case where we need to respond with the path switch reply to eNB.
   */
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  S1ap_PathSwitchRequestAcknowledgeIEs_t *pathSwitchRequestAcknowledge_p = NULL;

  S1ap_NAS_PDU_t                          nas_pdu = {0}; // yes, alloc on stack
  s1ap_message                            message = {0}; // yes, alloc on stack

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (path_switch_req_ack_pP != NULL);

   ue_ref = s1ap_is_ue_mme_id_in_list (path_switch_req_ack_pP->ue_id);
  if (!ue_ref) {
    OAILOG_ERROR (LOG_S1AP, "This mme ue s1ap id (" MME_UE_S1AP_ID_FMT ") is not attached to any UE context\n", path_switch_req_ack_pP->ue_id);
    // There are some race conditions were NAS T3450 timer is stopped and removed at same time
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /*
   * Start the outcome response timer.
   * * * * When time is reached, MME consider that procedure outcome has failed.
   */
  //     timer_setup(mme_config.s1ap_config.outcome_drop_timer_sec, 0, TASK_S1AP, INSTANCE_DEFAULT,
  //                 TIMER_ONE_SHOT,
  //                 NULL,
  //                 &ue_ref->outcome_response_timer_id);
  /*
   * Insert the timer in the MAP of mme_ue_s1ap_id <-> timer_id
   */
  //     s1ap_timer_insert(ue_ref->mme_ue_s1ap_id, ue_ref->outcome_response_timer_id);
  // todo: PSR if the state is handover, else just complete the message!
  message.procedureCode = S1ap_ProcedureCode_id_PathSwitchRequest;
  message.direction = S1AP_PDU_PR_successfulOutcome;
  pathSwitchRequestAcknowledge_p = &message.msg.s1ap_PathSwitchRequestAcknowledgeIEs;
  pathSwitchRequestAcknowledge_p->mme_ue_s1ap_id = (unsigned long)ue_ref->mme_ue_s1ap_id;
  pathSwitchRequestAcknowledge_p->eNB_UE_S1AP_ID = (unsigned long)ue_ref->enb_ue_s1ap_id;


  /* Set the GTP-TEID. This is the S1-U S-GW TEID. */
//  hash_table_ts_t * bearer_contexts_p = (hash_table_ts_t*)path_switch_req_ack_pP->bearer_ctx_to_be_switched_list.bearer_ctxs;
//
//  bearer_context_t * bearer_context_p = NULL;
//  hashtable_ts_get ((hash_table_ts_t * const)bearer_contexts_p, (const hash_key_t)5, (void **)&bearer_context_p);
//
//  uint                                    offset = 0;
//  S1ap_E_RABToBeSwitchedULItem_t          e_RABToBeSwitchedUl = {0}; // yes, alloc on stack
//
//  s1ap_add_bearer_context_to_switch_list(&pathSwitchRequestAcknowledge_p->e_RABToBeSwitchedULList, &e_RABToBeSwitchedUl, bearer_context_p);
  // todo: @ Lionel: pathSwitchRequestAcknowledge_p->presenceMask |= S1AP_PATHSWITCHREQUESTACKNOWLEDGEIES_E_RABTOBESWITCHEDULLIST_PRESENT;
//  /*
//   * Only add capability information if it's not empty.
//   */
//  if (conn_est_cnf_pP->ue_radio_cap_length) {
//    OAILOG_DEBUG (LOG_S1AP, "UE radio capability found, adding to message\n");
//    initialContextSetupRequest_p->presenceMask |=
//      S1AP_INITIALCONTEXTSETUPREQUESTIES_UERADIOCAPABILITY_PRESENT;
//    OCTET_STRING_fromBuf(&initialContextSetupRequest_p->ueRadioCapability,
//                        (const char*) conn_est_cnf_pP->ue_radio_capabilities,
//                         conn_est_cnf_pP->ue_radio_cap_length);
//    free_wrapper((void**) &(conn_est_cnf_pP->ue_radio_capabilities));
//  }

//  /*
//   * uEaggregateMaximumBitrateDL and uEaggregateMaximumBitrateUL expressed in term of bits/sec
//   */
//  asn_uint642INTEGER (&initialContextSetupRequest_p->uEaggregateMaximumBitrate.uEaggregateMaximumBitRateDL, conn_est_cnf_pP->ambr.br_dl);
//  asn_uint642INTEGER (&initialContextSetupRequest_p->uEaggregateMaximumBitrate.uEaggregateMaximumBitRateUL, conn_est_cnf_pP->ambr.br_ul);
//  e_RABToBeSetup.e_RAB_ID = conn_est_cnf_pP->eps_bearer_id;     //5;
//  e_RABToBeSetup.e_RABlevelQoSParameters.qCI = conn_est_cnf_pP->bearer_qos_qci;

  // todo: check if key exists :)
  pathSwitchRequestAcknowledge_p->securityContext.nextHopChainingCount = path_switch_req_ack_pP->ncc;
  pathSwitchRequestAcknowledge_p->securityContext.nextHopParameter.buf  = calloc (32, sizeof(uint8_t));
  memcpy (pathSwitchRequestAcknowledge_p->securityContext.nextHopParameter.buf, path_switch_req_ack_pP->nh, 32);
  pathSwitchRequestAcknowledge_p->securityContext.nextHopParameter.size = 32;


//pathSwitchRequestAcknowledge_p = &message.msg.s1ap_PathSwitchRequestAcknowledgeIEs;

//  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", conn_est_cnf_pP->security_capabilities_encryption_algorithms);
//  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n", conn_est_cnf_pP->security_capabilities_integrity_algorithms);

//  if (conn_est_cnf_pP->kenb) {
//    initialContextSetupRequest_p->securityKey.buf = calloc (32, sizeof(uint8_t));
//    memcpy (initialContextSetupRequest_p->securityKey.buf, conn_est_cnf_pP->kenb, 32);
//    initialContextSetupRequest_p->securityKey.size = 32;
//  } else {
//    OAILOG_DEBUG (LOG_S1AP, "No kenb\n");
//    initialContextSetupRequest_p->securityKey.buf = NULL;
//    initialContextSetupRequest_p->securityKey.size = 0;
//  }

  pathSwitchRequestAcknowledge_p->securityContext.nextHopParameter.bits_unused = 0;

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    // TODO: handle something
    DevMessage ("Failed to encode path switch acknowledge message\n");
  }

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_PATH_SWITCH_ACKNOWLEDGE message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)pathSwitchRequestAcknowledge_p->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)pathSwitchRequestAcknowledge_p->eNB_UE_S1AP_ID);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 PathSwitchAcknowledge/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas length %u",
                      (mme_ue_s1ap_id_t)pathSwitchRequestAcknowledge_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)pathSwitchRequestAcknowledge_p->eNB_UE_S1AP_ID, nas_pdu.size);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);

  /** Set the new state as connected. */
  ue_ref->s1_ue_state = S1AP_UE_CONNECTED;

  OAILOG_FUNC_OUT (LOG_S1AP);
}
// Note this file can have functions that are to be called in MME module to process 
