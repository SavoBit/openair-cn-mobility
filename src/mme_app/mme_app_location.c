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


/*! \file mme_app_location.c
   \brief
   \author Sebastien ROUX, Lionel GAUTHIER
   \version 1.0
   \company Eurecom
   \email: lionel.gauthier@eurecom.fr
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "assertions.h"
#include "common_types.h"
#include "conversions.h"
#include "msc.h"
#include "log.h"
#include "intertask_interface.h"
#include "mme_app_ue_context.h"
#include "mme_app_defs.h"
#include "mme_config.h"

int
mme_app_send_s6a_update_location_req (
  struct ue_context_s *const ue_context_pP)
{
  struct ue_context_s                    *ue_context_p = NULL;
  uint64_t                                imsi = 0;
  MessageDef                             *message_p = NULL;
  s6a_update_location_req_t              *s6a_ulr_p = NULL;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  IMSI_STRING_TO_IMSI64 ((char *)
                          ue_context_pP->pending_pdn_connectivity_req_imsi, &imsi);
  OAILOG_DEBUG (LOG_MME_APP, "Handling imsi " IMSI_64_FMT "\n", imsi);

  if ((ue_context_p = mme_ue_context_exists_imsi (&mme_app_desc.mme_ue_contexts, imsi)) == NULL) {
    OAILOG_ERROR (LOG_MME_APP, "That's embarrassing as we don't know this IMSI\n");
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }

  message_p = itti_alloc_new_message (TASK_MME_APP, S6A_UPDATE_LOCATION_REQ);

  if (message_p == NULL) {
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }

  s6a_ulr_p = &message_p->ittiMsg.s6a_update_location_req;
  memset ((void *)s6a_ulr_p, 0, sizeof (s6a_update_location_req_t));
  IMSI64_TO_STRING (imsi, s6a_ulr_p->imsi);
  s6a_ulr_p->imsi_length = strlen (s6a_ulr_p->imsi);
  s6a_ulr_p->initial_attach = INITIAL_ATTACH;
  memcpy (&s6a_ulr_p->visited_plmn, &ue_context_p->guti.gummei.plmn, sizeof (plmn_t));
  s6a_ulr_p->rat_type = RAT_EUTRAN;
  /*
   * Check if we already have UE data
   */
  s6a_ulr_p->skip_subscriber_data = 0;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S6A_MME, NULL, 0, "0 S6A_UPDATE_LOCATION_REQ imsi " IMSI_64_FMT, imsi);
  rc =  itti_send_msg_to_task (TASK_S6A, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}

int
mme_app_handle_s6a_update_location_ans (
  const s6a_update_location_ans_t * const ula_pP)
{
  uint64_t                                imsi = 0;
  struct ue_context_s                    *ue_context_p = NULL;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (ula_pP );

  if (ula_pP->result.present == S6A_RESULT_BASE) {
    if (ula_pP->result.choice.base != DIAMETER_SUCCESS) {
      /*
       * The update location procedure has failed. Notify the NAS layer
       * and don't initiate the bearer creation on S-GW side.
       */
      OAILOG_DEBUG (LOG_MME_APP, "ULR/ULA procedure returned non success (ULA.result.choice.base=%d)\n", ula_pP->result.choice.base);
      DevMessage ("ULR/ULA procedure returned non success\n");
    }
  } else {
    /*
     * The update location procedure has failed. Notify the NAS layer
     * and don't initiate the bearer creation on S-GW side.
     */
    OAILOG_DEBUG (LOG_MME_APP, "ULR/ULA procedure returned non success (ULA.result.present=%d)\n", ula_pP->result.present);
    DevMessage ("ULR/ULA procedure returned non success\n");
  }

  IMSI_STRING_TO_IMSI64 ((char *)ula_pP->imsi, &imsi);
  OAILOG_DEBUG (LOG_MME_APP, "%s Handling imsi " IMSI_64_FMT "\n", __FUNCTION__, imsi);

  if ((ue_context_p = mme_ue_context_exists_imsi (&mme_app_desc.mme_ue_contexts, imsi)) == NULL) {
    OAILOG_ERROR (LOG_MME_APP, "That's embarrassing as we don't know this IMSI\n");
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "0 S6A_UPDATE_LOCATION unknown imsi " IMSI_64_FMT" ", imsi);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }

  // Updating the UE subscription without much validation!

  ue_context_p->subscription_known = SUBSCRIPTION_KNOWN;
  ue_context_p->sub_status = ula_pP->subscription_data.subscriber_status;
  ue_context_p->access_restriction_data = ula_pP->subscription_data.access_restriction;
  /*
   * Copy the subscribed ambr to the sgw create session request message
   */
  memcpy (&ue_context_p->subscribed_ambr, &ula_pP->subscription_data.subscribed_ambr, sizeof (ambr_t));
  // In Activate Default EPS Bearer Context Setup Request message APN-AMPBR is forced to 200Mbps and 100 Mbps for DL
  // and UL respectively. Since as of now we support only one bearer, forcing AMBR as well to APN-AMBR values.
  ue_context_p->subscribed_ambr.br_ul = 100000000; // Setting it to 100 Mbps
  ue_context_p->subscribed_ambr.br_dl = 200000000; // Setting it to 200 Mbps
  // TODO task#14477798 - Configure the policy driven values in HSS and use those here and in NAS.
  //ue_context_p->subscribed_ambr.br_ul = ue_context_p->subscribed_ambr.br_ul; // Setting it to 100 Mbps
  //ue_context_p->subscribed_ambr.br_dl = ue_context_p->subscribed_ambr.br_dl; // Setting it to 200 Mbps

  memcpy (ue_context_p->msisdn, ula_pP->subscription_data.msisdn, ula_pP->subscription_data.msisdn_length);
  ue_context_p->msisdn_length = ula_pP->subscription_data.msisdn_length;
  AssertFatal (ula_pP->subscription_data.msisdn_length <= MSISDN_LENGTH, "MSISDN LENGTH is too high %u", MSISDN_LENGTH);
  ue_context_p->msisdn[ue_context_p->msisdn_length] = '\0';
  ue_context_p->rau_tau_timer = ula_pP->subscription_data.rau_tau_timer;
  ue_context_p->access_mode = ula_pP->subscription_data.access_mode;
  memcpy (&ue_context_p->apn_profile, &ula_pP->subscription_data.apn_config_profile, sizeof (apn_config_profile_t));
  /*
   * Set the value of  Mobile Reachability timer based on value of T3412 (Periodic TAU timer) sent in Attach accept /TAU accept.
   * Set it to MME_APP_DELTA_T3412_REACHABILITY_TIMER minutes greater than T3412.
   * Set the value of Implicit timer. Set it to MME_APP_DELTA_REACHABILITY_IMPLICIT_DETACH_TIMER minutes greater than  Mobile Reachability timer
  */
  ue_context_p->mobile_reachability_timer.id = MME_APP_TIMER_INACTIVE_ID;
  ue_context_p->mobile_reachability_timer.sec = ((mme_config.nas_config.t3412_min) + MME_APP_DELTA_T3412_REACHABILITY_TIMER) * 60;
  ue_context_p->implicit_detach_timer.id = MME_APP_TIMER_INACTIVE_ID;
  ue_context_p->implicit_detach_timer.sec = (ue_context_p->mobile_reachability_timer.sec) + MME_APP_DELTA_REACHABILITY_IMPLICIT_DETACH_TIMER * 60;

  /**
   * Check if the UE is already registered or not. The UE may have been handovered / performed TAU.
   */
  OAILOG_INFO(LOG_MME_APP, "UE with imsi " IMSI_64_FMT ", is already registered. We will not establish session in SAE-GW. "
      "Informing the NAS layer about the updated subscription information. \n", imsi);
  // todo: check the failure case.. TAU reject in that case!!
  /**
   * This method should return the subscription information to the NAS layer via an ITTI signal.
   * Todo: Making this method synchronized, would prevent some necessary flags (tau_active, etc.. (since no timer)).
   */
  MessageDef                             *message_p = NULL;
  message_p = itti_alloc_new_message (TASK_MME_APP, MME_APP_NAS_UPDATE_LOCATION_CNF);

  if (message_p == NULL) {
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  itti_mme_app_nas_update_location_cnf_t              *mme_app_nas_ula_cnf_p = NULL;

  mme_app_nas_ula_cnf_p = &message_p->ittiMsg.mme_app_nas_update_location_cnf;
  memset ((void *)mme_app_nas_ula_cnf_p, 0, sizeof (itti_mme_app_nas_update_location_cnf_t));
  IMSI64_TO_STRING (imsi, mme_app_nas_ula_cnf_p->imsi);
  mme_app_nas_ula_cnf_p->imsi_length = strlen (mme_app_nas_ula_cnf_p->imsi);
  mme_app_nas_ula_cnf_p->ue_id = ue_context_p->mme_ue_s1ap_id;

  //    mme_app_nas_ula_cnf_p->initial_attach = INITIAL_ATTACH;
  //    memcpy (&s6a_ulr_p->visited_plmn, &ue_context_p->guti.gummei.plmn, sizeof (plmn_t));
  //    s6a_ulr_p->rat_type = RAT_EUTRAN;

  mme_app_nas_ula_cnf_p->result.present = ula_pP->result.present;
  mme_app_nas_ula_cnf_p->result.choice.base = ula_pP->result.choice.base;
  rc =  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}

int
mme_app_handle_s6a_cancel_location_req(
  const s6a_cancel_location_req_t * const clr_pP)
{
  uint64_t                                imsi = 0;
  struct ue_context_s                    *ue_context_p = NULL;
  int                                     rc = RETURNok;
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (clr_pP );

  IMSI_STRING_TO_IMSI64 ((char *)clr_pP->imsi, &imsi);
  OAILOG_DEBUG (LOG_MME_APP, "%s Handling CANCEL_LOCATION_REQUEST for imsi " IMSI_64_FMT "\n", __FUNCTION__, imsi);

  if ((ue_context_p = mme_ue_context_exists_imsi (&mme_app_desc.mme_ue_contexts, imsi)) == NULL) {
    OAILOG_ERROR (LOG_MME_APP, "That's embarrassing as we don't know this IMSI\n");
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "0 S6A_CANCEL_LOCATION unknown imsi " IMSI_64_FMT" ", imsi);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  /** Check the cancellation type.. */
  if(clr_pP->cancellation_type == MME_UPDATE_PROCEDURE){
    /**
     * Handle handover based cancellation procedure.
     * Check the MME mobility timer.. if the timer has not expired yet, just set a flag (not waiting in this thread and resending the signal
     * not to block resources --> any other way to send a signal after a given time --> timer with signal sending!!!).
     * Else remove the UE implicitly.. (not sending Purge_UE for this one).
     */
    OAILOG_INFO(LOG_MME_APP, "Handling CLR for MME_UPDATE_PROCEDURE for UE with imsi " IMSI_64_FMT " "
        "Checking the MME_MOBILITY_COMPLETION timer %d. \n", imsi);
    /** Not checking any flags in this case.. Just check that the timer is invalidated. If so perform an implicit detach. */
    if(ue_context_p->mme_mobility_completion_timer.id != MME_APP_TIMER_INACTIVE_ID){
      OAILOG_INFO(LOG_MME_APP, "MME_MOBILTY_COMPLETION timer %u, is still running. Marking CLR but not removing the UE yet with imsi " IMSI_64_FMT ". \n",
          ue_context_p->mme_mobility_completion_timer.id, imsi);
      ue_context_p->pending_clear_location_request = true; // todo: not checking the pending flag..
      OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
    }else{
      OAILOG_INFO(LOG_MME_APP, "MME_MOBILTY_COMPLETION timer is not running. Implicit removal for UE with imsi " IMSI_64_FMT " due handover. \n", imsi);
    }
  }else{
    /** todo: handle rest of cancellation procedures.. */
    OAILOG_INFO(LOG_MME_APP, "Received cancellation type %d (not due handover). Not checking the MME_MOBILITY timer. Performing directly implicit detach on "
        "UE with imsi " IMSI_64_FMT " received unhandled cancellation type %d. \n", clr_pP->cancellation_type, imsi);
    // todo: not implicit removal but proper detach in this case..
  }

  /** Perform an implicit detach via NAS layer.. We purge context ourself or purge the MME_APP context. NAS has to purge the EMM context and the MME_APP context. */
  OAILOG_INFO (LOG_MME_APP, "Expired- Implicit Detach timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  ue_context_p->implicit_detach_timer.id = MME_APP_TIMER_INACTIVE_ID;

  // Initiate Implicit Detach for the UE
  message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
  DevAssert (message_p != NULL);
  message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);


  OAILOG_INFO (LOG_MME_APP, "Expired- Implicit Detach timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);

  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}


int
mme_app_handle_s6a_reset_req(
  const s6a_reset_req_t * const rr_pP)
{
  uint64_t                                imsi = 0;
  struct ue_context_s                    *ue_context_p = NULL;
  int                                     rc = RETURNok;
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (rr_pP );

  OAILOG_DEBUG (LOG_MME_APP, "%s Handling RESET_REQUEST \n", __FUNCTION__);
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}

