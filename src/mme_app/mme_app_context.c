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


#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "dynamic_memory_check.h"
#include "assertions.h"
#include "log.h"
#include "msc.h"
#include "common_types.h"
#include "conversions.h"
#include "intertask_interface.h"
#include "enum_string.h"
#include "mme_app_ue_context.h"
#include "mme_app_defs.h"
#include "mme_app_itti_messaging.h"
#include "s1ap_mme.h"
#include "timer.h"
#include "mme_app_statistics.h"

static void _mme_app_send_nas_ue_context_response_err(mme_ue_s1ap_id_t ue_id, MMECause_t mmeCause);

static void _mme_app_handle_s1ap_ue_context_release (const mme_ue_s1ap_id_t mme_ue_s1ap_id,
                                                     const enb_ue_s1ap_id_t enb_ue_s1ap_id,
                                                     uint32_t enb_id,
                                                     enum s1cause cause);

static void _mme_app_send_s10_context_response_err(teid_t mme_source_s10_teid, uint32_t mme_source_ipv4_address, void* trxn, MMECause_t mmeCause);

/* EMM state machine handlers */
static const mme_app_ue_callback_t          _mme_ue_callbacks[UE_CONTEXT_STATE_MAX] = {
  NULL,
  EmmCbS1apRegistered,
  EmmCbS1apHandoverTau,
};


//------------------------------------------------------------------------------
ue_context_t *mme_create_new_ue_context (void)
{
  ue_context_t                           *new_p = calloc (1, sizeof (ue_context_t));
  new_p->mme_ue_s1ap_id = INVALID_MME_UE_S1AP_ID;
  new_p->enb_s1ap_id_key = INVALID_ENB_UE_S1AP_ID_KEY;
  // Initialize timers to INVALID IDs
  new_p->mobile_reachability_timer.id = MME_APP_TIMER_INACTIVE_ID;
  new_p->implicit_detach_timer.id = MME_APP_TIMER_INACTIVE_ID;

  new_p->ue_radio_cap_length = 0;

  new_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
  new_p->ue_context_rel_cause = S1AP_INVALID_CAUSE;

  new_p->mme_mobility_completion_timer.id = MME_APP_TIMER_INACTIVE_ID;

  return new_p;
}

//------------------------------------------------------------------------------
void mme_app_ue_context_free_content (ue_context_t * const ue_context_p)
{
  //  imsi64_t         imsi;
  //  unsigned               imsi_auth:1;
  //  enb_ue_s1ap_id_t       enb_ue_s1ap_id:24;
  //  mme_ue_s1ap_id_t       mme_ue_s1ap_id;
  //  uint32_t               ue_id;
  //  uint8_t                nb_of_vectors;
  //  eutran_vector_t       *vector_list;
  //  eutran_vector_t       *vector_in_use;
  //  unsigned               subscription_known:1;
  //  uint8_t                msisdn[MSISDN_LENGTH+1];
  //  uint8_t                msisdn_length;
  //  mm_state_t             mm_state;
  //  guti_t                 guti;
  //  me_identity_t          me_identity;
  //  ecgi_t                  e_utran_cgi;
  //  time_t                 cell_age;
  //  network_access_mode_t  access_mode;
  //  apn_config_profile_t   apn_profile;
  //  ard_t                  access_restriction_data;
  //  subscriber_status_t    sub_status;
  //  ambr_t                 subscribed_ambr;
  //  ambr_t                 used_ambr;
  //  rau_tau_timer_t        rau_tau_timer;
  // int                    ue_radio_cap_length;
  // teid_t                 mme_s11_teid;
  // teid_t                 sgw_s11_teid;
  // PAA_t                  paa;
  // char                   pending_pdn_connectivity_req_imsi[16];
  // uint8_t                pending_pdn_connectivity_req_imsi_length;
  DevAssert(ue_context_p != NULL);
  bdestroy(ue_context_p->pending_pdn_connectivity_req_apn);
  bdestroy(ue_context_p->pending_pdn_connectivity_req_pdn_addr);
  bdestroy(ue_context_p->pending_s1ap_source_to_target_handover_container);
  // todo: remove all the bearer_contexts

  // Stop Mobile reachability timer,if running 
  if (ue_context_p->mobile_reachability_timer.id != MME_APP_TIMER_INACTIVE_ID) {
    if (timer_remove(ue_context_p->mobile_reachability_timer.id)) {

      OAILOG_ERROR (LOG_MME_APP, "Failed to stop Mobile Reachability timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    } 
    ue_context_p->mobile_reachability_timer.id = MME_APP_TIMER_INACTIVE_ID;
  }
  // Stop Implicit detach timer,if running 
  if (ue_context_p->implicit_detach_timer.id != MME_APP_TIMER_INACTIVE_ID) {
    if (timer_remove(ue_context_p->implicit_detach_timer.id)) {
      OAILOG_ERROR (LOG_MME_APP, "Failed to stop Implicit Detach timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    } 
    ue_context_p->implicit_detach_timer.id = MME_APP_TIMER_INACTIVE_ID;
  }
  // Stop Initial context setup process guard timer,if running 
  if (ue_context_p->initial_context_setup_rsp_timer.id != MME_APP_TIMER_INACTIVE_ID) {
    if (timer_remove(ue_context_p->initial_context_setup_rsp_timer.id)) {
      OAILOG_ERROR (LOG_MME_APP, "Failed to stop Initial Context Setup Rsp timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    } 
    ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
  }
  if (ue_context_p->ue_radio_capabilities) {
    free_wrapper((void**) &(ue_context_p->ue_radio_capabilities));
  }

  ue_context_p->ue_radio_cap_length = 0;

  ue_context_p->ue_context_rel_cause = S1AP_INVALID_CAUSE;


  // int                    pending_pdn_connectivity_req_pti;
  // unsigned               pending_pdn_connectivity_req_ue_id;
  // network_qos_t          pending_pdn_connectivity_req_qos;
  // pco_flat_t             pending_pdn_connectivity_req_pco;
  // DO NOT FREE THE FOLLOWING POINTER, IT IS esm_proc_data_t*
  // void                  *pending_pdn_connectivity_req_proc_data;
  //int                    pending_pdn_connectivity_req_request_type;
  //ebi_t                  default_bearer_id;
  //bearer_context_t       eps_bearers[BEARERS_PER_UE];

}

//------------------------------------------------------------------------------
ue_context_t                           *
mme_ue_context_exists_enb_ue_s1ap_id (
  mme_ue_context_t * const mme_ue_context_p,
  const enb_s1ap_id_key_t enb_key)
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;
  void                                   *id = NULL;
  
  hashtable_ts_get (mme_ue_context_p->enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)enb_key, (void **)&id);
  
  if (HASH_TABLE_OK == h_rc) {
    return mme_ue_context_exists_mme_ue_s1ap_id (mme_ue_context_p, (mme_ue_s1ap_id_t)(uintptr_t) id);
  }
  return NULL;
}

//------------------------------------------------------------------------------
ue_context_t                           *
mme_ue_context_exists_mme_ue_s1ap_id (
  mme_ue_context_t * const mme_ue_context_p,
  const mme_ue_s1ap_id_t mme_ue_s1ap_id)
{
  struct ue_context_s                    *ue_context_p = NULL;

  hashtable_ts_get (mme_ue_context_p->mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)mme_ue_s1ap_id, (void **)&ue_context_p);
  return ue_context_p;

}
//------------------------------------------------------------------------------
struct ue_context_s                    *
mme_ue_context_exists_imsi (
  mme_ue_context_t * const mme_ue_context_p,
  const imsi64_t imsi)
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;
  void                                   *id = NULL;

  h_rc = hashtable_ts_get (mme_ue_context_p->imsi_ue_context_htbl, (const hash_key_t)imsi, (void **)&id);

  if (HASH_TABLE_OK == h_rc) {
    return mme_ue_context_exists_mme_ue_s1ap_id (mme_ue_context_p, (mme_ue_s1ap_id_t)(uintptr_t) id);
  }

  return NULL;
}

//------------------------------------------------------------------------------
struct ue_context_s                    *
mme_ue_context_exists_s11_teid (
  mme_ue_context_t * const mme_ue_context_p,
  const s11_teid_t teid)
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;
  void                                   *id = NULL;

  h_rc = hashtable_ts_get (mme_ue_context_p->tun11_ue_context_htbl, (const hash_key_t)teid, (void **)&id);

  if (HASH_TABLE_OK == h_rc) {
    return mme_ue_context_exists_mme_ue_s1ap_id (mme_ue_context_p, (mme_ue_s1ap_id_t)(uintptr_t) id);
  }
  return NULL;
}

//------------------------------------------------------------------------------
struct ue_context_s                    *
mme_ue_context_exists_s10_teid (
  mme_ue_context_t * const mme_ue_context_p,
  const s10_teid_t teid)
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;
  void                                   *id = NULL;

  h_rc = hashtable_ts_get (mme_ue_context_p->tun10_ue_context_htbl, (const hash_key_t)teid, (void **)&id);

  if (HASH_TABLE_OK == h_rc) {
    return mme_ue_context_exists_mme_ue_s1ap_id (mme_ue_context_p, (mme_ue_s1ap_id_t)(uintptr_t) id);
  }
  return NULL;
}

//------------------------------------------------------------------------------
ue_context_t                           *
mme_ue_context_exists_guti (
  mme_ue_context_t * const mme_ue_context_p,
  const guti_t * const guti_p)
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;
  void                                   *id = NULL;

  h_rc = obj_hashtable_ts_get (mme_ue_context_p->guti_ue_context_htbl, (const void *)guti_p, sizeof (*guti_p), (void **)&id);

  if (HASH_TABLE_OK == h_rc) {
    return mme_ue_context_exists_mme_ue_s1ap_id (mme_ue_context_p, (mme_ue_s1ap_id_t)(uintptr_t)id);
  }

  return NULL;
}

//------------------------------------------------------------------------------
void mme_app_move_context (ue_context_t *dst, ue_context_t *src)
{
  OAILOG_FUNC_IN (LOG_MME_APP);
  if ((dst) && (src)) {
    dst->imsi                = src->imsi;
    dst->imsi_auth           = src->imsi_auth;
    //enb_s1ap_id_key
    //enb_ue_s1ap_id
    //mme_ue_s1ap_id
    dst->sctp_assoc_id_key       = src->sctp_assoc_id_key;
    dst->subscription_known      = src->subscription_known;
    memcpy((void *)dst->msisdn, (const void *)src->msisdn, sizeof(src->msisdn));
    dst->msisdn_length           = src->msisdn_length;src->msisdn_length = 0;
    dst->mm_state                = src->mm_state;
    dst->ecm_state               = src->ecm_state;
    dst->is_guti_set             = src->is_guti_set;
    dst->guti                    = src->guti;
    dst->me_identity             = src->me_identity;
    dst->e_utran_cgi             = src->e_utran_cgi;
    dst->cell_age                = src->cell_age;
    dst->access_mode             = src->access_mode;
    dst->apn_profile             = src->apn_profile;
    dst->access_restriction_data = src->access_restriction_data;
    dst->sub_status              = src->sub_status;
    dst->subscribed_ambr         = src->subscribed_ambr;
    dst->used_ambr               = src->used_ambr;
    dst->rau_tau_timer           = src->rau_tau_timer;
    dst->mme_s11_teid            = src->mme_s11_teid;
    dst->local_mme_s10_teid      = src->local_mme_s10_teid;
    dst->sgw_s11_teid            = src->sgw_s11_teid;
    memcpy((void *)dst->pending_pdn_connectivity_req_imsi, (const void *)src->pending_pdn_connectivity_req_imsi, sizeof(src->pending_pdn_connectivity_req_imsi));
    dst->pending_pdn_connectivity_req_imsi_length = src->pending_pdn_connectivity_req_imsi_length;
    dst->pending_pdn_connectivity_req_apn         = src->pending_pdn_connectivity_req_apn;
    src->pending_pdn_connectivity_req_apn         = NULL;

    dst->pending_pdn_connectivity_req_pdn_addr    = src->pending_pdn_connectivity_req_pdn_addr;
    src->pending_pdn_connectivity_req_pdn_addr    = NULL;
    dst->pending_pdn_connectivity_req_pti         = src->pending_pdn_connectivity_req_pti;
    dst->pending_pdn_connectivity_req_ue_id       = src->pending_pdn_connectivity_req_ue_id;
    dst->pending_pdn_connectivity_req_qos         = src->pending_pdn_connectivity_req_qos;
    dst->pending_pdn_connectivity_req_pco         = src->pending_pdn_connectivity_req_pco;
    dst->pending_pdn_connectivity_req_proc_data   = src->pending_pdn_connectivity_req_proc_data;
    src->pending_pdn_connectivity_req_proc_data   = NULL;
    dst->pending_pdn_connectivity_req_request_type= src->pending_pdn_connectivity_req_request_type;
    dst->default_bearer_id       = src->default_bearer_id;
    memcpy((void *)dst->eps_bearers, (const void *)src->eps_bearers, sizeof(bearer_context_t)*BEARERS_PER_UE);
    OAILOG_DEBUG (LOG_MME_APP,
           "mme_app_move_context("ENB_UE_S1AP_ID_FMT " <- " ENB_UE_S1AP_ID_FMT ") done\n",
           dst->enb_ue_s1ap_id, src->enb_ue_s1ap_id);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}
//------------------------------------------------------------------------------
// this is detected only while receiving an INITIAL UE message

/***********************************************IMPORTANT*****************************************************
 * We are not using this function. If plan to use this in future then the key insertion and removal within this 
 * function need to modified.
 **********************************************IMPORTANT*****************************************************/
void
mme_ue_context_duplicate_enb_ue_s1ap_id_detected (
  const enb_s1ap_id_key_t enb_key,
  const mme_ue_s1ap_id_t  mme_ue_s1ap_id,
  const bool              is_remove_old)
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;
  void                                   *id = NULL;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;
  enb_s1ap_id_key_t                       old_enb_key = 0;

  OAILOG_FUNC_IN (LOG_MME_APP);
  enb_ue_s1ap_id = MME_APP_ENB_S1AP_ID_KEY2ENB_S1AP_ID(enb_key);

  if (INVALID_MME_UE_S1AP_ID == mme_ue_s1ap_id) {
    OAILOG_ERROR (LOG_MME_APP,
        "Error could not associate this enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " with mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
        enb_ue_s1ap_id, mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  h_rc = hashtable_ts_get (mme_app_desc.mme_ue_contexts.mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)mme_ue_s1ap_id,  (void **)&id);
  if (HASH_TABLE_OK == h_rc) {
    old_enb_key = (enb_s1ap_id_key_t)(uintptr_t) id;
    if (old_enb_key != enb_key) {
      if (is_remove_old) {
        ue_context_t                           *old = NULL;
        /* TODO
         * Insert and remove need to be corrected. mme_ue_s1ap_id is used to point to context ptr and
         * enb_ue_s1ap_id_key is used to point to mme_ue_s1ap_id
         */ 
        h_rc = hashtable_ts_remove (mme_app_desc.mme_ue_contexts.mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)mme_ue_s1ap_id, (void **)&id);
        h_rc = hashtable_ts_insert (mme_app_desc.mme_ue_contexts.mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)mme_ue_s1ap_id, (void *)(uintptr_t)enb_key);
        h_rc = hashtable_ts_remove (mme_app_desc.mme_ue_contexts.enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)old_enb_key, (void **)&old);
        if (HASH_TABLE_OK == h_rc) {
          ue_context_t                           *new = NULL;
          h_rc = hashtable_ts_get (mme_app_desc.mme_ue_contexts.enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)enb_key, (void **)&new);
          mme_app_move_context(new, old);
          mme_app_ue_context_free_content(old);
          OAILOG_DEBUG (LOG_MME_APP,
                  "Removed old UE context enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
                  MME_APP_ENB_S1AP_ID_KEY2ENB_S1AP_ID(old_enb_key), mme_ue_s1ap_id);
        }
      } else {
        ue_context_t                           *new = NULL;
        h_rc = hashtable_ts_remove (mme_app_desc.mme_ue_contexts.enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)enb_key, (void **)&new);
        if (HASH_TABLE_OK == h_rc) {
          mme_app_ue_context_free_content(new);
          OAILOG_DEBUG (LOG_MME_APP,
                  "Removed new UE context enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
                  enb_ue_s1ap_id, mme_ue_s1ap_id);
        }
      }
    } else {
      OAILOG_DEBUG (LOG_MME_APP,
          "No duplicated context found enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " with mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
          enb_ue_s1ap_id, mme_ue_s1ap_id);
    }
  } else {
    OAILOG_ERROR (LOG_MME_APP,
            "Error could find this mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
            mme_ue_s1ap_id);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
int
mme_ue_context_notified_new_ue_s1ap_id_association (
  const enb_s1ap_id_key_t  enb_key,
  const mme_ue_s1ap_id_t   mme_ue_s1ap_id)
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;
  ue_context_t                           *ue_context_p = NULL;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;

  OAILOG_FUNC_IN (LOG_MME_APP);
  
  if (INVALID_MME_UE_S1AP_ID == mme_ue_s1ap_id) {
    OAILOG_ERROR (LOG_MME_APP,
        "Error could not associate this enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " with mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
        enb_ue_s1ap_id, mme_ue_s1ap_id);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }

  ue_context_p = mme_ue_context_exists_enb_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, enb_key);
  if (ue_context_p) {
    if (ue_context_p->enb_s1ap_id_key == enb_key) { // useless
      if (INVALID_MME_UE_S1AP_ID == ue_context_p->mme_ue_s1ap_id) {
        // new insertion of mme_ue_s1ap_id, not a change in the id
        h_rc = hashtable_ts_insert (mme_app_desc.mme_ue_contexts.mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)mme_ue_s1ap_id, (void *)ue_context_p);
        if (HASH_TABLE_OK == h_rc) {
          ue_context_p->mme_ue_s1ap_id = mme_ue_s1ap_id;
          OAILOG_DEBUG (LOG_MME_APP,
              "Associated this enb_ue_s1ap_ue_id " ENB_UE_S1AP_ID_FMT " with mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
              ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id);

          s1ap_notified_new_ue_mme_s1ap_id_association (ue_context_p->sctp_assoc_id_key,ue_context_p-> enb_ue_s1ap_id, mme_ue_s1ap_id);
          OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNok);
        }
      }
    }
  }
  OAILOG_ERROR (LOG_MME_APP,
      "Error could not associate this enb_ue_s1ap_ue_id " ENB_UE_S1AP_ID_FMT " with mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
      enb_ue_s1ap_id, mme_ue_s1ap_id);
  OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
}
//------------------------------------------------------------------------------
void
mme_ue_context_update_coll_keys (
  mme_ue_context_t * const mme_ue_context_p,
  ue_context_t     * const ue_context_p,
  const enb_s1ap_id_key_t  enb_s1ap_id_key,
  const mme_ue_s1ap_id_t   mme_ue_s1ap_id,
  const imsi64_t     imsi,
  const s11_teid_t         mme_s11_teid,
  const s10_teid_t         local_mme_s10_teid,
  const guti_t     * const guti_p)  //  never NULL, if none put &ue_context_p->guti
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;
  void                                   *id = NULL;

  OAILOG_FUNC_IN(LOG_MME_APP);

  OAILOG_TRACE (LOG_MME_APP, "Update ue context.old_enb_ue_s1ap_id_key %ld ue context.old_mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " ue context.old_IMSI " IMSI_64_FMT " ue context.old_GUTI "GUTI_FMT"\n",
             ue_context_p->enb_s1ap_id_key, ue_context_p->mme_ue_s1ap_id, ue_context_p->imsi, GUTI_ARG(&ue_context_p->guti));

  OAILOG_TRACE (LOG_MME_APP, "Update ue context %p updated_enb_ue_s1ap_id_key %ld updated_mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " updated_IMSI " IMSI_64_FMT " updated_GUTI " GUTI_FMT "\n",
            ue_context_p, enb_s1ap_id_key, mme_ue_s1ap_id, imsi, GUTI_ARG(guti_p));

  if ((INVALID_ENB_UE_S1AP_ID_KEY != enb_s1ap_id_key) && (ue_context_p->enb_s1ap_id_key != enb_s1ap_id_key)) {
      // new insertion of enb_ue_s1ap_id_key,
      h_rc = hashtable_ts_remove (mme_ue_context_p->enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)ue_context_p->enb_s1ap_id_key, (void **)&id);
      h_rc = hashtable_ts_insert (mme_ue_context_p->enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)enb_s1ap_id_key, (void *)(uintptr_t)mme_ue_s1ap_id);

      if (HASH_TABLE_OK != h_rc) {
        OAILOG_ERROR (LOG_MME_APP,
            "Error could not update this ue context %p enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " %s\n",
            ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, hashtable_rc_code2string(h_rc));
      }
      ue_context_p->enb_s1ap_id_key = enb_s1ap_id_key;
    }


  if ((INVALID_MME_UE_S1AP_ID != mme_ue_s1ap_id) && (ue_context_p->mme_ue_s1ap_id != mme_ue_s1ap_id)) {
      // new insertion of mme_ue_s1ap_id, not a change in the id
      h_rc = hashtable_ts_remove (mme_ue_context_p->mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)ue_context_p->mme_ue_s1ap_id,  (void **)&ue_context_p);
      h_rc = hashtable_ts_insert (mme_ue_context_p->mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)mme_ue_s1ap_id, (void *)ue_context_p);

      if (HASH_TABLE_OK != h_rc) {
        OAILOG_ERROR (LOG_MME_APP,
            "Error could not update this ue context %p enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " %s\n",
            ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, hashtable_rc_code2string(h_rc));
      }
      ue_context_p->mme_ue_s1ap_id = mme_ue_s1ap_id;

    if (INVALID_IMSI64 != imsi) {
      h_rc = hashtable_ts_remove (mme_ue_context_p->imsi_ue_context_htbl, (const hash_key_t)ue_context_p->imsi, (void **)&id);
      h_rc = hashtable_ts_insert (mme_ue_context_p->imsi_ue_context_htbl, (const hash_key_t)imsi, (void *)(uintptr_t)mme_ue_s1ap_id);
      if (HASH_TABLE_OK != h_rc) {
       OAILOG_ERROR (LOG_MME_APP,
          "Error could not update this ue context %p enb_ue_s1ap_ue_id " ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " imsi " IMSI_64_FMT ": %s\n",
          ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, imsi, hashtable_rc_code2string(h_rc));
    }
      ue_context_p->imsi = imsi;
    }
    /** S11 Key. */
    h_rc = hashtable_ts_remove (mme_ue_context_p->tun11_ue_context_htbl, (const hash_key_t)ue_context_p->mme_s11_teid, (void **)&id);
    h_rc = hashtable_ts_insert (mme_ue_context_p->tun11_ue_context_htbl, (const hash_key_t)mme_s11_teid, (void *)(uintptr_t)mme_ue_s1ap_id);
    if (HASH_TABLE_OK != h_rc) {
      OAILOG_TRACE (LOG_MME_APP,
          "Error could not update this ue context %p enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " mme_s11_teid " TEID_FMT " : %s\n",
          ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, mme_s11_teid, hashtable_rc_code2string(h_rc));
    }
    ue_context_p->mme_s11_teid = mme_s11_teid;

    /** S10 Key --> Key may be generated later and then added. */
    h_rc = hashtable_ts_remove (mme_ue_context_p->tun10_ue_context_htbl, (const hash_key_t)ue_context_p->local_mme_s10_teid, (void **)&id);
    h_rc = hashtable_ts_insert (mme_ue_context_p->tun10_ue_context_htbl, (const hash_key_t)local_mme_s10_teid, (void *)(uintptr_t)mme_ue_s1ap_id);
    if (HASH_TABLE_OK != h_rc) {
      OAILOG_TRACE (LOG_MME_APP,
          "Error could not update this ue context %p enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " mme_s10_teid " TEID_FMT " : %s\n",
          ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, local_mme_s10_teid, hashtable_rc_code2string(h_rc));
    }
    ue_context_p->local_mme_s10_teid = local_mme_s10_teid;

    if (guti_p)
    {
      h_rc = obj_hashtable_ts_remove (mme_ue_context_p->guti_ue_context_htbl, (const void *const)&ue_context_p->guti, sizeof (ue_context_p->guti), (void **)&id);
      h_rc = obj_hashtable_ts_insert (mme_ue_context_p->guti_ue_context_htbl, (const void *const)guti_p, sizeof (*guti_p), (void *)(uintptr_t)mme_ue_s1ap_id);
      if (HASH_TABLE_OK != h_rc) {
        OAILOG_TRACE (LOG_MME_APP, "Error could not update this ue context %p enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " guti " GUTI_FMT " %s\n",
            ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, GUTI_ARG(guti_p), hashtable_rc_code2string(h_rc));
      }
      ue_context_p->guti = *guti_p;
    }
  }

  if ((ue_context_p->imsi != imsi)
      || (ue_context_p->mme_ue_s1ap_id != mme_ue_s1ap_id)) {
    h_rc = hashtable_ts_remove (mme_ue_context_p->imsi_ue_context_htbl, (const hash_key_t)ue_context_p->imsi, (void **)&id);
    if (INVALID_MME_UE_S1AP_ID != mme_ue_s1ap_id) {
      h_rc = hashtable_ts_insert (mme_ue_context_p->imsi_ue_context_htbl, (const hash_key_t)imsi, (void *)(uintptr_t)mme_ue_s1ap_id);
    } else {
      h_rc = HASH_TABLE_KEY_NOT_EXISTS;
    }
    if (HASH_TABLE_OK != h_rc) {
      OAILOG_TRACE (LOG_MME_APP,
          "Error could not update this ue context %p enb_ue_s1ap_ue_id " ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " imsi " IMSI_64_FMT ": %s\n",
          ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, imsi, hashtable_rc_code2string(h_rc));
    }
    ue_context_p->imsi = imsi;
  }

  /** S11. */
  if ((ue_context_p->mme_s11_teid != mme_s11_teid)
      || (ue_context_p->mme_ue_s1ap_id != mme_ue_s1ap_id)) {
    h_rc = hashtable_ts_remove (mme_ue_context_p->tun11_ue_context_htbl, (const hash_key_t)ue_context_p->mme_s11_teid, (void **)&id);
    if (INVALID_MME_UE_S1AP_ID != mme_ue_s1ap_id) {
      h_rc = hashtable_ts_insert (mme_ue_context_p->tun11_ue_context_htbl, (const hash_key_t)mme_s11_teid, (void *)(uintptr_t)mme_ue_s1ap_id);
    } else {
      h_rc = HASH_TABLE_KEY_NOT_EXISTS;
    }

    if (HASH_TABLE_OK != h_rc) {
      OAILOG_TRACE (LOG_MME_APP,
          "Error could not update this ue context %p enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " mme_s11_teid " TEID_FMT " : %s\n",
          ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, mme_s11_teid, hashtable_rc_code2string(h_rc));
    }
    ue_context_p->mme_s11_teid = mme_s11_teid;
  }

  /** S10. */
  if ((ue_context_p->local_mme_s10_teid != local_mme_s10_teid)
      || (ue_context_p->mme_ue_s1ap_id != mme_ue_s1ap_id)) {
    h_rc = hashtable_ts_remove (mme_ue_context_p->tun10_ue_context_htbl, (const hash_key_t)ue_context_p->local_mme_s10_teid, (void **)&id);
    if (INVALID_MME_UE_S1AP_ID != mme_ue_s1ap_id) {
      h_rc = hashtable_ts_insert (mme_ue_context_p->tun10_ue_context_htbl, (const hash_key_t)local_mme_s10_teid, (void *)(uintptr_t)mme_ue_s1ap_id);
    } else {
      h_rc = HASH_TABLE_KEY_NOT_EXISTS;
    }

    if (HASH_TABLE_OK != h_rc) {
      OAILOG_TRACE (LOG_MME_APP,
          "Error could not update this ue context %p enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " local_mme_s10_teid " TEID_FMT " : %s\n",
          ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, local_mme_s10_teid, hashtable_rc_code2string(h_rc));
    }
    ue_context_p->local_mme_s10_teid = local_mme_s10_teid;
  }

  if (guti_p) {
    if ((guti_p->gummei.mme_code != ue_context_p->guti.gummei.mme_code)
      || (guti_p->gummei.mme_gid != ue_context_p->guti.gummei.mme_gid)
      || (guti_p->m_tmsi != ue_context_p->guti.m_tmsi)
      || (guti_p->gummei.plmn.mcc_digit1 != ue_context_p->guti.gummei.plmn.mcc_digit1)
      || (guti_p->gummei.plmn.mcc_digit2 != ue_context_p->guti.gummei.plmn.mcc_digit2)
      || (guti_p->gummei.plmn.mcc_digit3 != ue_context_p->guti.gummei.plmn.mcc_digit3)
      || (ue_context_p->mme_ue_s1ap_id != mme_ue_s1ap_id)) {

      // may check guti_p with a kind of instanceof()?
      h_rc = obj_hashtable_ts_remove (mme_ue_context_p->guti_ue_context_htbl, &ue_context_p->guti, sizeof (*guti_p), (void **)&id);
      if (INVALID_MME_UE_S1AP_ID != mme_ue_s1ap_id) {
        h_rc = obj_hashtable_ts_insert (mme_ue_context_p->guti_ue_context_htbl, (const void *const)guti_p, sizeof (*guti_p), (void *)(uintptr_t)mme_ue_s1ap_id);
      } else {
        h_rc = HASH_TABLE_KEY_NOT_EXISTS;
      }

      if (HASH_TABLE_OK != h_rc) {
        OAILOG_TRACE (LOG_MME_APP, "Error could not update this ue context %p enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " guti " GUTI_FMT " %s\n",
            ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, GUTI_ARG(guti_p), hashtable_rc_code2string(h_rc));
      }
      ue_context_p->guti = *guti_p;
    }
  }
  OAILOG_FUNC_OUT(LOG_MME_APP);
}

//------------------------------------------------------------------------------
void mme_ue_context_dump_coll_keys(void)
{
  bstring tmp = bfromcstr(" ");
  btrunc(tmp, 0);

  hashtable_ts_dump_content (mme_app_desc.mme_ue_contexts.imsi_ue_context_htbl, tmp);
  OAILOG_TRACE (LOG_MME_APP,"imsi_ue_context_htbl %s\n", bdata(tmp));

  btrunc(tmp, 0);
  hashtable_ts_dump_content (mme_app_desc.mme_ue_contexts.tun11_ue_context_htbl, tmp);
  OAILOG_TRACE (LOG_MME_APP,"tun11_ue_context_htbl %s\n", bdata(tmp));

  btrunc(tmp, 0);
  hashtable_ts_dump_content (mme_app_desc.mme_ue_contexts.tun10_ue_context_htbl, tmp);
  OAILOG_TRACE (LOG_MME_APP,"tun10_ue_context_htbl %s\n", bdata(tmp));

  btrunc(tmp, 0);
  hashtable_ts_dump_content (mme_app_desc.mme_ue_contexts.mme_ue_s1ap_id_ue_context_htbl, tmp);
  OAILOG_TRACE (LOG_MME_APP,"mme_ue_s1ap_id_ue_context_htbl %s\n", bdata(tmp));

  btrunc(tmp, 0);
  hashtable_ts_dump_content (mme_app_desc.mme_ue_contexts.enb_ue_s1ap_id_ue_context_htbl, tmp);
  OAILOG_TRACE (LOG_MME_APP,"enb_ue_s1ap_id_ue_context_htbl %s\n", bdata(tmp));

  btrunc(tmp, 0);
  obj_hashtable_ts_dump_content (mme_app_desc.mme_ue_contexts.guti_ue_context_htbl, tmp);
  OAILOG_TRACE (LOG_MME_APP,"guti_ue_context_htbl %s", bdata(tmp));
}

//------------------------------------------------------------------------------
int
mme_insert_ue_context (
  mme_ue_context_t * const mme_ue_context_p,
  const struct ue_context_s *const ue_context_p)
{
  hashtable_rc_t                          h_rc = HASH_TABLE_OK;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (mme_ue_context_p );
  DevAssert (ue_context_p );


  // filled ENB UE S1AP ID
  h_rc = hashtable_ts_is_key_exists (mme_ue_context_p->enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)ue_context_p->enb_s1ap_id_key);
  if (HASH_TABLE_OK == h_rc) {
    OAILOG_DEBUG (LOG_MME_APP, "This ue context %p already exists enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT "\n",
        ue_context_p, ue_context_p->enb_ue_s1ap_id);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  h_rc = hashtable_ts_insert (mme_ue_context_p->enb_ue_s1ap_id_ue_context_htbl,
                             (const hash_key_t)ue_context_p->enb_s1ap_id_key,
                              (void *)((uintptr_t)ue_context_p->mme_ue_s1ap_id));

  if (HASH_TABLE_OK != h_rc) {
    OAILOG_DEBUG (LOG_MME_APP, "Error could not register this ue context %p enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " ue_id 0x%x\n",
        ue_context_p, ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }

  if (INVALID_MME_UE_S1AP_ID != ue_context_p->mme_ue_s1ap_id) {
    h_rc = hashtable_ts_is_key_exists (mme_ue_context_p->mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)ue_context_p->mme_ue_s1ap_id);

    if (HASH_TABLE_OK == h_rc) {
      OAILOG_DEBUG (LOG_MME_APP, "This ue context %p already exists mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
          ue_context_p, ue_context_p->mme_ue_s1ap_id);
      OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
    }

    h_rc = hashtable_ts_insert (mme_ue_context_p->mme_ue_s1ap_id_ue_context_htbl,
                                (const hash_key_t)ue_context_p->mme_ue_s1ap_id,
                                (void *)ue_context_p);

    if (HASH_TABLE_OK != h_rc) {
      OAILOG_DEBUG (LOG_MME_APP, "Error could not register this ue context %p mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
          ue_context_p, ue_context_p->mme_ue_s1ap_id);
      OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
    }

    // filled IMSI
    if (ue_context_p->imsi) {
      h_rc = hashtable_ts_insert (mme_ue_context_p->imsi_ue_context_htbl,
                                  (const hash_key_t)ue_context_p->imsi,
                                  (void *)((uintptr_t)ue_context_p->mme_ue_s1ap_id));

      if (HASH_TABLE_OK != h_rc) {
        OAILOG_DEBUG (LOG_MME_APP, "Error could not register this ue context %p mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " imsi %" SCNu64 "\n",
            ue_context_p, ue_context_p->mme_ue_s1ap_id, ue_context_p->imsi);
        OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
      }
    }

    // filled S11 tun id
    if (ue_context_p->mme_s11_teid) {
      h_rc = hashtable_ts_insert (mme_ue_context_p->tun11_ue_context_htbl,
                                 (const hash_key_t)ue_context_p->mme_s11_teid,
                                 (void *)((uintptr_t)ue_context_p->mme_ue_s1ap_id));

      if (HASH_TABLE_OK != h_rc) {
        OAILOG_DEBUG (LOG_MME_APP, "Error could not register this ue context %p mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " mme_s11_teid " TEID_FMT "\n",
            ue_context_p, ue_context_p->mme_ue_s1ap_id, ue_context_p->mme_s11_teid);
        OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
      }
    }

    // filled S10 tun id
    if (ue_context_p->local_mme_s10_teid) {
      h_rc = hashtable_ts_insert (mme_ue_context_p->tun10_ue_context_htbl,
                                 (const hash_key_t)ue_context_p->local_mme_s10_teid,
                                 (void *)((uintptr_t)ue_context_p->mme_ue_s1ap_id));

      if (HASH_TABLE_OK != h_rc) {
        OAILOG_DEBUG (LOG_MME_APP, "Error could not register this ue context %p mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " local_mme_s10_teid " TEID_FMT "\n",
            ue_context_p, ue_context_p->mme_ue_s1ap_id, ue_context_p->local_mme_s10_teid);
        OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
      }
    }

    // filled guti
    if ((0 != ue_context_p->guti.gummei.mme_code) || (0 != ue_context_p->guti.gummei.mme_gid) || (0 != ue_context_p->guti.m_tmsi) || (0 != ue_context_p->guti.gummei.plmn.mcc_digit1) ||     // MCC 000 does not exist in ITU table
        (0 != ue_context_p->guti.gummei.plmn.mcc_digit2)
        || (0 != ue_context_p->guti.gummei.plmn.mcc_digit3)) {

      h_rc = obj_hashtable_ts_insert (mme_ue_context_p->guti_ue_context_htbl,
                                     (const void *const)&ue_context_p->guti,
                                     sizeof (ue_context_p->guti),
                                     (void *)((uintptr_t)ue_context_p->mme_ue_s1ap_id));

      if (HASH_TABLE_OK != h_rc) {
        OAILOG_DEBUG (LOG_MME_APP, "Error could not register this ue context %p mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " guti "GUTI_FMT"\n",
                ue_context_p, ue_context_p->mme_ue_s1ap_id, GUTI_ARG(&ue_context_p->guti));
        OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
      }
    }
  }
  OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNok);
}
/**
 * We don't need to notify anything.
 * 1- EMM and MME_APP are decoupled. That MME_APP is removed or not is/should be no problem for the EMM.
 * 2- The PDN session deletion process from the SAE-GW is now done always before the detach. That eases stuff.
 */
////------------------------------------------------------------------------------
//void mme_notify_ue_context_released (
//    mme_ue_context_t * const mme_ue_context_p,
//    struct ue_context_s *ue_context_p)
//{
//  OAILOG_FUNC_IN (LOG_MME_APP);
//  DevAssert (mme_ue_context_p);
//  DevAssert (ue_context_p);
//  // TODO HERE free resources
//
//  OAILOG_FUNC_OUT (LOG_MME_APP);
//}

//------------------------------------------------------------------------------
void mme_remove_ue_context (
  mme_ue_context_t * const mme_ue_context_p,
  struct ue_context_s *ue_context_p)
{
  unsigned int                           *id = NULL;
  hashtable_rc_t                          hash_rc = HASH_TABLE_OK;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (mme_ue_context_p);
  DevAssert (ue_context_p);
  
  // IMSI 
  if (ue_context_p->imsi) {
    hash_rc = hashtable_ts_remove (mme_ue_context_p->imsi_ue_context_htbl, (const hash_key_t)ue_context_p->imsi, (void **)&id);
    if (HASH_TABLE_OK != hash_rc)
      OAILOG_DEBUG(LOG_MME_APP, "UE context enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT ", IMSI %" SCNu64 "  not in IMSI collection",
          ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, ue_context_p->imsi);
  }
  
  // eNB UE S1P UE ID
  hash_rc = hashtable_ts_remove (mme_ue_context_p->enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)ue_context_p->enb_s1ap_id_key, (void **)&id);
  if (HASH_TABLE_OK != hash_rc)
    OAILOG_DEBUG(LOG_MME_APP, "UE context enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT ", ENB_UE_S1AP_ID not ENB_UE_S1AP_ID collection",
      ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id);
  
  // filled S11 tun id
  if (ue_context_p->mme_s11_teid) {
    hash_rc = hashtable_ts_remove (mme_ue_context_p->tun11_ue_context_htbl, (const hash_key_t)ue_context_p->mme_s11_teid, (void **)&id);
    if (HASH_TABLE_OK != hash_rc)
      OAILOG_DEBUG(LOG_MME_APP, "UE context enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT ", MME S11 TEID  " TEID_FMT "  not in S11 collection",
          ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, ue_context_p->mme_s11_teid);
  }

  // filled S10 tun id
  if (ue_context_p->local_mme_s10_teid) {
    hash_rc = hashtable_ts_remove (mme_ue_context_p->tun10_ue_context_htbl, (const hash_key_t)ue_context_p->local_mme_s10_teid, (void **)&id);
    if (HASH_TABLE_OK != hash_rc)
      OAILOG_DEBUG(LOG_MME_APP, "UE context enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT ", LOCAL_MME S10 TEID  " TEID_FMT "  not in S10 collection",
          ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id, ue_context_p->local_mme_s10_teid);
  }

  // filled guti
  if ((ue_context_p->guti.gummei.mme_code) || (ue_context_p->guti.gummei.mme_gid) || (ue_context_p->guti.m_tmsi) ||
      (ue_context_p->guti.gummei.plmn.mcc_digit1) || (ue_context_p->guti.gummei.plmn.mcc_digit2) || (ue_context_p->guti.gummei.plmn.mcc_digit3)) { // MCC 000 does not exist in ITU table
    hash_rc = obj_hashtable_ts_remove (mme_ue_context_p->guti_ue_context_htbl, (const void *const)&ue_context_p->guti, sizeof (ue_context_p->guti), (void **)&id);
    if (HASH_TABLE_OK != hash_rc)
      OAILOG_DEBUG(LOG_MME_APP, "UE context enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT ", GUTI  not in GUTI collection",
          ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id);
  }
  
  // filled NAS UE ID/ MME UE S1AP ID
  if (INVALID_MME_UE_S1AP_ID != ue_context_p->mme_ue_s1ap_id) {
    hash_rc = hashtable_ts_remove (mme_ue_context_p->mme_ue_s1ap_id_ue_context_htbl, (const hash_key_t)ue_context_p->mme_ue_s1ap_id, (void **)&ue_context_p);
    if (HASH_TABLE_OK != hash_rc)
      OAILOG_DEBUG(LOG_MME_APP, "UE context enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT ", mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " not in MME UE S1AP ID collection",
          ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id);
  }

  mme_app_ue_context_free_content(ue_context_p);
  free_wrapper ((void**) &ue_context_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//-------------------------------------------------------------------------------------------------------
void mme_ue_context_update_ue_sig_connection_state (
  mme_ue_context_t * const mme_ue_context_p,
  struct ue_context_s *ue_context_p,
  ecm_state_t new_ecm_state)
{
  // Function is used to update UE's Signaling Connection State 
  hashtable_rc_t                          hash_rc = HASH_TABLE_OK;
  unsigned int                           *id = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (mme_ue_context_p);
  DevAssert (ue_context_p);
  if (new_ecm_state == ECM_IDLE)
  {
    hash_rc = hashtable_ts_remove (mme_ue_context_p->enb_ue_s1ap_id_ue_context_htbl, (const hash_key_t)ue_context_p->enb_s1ap_id_key, (void **)&id);
    if (HASH_TABLE_OK != hash_rc) 
    {
      OAILOG_DEBUG(LOG_MME_APP, "UE context enb_ue_s1ap_ue_id_key %ld mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT ", ENB_UE_S1AP_ID_KEY could not be found",
                                  ue_context_p->enb_s1ap_id_key, ue_context_p->mme_ue_s1ap_id);
    }
    ue_context_p->enb_s1ap_id_key = INVALID_ENB_UE_S1AP_ID_KEY;

    OAILOG_DEBUG (LOG_MME_APP, "MME_APP: UE Connection State changed to IDLE. mme_ue_s1ap_id = %d\n", ue_context_p->mme_ue_s1ap_id);
    
    if (mme_config.nas_config.t3412_min > 0) {
      // Start Mobile reachability timer only if periodic TAU timer is not disabled
      if (timer_setup (ue_context_p->mobile_reachability_timer.sec, 0, TASK_MME_APP, INSTANCE_DEFAULT, TIMER_ONE_SHOT, (void *)&(ue_context_p->mme_ue_s1ap_id), &(ue_context_p->mobile_reachability_timer.id)) < 0) {
        OAILOG_ERROR (LOG_MME_APP, "Failed to start Mobile Reachability timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
        ue_context_p->mobile_reachability_timer.id = MME_APP_TIMER_INACTIVE_ID;
      } else {
        OAILOG_DEBUG (LOG_MME_APP, "Started Mobile Reachability timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
      }
    }
    if (ue_context_p->ecm_state == ECM_CONNECTED) {
      ue_context_p->ecm_state       = ECM_IDLE;
      // Update Stats
      update_mme_app_stats_connected_ue_sub();
    }

  }else if ((ue_context_p->ecm_state == ECM_IDLE) && (new_ecm_state == ECM_CONNECTED))
  {
    ue_context_p->ecm_state = ECM_CONNECTED;

    OAILOG_DEBUG (LOG_MME_APP, "MME_APP: UE Connection State changed to CONNECTED.enb_ue_s1ap_id = %d, mme_ue_s1ap_id = %d\n", ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id);
    
    // Stop Mobile reachability timer,if running 
    if (ue_context_p->mobile_reachability_timer.id != MME_APP_TIMER_INACTIVE_ID)
    {
      if (timer_remove(ue_context_p->mobile_reachability_timer.id)) {

        OAILOG_ERROR (LOG_MME_APP, "Failed to stop Mobile Reachability timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
      } 
      ue_context_p->mobile_reachability_timer.id = MME_APP_TIMER_INACTIVE_ID;
    }
    // Stop Implicit detach timer,if running 
    if (ue_context_p->implicit_detach_timer.id != MME_APP_TIMER_INACTIVE_ID)
    {
      if (timer_remove(ue_context_p->implicit_detach_timer.id)) {
        OAILOG_ERROR (LOG_MME_APP, "Failed to stop Implicit Detach timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
      } 
      ue_context_p->implicit_detach_timer.id = MME_APP_TIMER_INACTIVE_ID;
    }
    // Update Stats
    update_mme_app_stats_connected_ue_add();
  }
  return;
}
//------------------------------------------------------------------------------
bool
mme_app_dump_ue_context (
  const hash_key_t keyP,
  void *const ue_context_pP,
  void *unused_param_pP,
  void** unused_result_pP)
//------------------------------------------------------------------------------
{
  struct ue_context_s                    *const context_p = (struct ue_context_s *)ue_context_pP;
  uint8_t                                 j = 0;

  OAILOG_DEBUG (LOG_MME_APP, "-----------------------UE context %p --------------------\n", ue_context_pP);
  if (context_p) {
    OAILOG_DEBUG (LOG_MME_APP, "    - IMSI ...........: " IMSI_64_FMT "\n", context_p->imsi);
    OAILOG_DEBUG (LOG_MME_APP, "                        |  m_tmsi  | mmec | mmegid | mcc | mnc |\n");
    OAILOG_DEBUG (LOG_MME_APP, "    - GUTI............: | %08x |  %02x  |  %04x  | %03u | %03u |\n", context_p->guti.m_tmsi, context_p->guti.gummei.mme_code, context_p->guti.gummei.mme_gid,
                 /*
                  * TODO check if two or three digits MNC...
                  */
        context_p->guti.gummei.plmn.mcc_digit3 * 100 +
        context_p->guti.gummei.plmn.mcc_digit2 * 10 + context_p->guti.gummei.plmn.mcc_digit1,
        context_p->guti.gummei.plmn.mnc_digit3 * 100 + context_p->guti.gummei.plmn.mnc_digit2 * 10 + context_p->guti.gummei.plmn.mnc_digit1);
    OAILOG_DEBUG (LOG_MME_APP, "    - Authenticated ..: %s\n", (context_p->imsi_auth == IMSI_UNAUTHENTICATED) ? "FALSE" : "TRUE");
    OAILOG_DEBUG (LOG_MME_APP, "    - eNB UE s1ap ID .: %08x\n", context_p->enb_ue_s1ap_id);
    OAILOG_DEBUG (LOG_MME_APP, "    - MME UE s1ap ID .: %08x\n", context_p->mme_ue_s1ap_id);
    OAILOG_DEBUG (LOG_MME_APP, "    - MME S11 TEID ...: %08x\n", context_p->mme_s11_teid);
    OAILOG_DEBUG (LOG_MME_APP, "    - MME S10 TEID ...: %08x\n", context_p->local_mme_s10_teid);
    OAILOG_DEBUG (LOG_MME_APP, "    - SGW S11 TEID ...: %08x\n", context_p->sgw_s11_teid);
    OAILOG_DEBUG (LOG_MME_APP, "                        | mcc | mnc | cell identity |\n");
    OAILOG_DEBUG (LOG_MME_APP, "    - E-UTRAN CGI ....: | %03u | %03u | %05x.%02x    |\n",
                 context_p->e_utran_cgi.plmn.mcc_digit3 * 100 +
                 context_p->e_utran_cgi.plmn.mcc_digit2 * 10 +
                 context_p->e_utran_cgi.plmn.mcc_digit1,
                 context_p->e_utran_cgi.plmn.mnc_digit3 * 100 + context_p->e_utran_cgi.plmn.mnc_digit2 * 10 + context_p->e_utran_cgi.plmn.mnc_digit1,
                 context_p->e_utran_cgi.cell_identity.enb_id, context_p->e_utran_cgi.cell_identity.cell_id);
    /*
     * Ctime return a \n in the string
     */
    OAILOG_DEBUG (LOG_MME_APP, "    - Last acquired ..: %s", ctime (&context_p->cell_age));

    /*
     * Display UE info only if we know them
     */
    if (SUBSCRIPTION_KNOWN == context_p->subscription_known) {
      OAILOG_DEBUG (LOG_MME_APP, "    - Status .........: %s\n", (context_p->sub_status == SS_SERVICE_GRANTED) ? "Granted" : "Barred");
#define DISPLAY_BIT_MASK_PRESENT(mASK)   \
    ((context_p->access_restriction_data & mASK) ? 'X' : 'O')
      OAILOG_DEBUG (LOG_MME_APP, "    (O = allowed, X = !O) |UTRAN|GERAN|GAN|HSDPA EVO|E_UTRAN|HO TO NO 3GPP|\n");
      OAILOG_DEBUG (LOG_MME_APP,
          "    - Access restriction  |  %c  |  %c  | %c |    %c    |   %c   |      %c      |\n",
          DISPLAY_BIT_MASK_PRESENT (ARD_UTRAN_NOT_ALLOWED),
          DISPLAY_BIT_MASK_PRESENT (ARD_GERAN_NOT_ALLOWED),
          DISPLAY_BIT_MASK_PRESENT (ARD_GAN_NOT_ALLOWED), DISPLAY_BIT_MASK_PRESENT (ARD_I_HSDPA_EVO_NOT_ALLOWED), DISPLAY_BIT_MASK_PRESENT (ARD_E_UTRAN_NOT_ALLOWED), DISPLAY_BIT_MASK_PRESENT (ARD_HO_TO_NON_3GPP_NOT_ALLOWED));
      OAILOG_DEBUG (LOG_MME_APP, "    - Access Mode ....: %s\n", ACCESS_MODE_TO_STRING (context_p->access_mode));
      OAILOG_DEBUG (LOG_MME_APP, "    - MSISDN .........: %-*s\n", MSISDN_LENGTH, context_p->msisdn);
      OAILOG_DEBUG (LOG_MME_APP, "    - RAU/TAU timer ..: %u\n", context_p->rau_tau_timer);
      OAILOG_DEBUG (LOG_MME_APP, "    - IMEISV .........: %*s\n", IMEISV_DIGITS_MAX, context_p->me_identity.imeisv);
      OAILOG_DEBUG (LOG_MME_APP, "    - AMBR (bits/s)     ( Downlink |  Uplink  )\n");
      OAILOG_DEBUG (LOG_MME_APP, "        Subscribed ...: (%010" PRIu64 "|%010" PRIu64 ")\n", context_p->subscribed_ambr.br_dl, context_p->subscribed_ambr.br_ul);
      OAILOG_DEBUG (LOG_MME_APP, "        Allocated ....: (%010" PRIu64 "|%010" PRIu64 ")\n", context_p->used_ambr.br_dl, context_p->used_ambr.br_ul);

      OAILOG_DEBUG (LOG_MME_APP, "    - PDN List:\n");

      for (j = 0; j < context_p->apn_profile.nb_apns; j++) {
        struct apn_configuration_s             *apn_config_p;

        apn_config_p = &context_p->apn_profile.apn_configuration[j];
        /*
         * Default APN ?
         */
        OAILOG_DEBUG (LOG_MME_APP, "        - Default APN ...: %s\n", (apn_config_p->context_identifier == context_p->apn_profile.context_identifier)
                     ? "TRUE" : "FALSE");
        OAILOG_DEBUG (LOG_MME_APP, "        - APN ...........: %s\n", apn_config_p->service_selection);
        OAILOG_DEBUG (LOG_MME_APP, "        - AMBR (bits/s) ( Downlink |  Uplink  )\n");
        OAILOG_DEBUG (LOG_MME_APP, "                        (%010" PRIu64 "|%010" PRIu64 ")\n", apn_config_p->ambr.br_dl, apn_config_p->ambr.br_ul);
        OAILOG_DEBUG (LOG_MME_APP, "        - PDN type ......: %s\n", PDN_TYPE_TO_STRING (apn_config_p->pdn_type));
        OAILOG_DEBUG (LOG_MME_APP, "        - QOS\n");
        OAILOG_DEBUG (LOG_MME_APP, "            QCI .........: %u\n", apn_config_p->subscribed_qos.qci);
        OAILOG_DEBUG (LOG_MME_APP, "            Prio level ..: %u\n", apn_config_p->subscribed_qos.allocation_retention_priority.priority_level);
        OAILOG_DEBUG (LOG_MME_APP, "            Pre-emp vul .: %s\n", (apn_config_p->subscribed_qos.allocation_retention_priority.pre_emp_vulnerability == PRE_EMPTION_VULNERABILITY_ENABLED) ? "ENABLED" : "DISABLED");
        OAILOG_DEBUG (LOG_MME_APP, "            Pre-emp cap .: %s\n", (apn_config_p->subscribed_qos.allocation_retention_priority.pre_emp_capability == PRE_EMPTION_CAPABILITY_ENABLED) ? "ENABLED" : "DISABLED");

        if (apn_config_p->nb_ip_address == 0) {
          OAILOG_DEBUG (LOG_MME_APP, "            IP addr .....: Dynamic allocation\n");
        } else {
          int                                     i;

          OAILOG_DEBUG (LOG_MME_APP, "            IP addresses :\n");

          for (i = 0; i < apn_config_p->nb_ip_address; i++) {
            if (apn_config_p->ip_address[i].pdn_type == IPv4) {
              OAILOG_DEBUG (LOG_MME_APP, "                           [" IPV4_ADDR "]\n", IPV4_ADDR_DISPLAY_8 (apn_config_p->ip_address[i].address.ipv4_address));
            } else {
              char                                    ipv6[40];

              inet_ntop (AF_INET6, apn_config_p->ip_address[i].address.ipv6_address, ipv6, 40);
              OAILOG_DEBUG (LOG_MME_APP, "                           [%s]\n", ipv6);
            }
          }
        }
        OAILOG_DEBUG (LOG_MME_APP, "\n");
      }
      OAILOG_DEBUG (LOG_MME_APP, "    - Bearer List:\n");

      for (j = 0; j < BEARERS_PER_UE; j++) {
        bearer_context_t                       *bearer_context_p;

        bearer_context_p = &context_p->eps_bearers[j];

        if (bearer_context_p->s_gw_teid != 0) {
          OAILOG_DEBUG (LOG_MME_APP, "        Bearer id .......: %02u\n", j);
          OAILOG_DEBUG (LOG_MME_APP, "        S-GW TEID (UP)...: %08x\n", bearer_context_p->s_gw_teid);
          OAILOG_DEBUG (LOG_MME_APP, "        P-GW TEID (UP)...: %08x\n", bearer_context_p->p_gw_teid);
          OAILOG_DEBUG (LOG_MME_APP, "        QCI .............: %u\n", bearer_context_p->qci);
          OAILOG_DEBUG (LOG_MME_APP, "        Priority level ..: %u\n", bearer_context_p->prio_level);
          OAILOG_DEBUG (LOG_MME_APP, "        Pre-emp vul .....: %s\n", (bearer_context_p->pre_emp_vulnerability == PRE_EMPTION_VULNERABILITY_ENABLED) ? "ENABLED" : "DISABLED");
          OAILOG_DEBUG (LOG_MME_APP, "        Pre-emp cap .....: %s\n", (bearer_context_p->pre_emp_capability == PRE_EMPTION_CAPABILITY_ENABLED) ? "ENABLED" : "DISABLED");
        }
      }
    }
    OAILOG_DEBUG (LOG_MME_APP, "---------------------------------------------------------\n");
    return false;
  }
  OAILOG_DEBUG (LOG_MME_APP, "---------------------------------------------------------\n");
  return true;
}


//------------------------------------------------------------------------------
void
mme_app_dump_ue_contexts (
  const mme_ue_context_t * const mme_ue_context_p)
//------------------------------------------------------------------------------
{
  hashtable_ts_apply_callback_on_elements (mme_ue_context_p->mme_ue_s1ap_id_ue_context_htbl, mme_app_dump_ue_context, NULL, NULL);
}


void
mme_app_handle_s1ap_ue_context_release_req (
  const itti_s1ap_ue_context_release_req_t const *s1ap_ue_context_release_req)
//------------------------------------------------------------------------------
{
  _mme_app_handle_s1ap_ue_context_release(s1ap_ue_context_release_req->mme_ue_s1ap_id,
                                          s1ap_ue_context_release_req->enb_ue_s1ap_id,
                                          s1ap_ue_context_release_req->enb_id,
                                          S1AP_RADIO_EUTRAN_GENERATED_REASON);
}

//------------------------------------------------------------------------------
void
mme_app_handle_enb_deregister_ind(const itti_s1ap_eNB_deregistered_ind_t const * eNB_deregistered_ind) {
  for (int i = 0; i < eNB_deregistered_ind->nb_ue_to_deregister; i++) {
    _mme_app_handle_s1ap_ue_context_release(eNB_deregistered_ind->mme_ue_s1ap_id[i],
                                            eNB_deregistered_ind->enb_ue_s1ap_id[i],
                                            eNB_deregistered_ind->enb_id,
                                            S1AP_SCTP_SHUTDOWN_OR_RESET);
  }
} 

//------------------------------------------------------------------------------
void 
mme_app_handle_enb_reset_req (const itti_s1ap_enb_initiated_reset_req_t const * enb_reset_req) 
{ 
  
  MessageDef *message_p;
  OAILOG_DEBUG (LOG_MME_APP, " eNB Reset request received. eNB id = %d, reset_type  %d \n ", enb_reset_req->enb_id, enb_reset_req->s1ap_reset_type); 
  DevAssert (enb_reset_req->ue_to_reset_list != NULL);
  if (enb_reset_req->s1ap_reset_type == RESET_ALL) {
  // Full Reset. Trigger UE Context release release for all the connected UEs.
    for (int i = 0; i < enb_reset_req->num_ue; i++) {
      _mme_app_handle_s1ap_ue_context_release(*(enb_reset_req->ue_to_reset_list[i].mme_ue_s1ap_id),
                                            *(enb_reset_req->ue_to_reset_list[i].enb_ue_s1ap_id),
                                            enb_reset_req->enb_id, 
                                            S1AP_SCTP_SHUTDOWN_OR_RESET);
    }  
      
  } else { // Partial Reset
    for (int i = 0; i < enb_reset_req->num_ue; i++) {
      if (enb_reset_req->ue_to_reset_list[i].mme_ue_s1ap_id == NULL && 
                          enb_reset_req->ue_to_reset_list[i].enb_ue_s1ap_id == NULL) 
        continue;
      else 
        _mme_app_handle_s1ap_ue_context_release(*(enb_reset_req->ue_to_reset_list[i].mme_ue_s1ap_id),
                                            *(enb_reset_req->ue_to_reset_list[i].enb_ue_s1ap_id),
                                            enb_reset_req->enb_id, 
                                            S1AP_SCTP_SHUTDOWN_OR_RESET);
    } 
      
  }
  // Send Reset Ack to S1AP module

  message_p = itti_alloc_new_message (TASK_MME_APP, S1AP_ENB_INITIATED_RESET_ACK);
  DevAssert (message_p != NULL);
  memset ((void *)&message_p->ittiMsg.s1ap_enb_initiated_reset_ack, 0, sizeof (itti_s1ap_enb_initiated_reset_ack_t));
  S1AP_ENB_INITIATED_RESET_ACK (message_p).s1ap_reset_type = enb_reset_req->s1ap_reset_type;
  S1AP_ENB_INITIATED_RESET_ACK (message_p).sctp_assoc_id = enb_reset_req->sctp_assoc_id;
  S1AP_ENB_INITIATED_RESET_ACK (message_p).sctp_stream_id = enb_reset_req->sctp_stream_id;
  S1AP_ENB_INITIATED_RESET_ACK (message_p).num_ue = enb_reset_req->num_ue;
  /* 
   * Send the same ue_reset_list to S1AP module to be used to construct S1AP Reset Ack message. This would be freed by
   * S1AP module.
   */
  
  S1AP_ENB_INITIATED_RESET_ACK (message_p).ue_to_reset_list = enb_reset_req->ue_to_reset_list; 
  itti_send_msg_to_task (TASK_S1AP, INSTANCE_DEFAULT, message_p);
  OAILOG_DEBUG (LOG_MME_APP, " Reset Ack sent to S1AP. eNB id = %d, reset_type  %d \n ", enb_reset_req->enb_id, enb_reset_req->s1ap_reset_type); 
  OAILOG_FUNC_OUT (LOG_MME_APP);
} 

//------------------------------------------------------------------------------
/*
   From GPP TS 23.401 version 11.11.0 Release 11, section 5.3.5 S1 release procedure, point 6:
   The MME deletes any eNodeB related information ("eNodeB Address in Use for S1-MME" and "eNB UE S1AP
   ID") from the UE's MME context, but, retains the rest of the UE's MME context including the S-GW's S1-U
   configuration information (address and TEIDs). All non-GBR EPS bearers established for the UE are preserved
   in the MME and in the Serving GW.
   If the cause of S1 release is because of User is inactivity, Inter-RAT Redirection, the MME shall preserve the
   GBR bearers. If the cause of S1 release is because of CS Fallback triggered, further details about bearer handling
   are described in TS 23.272 [58]. Otherwise, e.g. Radio Connection With UE Lost, S1 signalling connection lost,
   eNodeB failure the MME shall trigger the MME Initiated Dedicated Bearer Deactivation procedure
   (clause 5.4.4.2) for the GBR bearer(s) of the UE after the S1 Release procedure is completed.
*/
//------------------------------------------------------------------------------
void
mme_app_handle_s1ap_ue_context_release_complete (
  const itti_s1ap_ue_context_release_complete_t const
  *s1ap_ue_context_release_complete)
//------------------------------------------------------------------------------
{
  struct ue_context_s                    *ue_context_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, s1ap_ue_context_release_complete->mme_ue_s1ap_id);

  if (!ue_context_p) {
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "0 S1AP_UE_CONTEXT_RELEASE_COMPLETE Unknown mme_ue_s1ap_id 0x%06" PRIX32 " ", s1ap_ue_context_release_complete->mme_ue_s1ap_id);
    OAILOG_ERROR (LOG_MME_APP, "UE context doesn't exist for enb_ue_s1ap_ue_id "ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n",
        s1ap_ue_context_release_complete->enb_ue_s1ap_id, s1ap_ue_context_release_complete->mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }

  if (ue_context_p->mm_state == UE_UNREGISTERED) {
    /** We don't need to check anymore if the SAE-GW session was purged. If the UE is DEREGISTERD, the session should already be deleted. */
    OAILOG_DEBUG (LOG_MME_APP, "Deleting UE context associated in MME for mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n ", s1ap_ue_context_release_complete->mme_ue_s1ap_id);
    /**
     * This will not remove the EMM context. MME_APP does not remove the EMM context. The detach procedure is already activated.
     * This removed the MME_APP context only.
     * If the UE is DEREGISTERED, we check the s1cause.
     */
    // Move the UE to Idle state
    // todo: this should always happen before signaling connection is ECM_IDLE..
    mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts, ue_context_p,ECM_IDLE);

    mme_remove_ue_context(&mme_app_desc.mme_ue_contexts, ue_context_p);
    update_mme_app_stats_connected_ue_sub();
  }  
  else {
    /**
     * Check if it is an handover cancellation.
     * If so send a cancel_ack to the source MME and leave the UE state as connected (remove the S1 cause).
     * Else, set the connection to ECM_IDLE.
     */
    if(ue_context_p->ue_context_rel_cause == S1AP_HANDOVER_CANCELLED){
      /** Don't change the signaling connection state. */
      mme_app_send_s1ap_handover_cancel_acknowledge(ue_context_p->mme_ue_s1ap_id, s1ap_ue_context_release_complete->enb_ue_s1ap_id, s1ap_ue_context_release_complete->sctp_assoc_id);
      OAILOG_DEBUG(LOG_MME_APP, "Successfully terminated the resources in the target eNB %d for UE with mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " (REGISTERED). "
          "Sending HO-CANCELLATION-ACK back to the source eNB. \n", s1ap_ue_context_release_complete->enb_id, ue_context_p->mme_ue_s1ap_id, ue_context_p->mm_state);
    }else{
      // Update keys and ECM state
      // todo: when this could happen, UE context release for an UE without any pre
      mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts, ue_context_p,ECM_IDLE);
    }
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//-------------------------------------------------------------------------------------------------------
void mme_ue_context_update_ue_emm_state (
  mme_ue_s1ap_id_t       mme_ue_s1ap_id, mm_state_t  new_mm_state)
{
  // Function is used to update UE's mobility management State- Registered/Un-Registered 

  /** Only checks for state changes. */
  struct ue_context_s                    *ue_context_p = NULL;

  OAILOG_FUNC_IN (LOG_MME_APP);
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, mme_ue_s1ap_id);
  if (ue_context_p == NULL) {
    OAILOG_CRITICAL (LOG_MME_APP, "**** Abnormal - UE context is null.****\n");
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  if (ue_context_p->mm_state == UE_UNREGISTERED && (new_mm_state == UE_REGISTERED))
  {

    /** Call the new callback function for new registration. */
    // todo: use the old_state
    if(_mme_ue_callbacks[ue_context_p->mm_state]){
      OAILOG_DEBUG(LOG_MME_APP, "Calling the UE callback function in MME_APP mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " for state %d \n", mme_ue_s1ap_id, ue_context_p->mm_state);
      _mme_ue_callbacks[ue_context_p->mm_state](mme_ue_s1ap_id);
      OAILOG_DEBUG(LOG_MME_APP, "Successfully executed UE callback function in MME_APP mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " for state %d \n", mme_ue_s1ap_id, ue_context_p->mm_state);
    }

    ue_context_p->mm_state = new_mm_state;

    // Update Stats
    update_mme_app_stats_attached_ue_add();

  } else if ((ue_context_p->mm_state == UE_HANDOVER_TAU) && (new_mm_state == UE_REGISTERED))
  {
    
    /** Call the new callback function for new registration. */
    // todo: use the old_state
    if(_mme_ue_callbacks[ue_context_p->mm_state]){
      OAILOG_DEBUG(LOG_MME_APP, "Calling the UE callback function in MME_APP mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " for state %d \n", mme_ue_s1ap_id, ue_context_p->mm_state);
      _mme_ue_callbacks[ue_context_p->mm_state](mme_ue_s1ap_id);
      OAILOG_DEBUG(LOG_MME_APP, "Successfully executed UE callback function in MME_APP mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " for state %d \n", mme_ue_s1ap_id, ue_context_p->mm_state);
    }

    /** Update to the new state. Will use the handover_information element as flag. */
    ue_context_p->mm_state = new_mm_state;

    OAILOG_DEBUG(LOG_MME_APP, "UE with mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " entering REGISTERED state from HANDOVER state. \n");

    // Update Stats --> also for handover!! (todo: new statistics for handover UEs?)
    update_mme_app_stats_attached_ue_add();

  }
  else if ((ue_context_p->mm_state == UE_REGISTERED) && (new_mm_state == UE_UNREGISTERED))
  {

    /** Call the new callback function for deregistration. */
    // todo: use the old_state
    if(_mme_ue_callbacks[ue_context_p->mm_state]){
      OAILOG_DEBUG(LOG_MME_APP, "Calling the UE callback function in MME_APP mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " for state %d \n", mme_ue_s1ap_id, ue_context_p->mm_state);
      _mme_ue_callbacks[ue_context_p->mm_state](mme_ue_s1ap_id);
      OAILOG_DEBUG(LOG_MME_APP, "Successfully executed UE callback function in MME_APP mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " for state %d \n", mme_ue_s1ap_id, ue_context_p->mm_state);
    }

    ue_context_p->mm_state = new_mm_state;
    
    // Update Stats
    update_mme_app_stats_attached_ue_sub();
  }else{
    OAILOG_CRITICAL(LOG_MME_APP, "**** Abnormal - No handler for state transition of UE with mme_ue_s1ap_ue_id "MME_UE_S1AP_ID_FMT " "
        "entering %d state from %d state. ****\n", ue_context_p->mm_state, new_mm_state);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  // todo: transition to/from UE_HANDOVER state!
  OAILOG_FUNC_OUT (LOG_MME_APP);
}


//------------------------------------------------------------------------------
static void
_mme_app_handle_s1ap_ue_context_release (const mme_ue_s1ap_id_t mme_ue_s1ap_id,
                                         const enb_ue_s1ap_id_t enb_ue_s1ap_id,
                                         uint32_t  enb_id,           
                                         enum s1cause cause)
//------------------------------------------------------------------------------
{
  struct ue_context_s                    *ue_context_p = NULL;
  enb_s1ap_id_key_t                       enb_s1ap_id_key = INVALID_ENB_UE_S1AP_ID_KEY;
  MessageDef *message_p;

  OAILOG_FUNC_IN (LOG_MME_APP);
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, mme_ue_s1ap_id);
  if (!ue_context_p) {
    /* 
     * Use enb_ue_s1ap_id_key to get the UE context - In case MME APP could not update S1AP with valid mme_ue_s1ap_id
     * before context release is triggered from s1ap.
     */
    MME_APP_ENB_S1AP_ID_KEY(enb_s1ap_id_key, enb_id, enb_ue_s1ap_id);
    ue_context_p = mme_ue_context_exists_enb_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, enb_s1ap_id_key);

    OAILOG_WARNING (LOG_MME_APP, "Invalid mme_ue_s1ap_ue_id " 
      MME_UE_S1AP_ID_FMT " received from S1AP. Using enb_s1ap_id_key %ld to get the context \n", mme_ue_s1ap_id, enb_s1ap_id_key);
  }
  if (!ue_context_p) {
    OAILOG_ERROR (LOG_MME_APP, " UE Context Release Req: UE context doesn't exist for enb_ue_s1ap_ue_id "
        ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id, mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  // Set the UE context release cause in UE context. This is used while constructing UE Context Release Command
  ue_context_p->ue_context_rel_cause = cause;

  if (ue_context_p->ecm_state == ECM_IDLE) {
    // This case could happen during sctp reset, before the UE could move to ECM_CONNECTED
    // calling below function to set the enb_s1ap_id_key to invalid
    if (ue_context_p->ue_context_rel_cause == S1AP_SCTP_SHUTDOWN_OR_RESET) {
      mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts, ue_context_p, ECM_IDLE);
      mme_app_itti_ue_context_release(ue_context_p, ue_context_p->ue_context_rel_cause);
      OAILOG_WARNING (LOG_MME_APP, "UE Conetext Release Reqeust:Cause SCTP RESET/SHUTDOWN. UE state: IDLE. mme_ue_s1ap_id = %d, enb_ue_s1ap_id = %d Action -- Handle the message\n ", 
                                  ue_context_p->mme_ue_s1ap_id, ue_context_p->enb_ue_s1ap_id);
    }
    OAILOG_ERROR (LOG_MME_APP, "ERROR: UE Context Release Request: UE state : IDLE. enb_ue_s1ap_ue_id " 
    ENB_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " Action--- Ignore the message\n", ue_context_p->enb_ue_s1ap_id, ue_context_p->mme_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  // Stop Initial context setup process guard timer,if running 
  if (ue_context_p->initial_context_setup_rsp_timer.id != MME_APP_TIMER_INACTIVE_ID) {
    if (timer_remove(ue_context_p->initial_context_setup_rsp_timer.id)) {
      OAILOG_ERROR (LOG_MME_APP, "Failed to stop Initial Context Setup Rsp timer for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
    } 
    ue_context_p->initial_context_setup_rsp_timer.id = MME_APP_TIMER_INACTIVE_ID;
    // Setting UE context release cause as Initial context setup failure
    ue_context_p->ue_context_rel_cause = S1AP_INITIAL_CONTEXT_SETUP_FAILED;
  }
  if (ue_context_p->mm_state == UE_UNREGISTERED) {
    // Initiate Implicit Detach for the UE
    message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
    DevAssert (message_p != NULL);
    message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
    itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  } else {
    // release S1-U tunnel mapping in S_GW for all the active bearers for the UE
    mme_app_send_s11_release_access_bearers_req (ue_context_p);
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//-------------------------------------------------------------------------
static
int mme_app_set_pdn_connections(struct mme_ue_eps_pdn_connections_s * pdn_connections, struct ue_context_s * ue_context_p){
  int                           rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);

  DevAssert(ue_context_p);
  DevAssert(pdn_connections);

  /** Set the PDN connections. */
  pdn_connections->num_pdn_connections = 1;
  memcpy (pdn_connections->pdn_connection[0].apn, ue_context_p->apn_profile.apn_configuration[0].service_selection, ue_context_p->apn_profile.apn_configuration[0].service_selection_length);
  pdn_connections->pdn_connection[0].ip_address.present = 0x0;
  memset (pdn_connections->pdn_connection[0].ip_address.address.v4, 0, 4);
  //    memset (pdn_connections->pdn_connection[0].ipv6_address, 0, 16);
  memcpy (pdn_connections->pdn_connection[0].ip_address.address.v4, ue_context_p->paa.ipv4_address, 4);
  pdn_connections->pdn_connection[0].linked_eps_bearer_id = 5; //todo: multiple bearers/pdns

  /** Set a blank PGW-S5/S8-FTEID. */
  OAI_GCC_DIAG_OFF(pointer-to-int-cast);
  pdn_connections->pdn_connection[0].pgw_address_for_cp.teid = (teid_t) 0x000000; /**< Which does not matter. */
  OAI_GCC_DIAG_ON(pointer-to-int-cast);
  pdn_connections->pdn_connection[0].pgw_address_for_cp.interface_type = S5_S8_PGW_GTP_C;
  mme_config_read_lock (&mme_config);
  pdn_connections->pdn_connection[0].pgw_address_for_cp.ipv4_address = mme_config.ipv4.s11;
  mme_config_unlock (&mme_config);
  pdn_connections->pdn_connection[0].pgw_address_for_cp.ipv4 = 1;
  /** APN Restriction. */
  pdn_connections->pdn_connection[0].apn_restriction = 0;
  /** AMBR */
  pdn_connections->pdn_connection[0].apn_ambr.br_ul = 5000000;
  pdn_connections->pdn_connection[0].apn_ambr.br_dl = 10000000;
  /** Bearer Context. */
  pdn_connections->pdn_connection[0].bearer_context.eps_bearer_id = 5;
  OAI_GCC_DIAG_OFF(pointer-to-int-cast);
  pdn_connections->pdn_connection[0].bearer_context.s1u_sgw_fteid.teid = (teid_t) 0x000000; /**< Which does not matter. */
  OAI_GCC_DIAG_ON(pointer-to-int-cast);
  pdn_connections->pdn_connection[0].bearer_context.s1u_sgw_fteid.interface_type = S1_U_SGW_GTP_U;
  mme_config_read_lock (&mme_config);
  pdn_connections->pdn_connection[0].bearer_context.s1u_sgw_fteid.ipv4_address = mme_config.ipv4.s11;
  mme_config_unlock (&mme_config);
  pdn_connections->pdn_connection[0].bearer_context.s1u_sgw_fteid.ipv4 = 1;
  /** Set the bearer context. */
  pdn_connections->pdn_connection[0].bearer_context.bearer_level_qos.gbr.br_ul = 0;
  pdn_connections->pdn_connection[0].bearer_context.bearer_level_qos.gbr.br_dl = 0;
  pdn_connections->pdn_connection[0].bearer_context.bearer_level_qos.mbr.br_ul = 0;
  pdn_connections->pdn_connection[0].bearer_context.bearer_level_qos.mbr.br_dl = 0;
  pdn_connections->pdn_connection[0].bearer_context.bearer_level_qos.qci = 9; ue_context_p->apn_profile.apn_configuration[0].subscribed_qos.qci;
  pdn_connections->pdn_connection[0].bearer_context.bearer_level_qos.pvi = 0; ue_context_p->apn_profile.apn_configuration[0].subscribed_qos.allocation_retention_priority.pre_emp_vulnerability;
  pdn_connections->pdn_connection[0].bearer_context.bearer_level_qos.pci = 0; ue_context_p->apn_profile.apn_configuration[0].subscribed_qos.allocation_retention_priority.pre_emp_capability;
  pdn_connections->pdn_connection[0].bearer_context.bearer_level_qos.pl  = ue_context_p->apn_profile.apn_configuration[0].subscribed_qos.allocation_retention_priority.priority_level;

  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}

//----------------------------------------------------------------------------------------------------------
static
int mme_app_set_ue_eps_mm_context(mm_context_eps_t * ue_eps_mme_context_p, struct ue_context_s *ue_context_p, emm_data_context_t *ue_nas_ctx) {

  int                           rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);

  DevAssert(ue_context_p);
  DevAssert(ue_eps_mme_context_p);

  /** Add the MM_Context from the security context. */
  ue_eps_mme_context_p->ksi  = ue_nas_ctx->ue_ksi;
  /** Used NAS Integrity Algorithm. */
  ue_eps_mme_context_p->nas_int_alg  = ue_nas_ctx->_security.selected_algorithms.integrity & 0x07;
  ue_eps_mme_context_p->nas_cipher_alg  = ue_nas_ctx->_security.selected_algorithms.encryption & 0x0F;
  // nas_dl_count --> copy int to byte!
  ue_eps_mme_context_p->nas_ul_count  = ue_nas_ctx->_security.ul_count;
  ue_eps_mme_context_p->nas_dl_count  = ue_nas_ctx->_security.dl_count;
  /** Add the NCC. */
  ue_eps_mme_context_p->ncc       = ue_nas_ctx->_security.ncc;
  /** Add the K_ASME. */
  // todo: copy k_asme
  memset(ue_eps_mme_context_p->k_asme, 0, 32);
  memcpy(ue_eps_mme_context_p->k_asme, ue_nas_ctx->_vector[ue_nas_ctx->_security.vector_index].kasme, 32);
  /** Add the NH key. */
  memset(ue_eps_mme_context_p->nh, 0, 32);
  memcpy(ue_eps_mme_context_p->nh, ue_nas_ctx->_vector[ue_nas_ctx->_security.vector_index].nh_conj, 32);

  // Add the UE Network Capability.
  ue_eps_mme_context_p->ue_nc.eea = ue_nas_ctx->eea;
  ue_eps_mme_context_p->ue_nc.eia = ue_nas_ctx->eia; /*<< Check that they exist.*/
  ue_eps_mme_context_p->ue_nc_length = 2;
  if(ue_nas_ctx->_security.capability.umts_integrity && ue_nas_ctx->_security.capability.umts_encryption){
    OAILOG_DEBUG(LOG_MME_APP, "Adding UMTS encryption and UMTS integrity alghorithms into the forward relocation request.");
    ue_eps_mme_context_p->ue_nc_length +=2;
    ue_eps_mme_context_p->ue_nc.umts_present = true;
    ue_eps_mme_context_p->ue_nc.uia = ue_nas_ctx->_security.capability.umts_integrity;
    ue_eps_mme_context_p->ue_nc.uea = ue_nas_ctx->_security.capability.umts_encryption;
  }
  // todo: gprs/misc!?
  /** Set the length of the MS network capability to 0. */
  ue_eps_mme_context_p->ms_nc_length = 0;
  ue_eps_mme_context_p->mei_length   = 0;
  ue_eps_mme_context_p->vdp_lenth    = 0;
  // todo: access restriction
  ue_eps_mme_context_p->access_restriction_flags        = ue_context_p->access_restriction_data & 0xFF;

  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);
}


static
void mme_app_handle_pending_pdn_connectivity_information(ue_context_t *ue_context_p, pdn_connection_t * pdn_conn_pP){
  OAILOG_FUNC_IN (LOG_MME_APP);

  int                     rc = RETURNok;
  /** Get and handle the PDN Connection element as pending PDN connection element. */

  DevAssert(ue_context_p);
  DevAssert(pdn_conn_pP);

  /** Set the pending PDN information in the UE context. */
  ue_context_p->pending_pdn_connectivity_req_apn = bfromcstr(pdn_conn_pP->apn);
  DevAssert (ue_context_p->pending_pdn_connectivity_req_apn);

  // copy
  if (ue_context_p->pending_pdn_connectivity_req_pdn_addr) {
    bdestroy (ue_context_p->pending_pdn_connectivity_req_pdn_addr);
  }
  ue_context_p->pending_pdn_connectivity_req_pdn_type = pdn_conn_pP->pdn_type; /**< Set PDN type. */
  /** Decouple the pdn_addr. */
  /** Copy the value into the UE context. */
  memset (ue_context_p->paa.ipv4_address, 0, 4);
  // memcpy (ue_context_p->paa.ipv4_address, pdn_conn_pP->ip_address.address.v4, 4);
  // todo: deallocating the current one?
  ue_context_p->pending_pdn_connectivity_req_pdn_addr = blk2bstr(pdn_conn_pP->ip_address.address.v4, 4);

  // todo: need to erase the IPv4 ?! pdn_conn_pP->pdn_addr = NULL;
  // memset (pdn_conn_pP->ip_address.address.v4, 0, 4);

  /** Set PTI to invalid. */
  ue_context_p->pending_pdn_connectivity_req_pti = PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED;
  ue_context_p->pending_pdn_connectivity_req_ue_id = ue_context_p->mme_ue_s1ap_id;
  // todo: add PCO's later..
  // copy_protocol_configuration_options (&ue_context_p->pending_pdn_connectivity_req_pco, &nas_pdn_connectivity_req_pP->pco);
  // clear_protocol_configuration_options(&nas_pdn_connectivity_req_pP->pco);
  //#define TEMPORARY_DEBUG 1
  //#if TEMPORARY_DEBUG
  // bstring b = protocol_configuration_options_to_xml(&ue_context_p->pending_pdn_connectivity_req_pco);
  // OAILOG_DEBUG (LOG_MME_APP, "PCO %s\n", bdata(b));
  // bdestroy(b);
  //#endif

  /** Set the pending qos. */
  // todo: is this subscribed qos or bearer qos? Probably, this is wrong..
  ue_context_p->pending_pdn_connectivity_req_qos.gbrDL = pdn_conn_pP->bearer_context.bearer_level_qos.gbr.br_dl;
  ue_context_p->pending_pdn_connectivity_req_qos.gbrUL = pdn_conn_pP->bearer_context.bearer_level_qos.gbr.br_ul;
  ue_context_p->pending_pdn_connectivity_req_qos.mbrDL = pdn_conn_pP->bearer_context.bearer_level_qos.mbr.br_dl;
  ue_context_p->pending_pdn_connectivity_req_qos.mbrUL = pdn_conn_pP->bearer_context.bearer_level_qos.mbr.br_ul;
  /** Set ARP. */
  ue_context_p->pending_pdn_connectivity_req_qos.pci = pdn_conn_pP->bearer_context.bearer_level_qos.pci;
  ue_context_p->pending_pdn_connectivity_req_qos.pvi = pdn_conn_pP->bearer_context.bearer_level_qos.pvi;
  ue_context_p->pending_pdn_connectivity_req_qos.pl = pdn_conn_pP->bearer_context.bearer_level_qos.pl;
  /** Set QCI. */
  ue_context_p->pending_pdn_connectivity_req_qos.qci = 9; // todo: decode bearer context in pdn_conn pdn_conn_pP->bearer_context.bearer_level_qos.qci;

  /** Set the pending EBI. */
  ue_context_p->pending_pdn_connectivity_req_ebi = pdn_conn_pP->linked_eps_bearer_id;

  ue_context_p->pending_pdn_connectivity_req_request_type = 2;
  // todo: (misusing) this field.. since we don't have a default_apn_config (from HSS via ULR) yet..

  /** Send the APN_AMBR. */
  ue_context_p->subscribed_ambr.br_dl = pdn_conn_pP->apn_ambr.br_dl;
  ue_context_p->subscribed_ambr.br_ul = pdn_conn_pP->apn_ambr.br_dl;

  /** APN Restriction. */
  ue_context_p->pending_pdn_connectivity_req_apn_restriction = pdn_conn_pP->apn_restriction;

  OAILOG_INFO (LOG_MME_APP, "Successfully updated the MME_APP UE context with the pendign pdn information for UE id  %d. \n", ue_context_p->mme_ue_s1ap_id);
  OAILOG_FUNC_IN (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_nas_ue_context_req(const itti_nas_ue_context_req_t * const nas_ue_context_request_pP){
  /**
   * Send a context request for the given UE to the specified MME with the given last visited TAI.
   */
  MessageDef            *message_p;
  struct ue_context_s   *ue_context_p = NULL;

  /**
   * Check that the UE does exist.
   * This should come through an initial request for attach/TAU.
   * MME_APP UE context is created and is in UE_UNREGISTERED mode.
   */
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, nas_ue_context_request_pP->ue_id);
  if (ue_context_p == NULL) { /**< Always think separate of EMM_DATA context and the rest. Could mean or not mean, that no EMM_DATA exists. */
    OAILOG_ERROR(LOG_MME_APP, "An UE MME context does not exist for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " and guti: " GUTI_FMT ". \n",
        nas_ue_context_request_pP->ue_id, GUTI_ARG(&nas_ue_context_request_pP->old_guti));
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "An UE MME context does not exist for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " and guti: " GUTI_FMT ". \n",
        nas_ue_context_request_pP->ue_id, GUTI_ARG(&nas_ue_context_request_pP->old_guti));
    /** This should always clear the allocated UE context resources, if there are any. We do not clear them directly, but only inform NAS/EMM layer of what happened. */
    _mme_app_send_nas_ue_context_response_err(nas_ue_context_request_pP->ue_id, SYSTEM_FAILURE);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }

  /**
   * Check that the UE is in EMM_UNREGISTERED state.
   */
  if(ue_context_p->mm_state != UE_UNREGISTERED){
    OAILOG_ERROR(LOG_MME_APP, "UE MME context is not in UE_UNREGISTERED state but instead in %d for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " and guti: " GUTI_FMT ". \n",
        ue_context_p->mm_state, nas_ue_context_request_pP->ue_id, GUTI_ARG(&nas_ue_context_request_pP->old_guti));
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "UE MME context is not in UE_UNREGISTERED state but instead in %d for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " and guti: " GUTI_FMT ". \n",
        ue_context_p->mm_state, nas_ue_context_request_pP->ue_id, GUTI_ARG(&nas_ue_context_request_pP->old_guti));
    /** This should always clear the allocated UE context resources. */
    _mme_app_send_nas_ue_context_response_err(nas_ue_context_request_pP->ue_id, SYSTEM_FAILURE);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }

  // todo: currently only just a single MME is allowed.
  /** Only use origin TAI to find the source-MME. */
  if(!TAIS_ARE_EQUAL(nas_ue_context_request_pP->originating_tai, mme_config.nghMme.nghMme[0].ngh_mme_tai)){
    OAILOG_DEBUG (LOG_MME_APP, "The selected TAI " TAI_FMT " is not configured as an S10 MME neighbor. "
        "Not proceeding with the NAS UE context request for mme_ue_s1ap_id of UE: "MME_UE_S1AP_ID_FMT ". \n",
        nas_ue_context_request_pP->originating_tai, nas_ue_context_request_pP->ue_id);
    /** Send a nas_context_reject back. */
    _mme_app_send_nas_ue_context_response_err(nas_ue_context_request_pP->ue_id, RELOCATION_FAILURE);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }

  /**
   * No temporary handover target information needed to be allocated.
   * Also the MME_APP UE context will not be changed (incl. MME_APP UE state).
   */
  message_p = itti_alloc_new_message (TASK_MME_APP, S10_CONTEXT_REQUEST);
  DevAssert (message_p != NULL);
  itti_s10_context_request_t *s10_context_request_p = &message_p->ittiMsg.s10_context_request;
  memset ((void*)s10_context_request_p, 0, sizeof (itti_s10_context_request_t));

  /** Always set the counterpart to 0. */
  s10_context_request_p->teid = 0;
  /** Prepare the S10 message and initialize the S10 GTPv2c tunnel endpoints. */
  // todo: search the list of neighboring MMEs for the correct origin TAI
  s10_context_request_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr;
  /** Set the Target MME_S10_FTEID (this MME's S10 Tunnel endpoint). */
  OAI_GCC_DIAG_OFF(pointer-to-int-cast);
  s10_context_request_p->s10_target_mme_teid.teid = (teid_t) ue_context_p;
  OAI_GCC_DIAG_ON(pointer-to-int-cast);
  s10_context_request_p->s10_target_mme_teid.interface_type = S10_MME_GTP_C;
  mme_config_read_lock (&mme_config);
  s10_context_request_p->s10_target_mme_teid.ipv4_address = mme_config.ipv4.s10;
  mme_config_unlock (&mme_config);
  s10_context_request_p->s10_target_mme_teid.ipv4 = 1;

  /** Update the MME_APP UE context with the new S10 local TEID to find it from the S10 answer. */
  mme_ue_context_update_coll_keys (&mme_app_desc.mme_ue_contexts, ue_context_p,
      ue_context_p->enb_s1ap_id_key,
      ue_context_p->mme_ue_s1ap_id,
      INVALID_IMSI64,
      ue_context_p->mme_s11_teid,       /**< Won't be changed. */
      s10_context_request_p->s10_target_mme_teid.teid,
      NULL); /**< Don't register with the old GUTI. */

  /** Set the Complete Request Message. */
  s10_context_request_p->complete_request_message.request_type     = nas_ue_context_request_pP->request_type;
  if (!s10_context_request_p->complete_request_message.request_value) {
    OAILOG_ERROR(LOG_MME_APP, "No complete request exists for TAU of UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " and guti: " GUTI_FMT ". \n",
        nas_ue_context_request_pP->ue_id, GUTI_ARG(&nas_ue_context_request_pP->old_guti));
    MSC_LOG_EVENT (MSC_MMEAPP_MME, "No complete request exists for TAU of UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " and guti: " GUTI_FMT ". \n",
        nas_ue_context_request_pP->ue_id, GUTI_ARG(&nas_ue_context_request_pP->old_guti));
    _mme_app_send_nas_ue_context_response_err(nas_ue_context_request_pP->ue_id, REQUEST_REJECTED);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }

  /** Set the RAT_TYPE. */
  s10_context_request_p->rat_type = nas_ue_context_request_pP->rat_type;
  /** Set the GUTI. */
  memset((void*)&s10_context_request_p->old_guti, 0, sizeof(guti_t));
  memcpy((void*)&s10_context_request_p->old_guti, (void*)&nas_ue_context_request_pP->old_guti, sizeof(guti_t));
  /** Serving Network. */
  s10_context_request_p->serving_network.mcc[0] = ue_context_p->e_utran_cgi.plmn.mcc_digit1;
  s10_context_request_p->serving_network.mcc[1] = ue_context_p->e_utran_cgi.plmn.mcc_digit2;
  s10_context_request_p->serving_network.mcc[2] = ue_context_p->e_utran_cgi.plmn.mcc_digit3;
  s10_context_request_p->serving_network.mnc[0] = ue_context_p->e_utran_cgi.plmn.mnc_digit1;
  s10_context_request_p->serving_network.mnc[1] = ue_context_p->e_utran_cgi.plmn.mnc_digit2;
  s10_context_request_p->serving_network.mnc[2] = ue_context_p->e_utran_cgi.plmn.mnc_digit3;

  /** Send the Forward Relocation Message to S11. */
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S11_MME ,
      NULL, 0, "0 S10_CONTEXT_REQ for mmeUeS1apId %d \n", nas_ue_context_request_pP->ue_id);
  itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);

  /**
   * S10 Initial request timer will be started on the target MME side in the GTPv2c stack.
   * UE context removal & Attach/TAU reject will be be performed.
   * Also GTPv2c has a transaction started. If no response from source MME arrives, an ITTI message with SYSTEM_FAILURE cause will be returned.
   */
  OAILOG_INFO(LOG_MME_APP, "Successfully sent S10 Context Request for received NAS request for UE id  %d \n", ue_context_p->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_s10_context_request(const itti_s10_context_request_t * const s10_context_request_pP )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;
 int                                     rc = RETURNok;

 DevAssert(s10_context_request_pP);
 DevAssert(s10_context_request_pP->trxn);

 OAILOG_FUNC_IN (LOG_MME_APP);
 OAILOG_DEBUG (LOG_MME_APP, "Received S10_CONTEXT_REQUEST from S10. \n");

 /** Get the GUTI and try to get the context via GUTI. */
 // todo: checking that IMSI exists.. means that UE is validated on the target side.. check 23.401 for this case..
 /** Check that the UE does not exist. */
 ue_context_p = mme_ue_context_exists_guti(&mme_app_desc.mme_ue_contexts, &s10_context_request_pP->old_guti);
 if (ue_context_p == NULL) {
   /** No UE was found. */
   OAILOG_ERROR (LOG_MME_APP, "No UE for guti " GUTI_FMT " was found. Cannot proceed with context request. \n", GUTI_ARG(&s10_context_request_pP->old_guti));
   MSC_LOG_EVENT (MSC_MMEAPP_MME, "S10_CONTEXT_REQUEST. No UE existing for guti: " GUTI_FMT, GUTI_ARG(&s10_context_request_pP->old_guti));
   // todo: error check
   _mme_app_send_s10_context_response_err(s10_context_request_pP->s10_target_mme_teid.teid, s10_context_request_pP->s10_target_mme_teid.ipv4, s10_context_request_pP->trxn, MANDATORY_IE_MISSING);
   bdestroy(s10_context_request_pP->complete_request_message.request_value);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 OAILOG_INFO(LOG_MME_APP, "Received a CONTEXT_REQUEST for new UE with GUTI" GUTI_FMT ". \n", GUTI_ARG(&s10_context_request_pP->old_guti));

 /** Check that NAS/EMM context is existing. */
 emm_data_context_t *ue_nas_ctx = emm_data_context_get_by_guti(&_emm_data, &s10_context_request_pP->old_guti);
 if (!ue_nas_ctx) {
   OAILOG_ERROR(LOG_MME_APP, "A NAS EMM context is not existing for this GUTI "GUTI_FMT " already exists. \n", GUTI_ARG(&s10_context_request_pP->old_guti));
   _mme_app_send_s10_context_response_err(s10_context_request_pP->s10_target_mme_teid.teid, s10_context_request_pP->s10_target_mme_teid.ipv4, s10_context_request_pP->trxn, CONTEXT_NOT_FOUND);
   bdestroy(s10_context_request_pP->complete_request_message.request_value);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Check that a valid security context exists for the MME_UE_CONTEXT. */
 if (!IS_EMM_CTXT_PRESENT_SECURITY(ue_nas_ctx)) {
   OAILOG_ERROR(LOG_MME_APP, "A NAS EMM context is present but no security context is existing for this GUTI "GUTI_FMT ". \n", GUTI_ARG(&s10_context_request_pP->old_guti));
   _mme_app_send_s10_context_response_err(s10_context_request_pP->s10_target_mme_teid.teid, s10_context_request_pP->s10_target_mme_teid.ipv4, s10_context_request_pP->trxn, CONTEXT_NOT_FOUND);
   bdestroy(s10_context_request_pP->complete_request_message.request_value);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Check that the UE is registered. Due to some errors in the RRC, it may be idle or connected. Don't know. */
 if (UE_REGISTERED == ue_context_p->mm_state) { /**< Should also mean EMM_REGISTERED. */
   /** UE may be in idle mode or it may be detached. */
   OAILOG_ERROR(LOG_MME_APP, "UE NAS EMM context is in ECM_CONNECTED state for GUTI "GUTI_FMT ". \n", GUTI_ARG(&s10_context_request_pP->old_guti));
   _mme_app_send_s10_context_response_err(s10_context_request_pP->s10_target_mme_teid.teid, s10_context_request_pP->s10_target_mme_teid.ipv4, s10_context_request_pP->trxn, REQUEST_REJECTED);
   bdestroy(s10_context_request_pP->complete_request_message.request_value);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 rc = emm_data_context_validate_complete_nas_request(ue_nas_ctx, &s10_context_request_pP->complete_request_message);
 /**
  * Destroy the message finally
  * todo: check what if already destroyed.
  */
 bdestroy(s10_context_request_pP->complete_request_message.request_value);
 /** Prepare the S10 CONTEXT_RESPONSE. */
 message_p = itti_alloc_new_message (TASK_MME_APP, S10_CONTEXT_RESPONSE);
 DevAssert (message_p != NULL);
 itti_s10_context_response_t *context_response_p = &message_p->ittiMsg.s10_context_response;
 memset ((void*)context_response_p, 0, sizeof (itti_s10_context_response_t));
 /** Set the target S10 TEID. */
 context_response_p->teid    = s10_context_request_pP->s10_target_mme_teid.teid; /**< Only a single target-MME TEID can exist at a time. */
 context_response_p->peer_ip = s10_context_request_pP->s10_target_mme_teid.ipv4; /**< todo: Check this is correct. */
 context_response_p->trxn    = s10_context_request_pP->trxn;
 /** Set the cause. Since the UE context state has not been changed yet, nothing to do in the context if success or failure.*/
 context_response_p->cause = rc;

 if(rc == REQUEST_ACCEPTED){
   /** Set the Source MME_S10_FTEID the same as in S11. */
   OAI_GCC_DIAG_OFF(pointer-to-int-cast);
   context_response_p->s10_source_mme_teid.teid = (teid_t) ue_context_p; /**< This one also sets the context pointer. */
   OAI_GCC_DIAG_ON(pointer-to-int-cast);
   context_response_p->s10_source_mme_teid.interface_type = S10_MME_GTP_C;
   mme_config_read_lock (&mme_config);
   context_response_p->s10_source_mme_teid.ipv4_address = mme_config.ipv4.s10;
   mme_config_unlock (&mme_config);
   context_response_p->s10_source_mme_teid.ipv4 = 1;

   /**
    * Update the local_s10_key.
    * Not setting the key directly in the  ue_context structure. Only over this function!
    */
   mme_ue_context_update_coll_keys (&mme_app_desc.mme_ue_contexts, ue_context_p,
       ue_context_p->enb_s1ap_id_key,
       ue_context_p->mme_ue_s1ap_id,
       ue_context_p->imsi,
       ue_context_p->mme_s11_teid,       // mme_s11_teid is new
       context_response_p->s10_source_mme_teid.teid,       // set with forward_relocation_request // s10_context_response!
       &ue_context_p->guti);

   /** Set the S11 Source SAEGW FTEID. */
   OAI_GCC_DIAG_OFF(pointer-to-int-cast);
   context_response_p->s11_sgw_teid.teid = ue_context_p->sgw_s11_teid;
   OAI_GCC_DIAG_ON(pointer-to-int-cast);
   context_response_p->s11_sgw_teid.interface_type = S11_MME_GTP_C;
   mme_config_read_lock (&mme_config);
   context_response_p->s11_sgw_teid.ipv4_address = mme_config.ipv4.sgw_s11;
   mme_config_unlock (&mme_config);
   context_response_p->s11_sgw_teid.ipv4 = 1;

   /** Set the IMSI. */
   memset (&context_response_p->imsi.digit, 0, 16); /**< IMSI in create session request. */
   IMSI64_TO_STRING (ue_context_p->imsi, (char *)context_response_p->imsi.digit);
   // message content was set to 0
   context_response_p->imsi.length = strlen ((const char *)context_response_p->imsi.digit);

   /** Set the MM_UE_EPS_CONTEXT. */
   DevAssert(mme_app_set_pdn_connections(&context_response_p->pdn_connections, ue_context_p) == RETURNok);
   /** Set the PDN_CONNECTION IE. */
   DevAssert(mme_app_set_ue_eps_mm_context(&context_response_p->mm_context, ue_context_p, ue_nas_ctx) == RETURNok);

   /**
    * Start timer to wait the handover/TAU procedure to complete.
    * A Clear_Location_Request message received from the HSS will cause the resources to be removed.
    * Resources will not be removed if that is not received. --> TS.23.401 defines for SGSN "remove after CLReq" explicitly).
    */
   mme_config_read_lock (&mme_config);
   if (timer_setup (mme_config.mme_mobility_completion_timer, 0,
       TASK_MME_APP, INSTANCE_DEFAULT, TIMER_ONE_SHOT, (void *) &(ue_context_p->mme_ue_s1ap_id), &(ue_context_p->mme_mobility_completion_timer.id)) < 0) {
     OAILOG_ERROR (LOG_MME_APP, "Failed to start MME mobility completion timer for UE id  %d for duration %d \n", ue_context_p->mme_ue_s1ap_id, mme_config.mme_mobility_completion_timer);
     ue_context_p->mme_mobility_completion_timer.id = MME_APP_TIMER_INACTIVE_ID;
     // todo: do some appropriate error handling..
   } else {
     OAILOG_DEBUG (LOG_MME_APP, "MME APP : Handled S10_CONTEXT_REQUEST at source MME side and started timer for UE context removal. "
         "Activated the MME mobilty timer UE id  %d. Waiting for CANCEL_LOCATION_REQUEST from HSS.. Timer Id %u. Timer duration %d. \n",
         ue_context_p->mme_ue_s1ap_id, ue_context_p->mme_mobility_completion_timer.id, mme_config.mme_mobility_completion_timer);
     /** Upon expiration, invalidate the timer.. no flag needed. */
   }
   mme_config_unlock (&mme_config);
 }else{
   /**
    * No source-MME (local) FTEID needs to be set. No tunnel needs to be established.
    * Just respond with the error cause to the given target-MME FTEID.
    */
 }
 /** Without interacting with NAS, directly send the S10_CONTEXT_RESPONSE message. */
 OAILOG_INFO(LOG_MME_APP, "Allocated S10_CONTEXT_RESPONSE MESSAGE for UE with IMSI " IMSI_64_FMT " and mmeUeS1apId " MME_UE_S1AP_ID_FMT " with error cause %d. \n",
     ue_context_p->imsi, ue_context_p->mme_ue_s1ap_id, context_response_p->cause);

 MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME,  MSC_S11_MME ,
     NULL, 0, "0 S10_CONTEXT_RESPONSE for UE %d is sent. \n", ue_context_p->mme_ue_s1ap_id);
 itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
 /** Send just S10_CONTEXT_RESPONSE. Currently not waiting for the S10_CONTEXT_ACKNOWLEDGE and nothing done if it does not arrive (no timer etc.). */
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_s10_context_response(
    const itti_s10_context_response_t* const s10_context_response_pP
    )
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  uint64_t                                imsi = 0;
  int16_t                                 bearer_id =0;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (s10_context_response_pP );

  IMSI_STRING_TO_IMSI64 (&s10_context_response_pP->imsi, &imsi);
  OAILOG_DEBUG (LOG_MME_APP, "Handling S10 CONTEXT RESPONSE for received imsi " IMSI_64_FMT " and local S10 TEID " TEID_FMT ". \n",
      imsi, s10_context_response_pP->teid);
  ue_context_p = mme_ue_context_exists_s10_teid (&mme_app_desc.mme_ue_contexts, s10_context_response_pP->teid);
  /** Check that the UE_CONTEXT exists for the S10_FTEID. */
  if (ue_context_p == NULL) { /**< If no UE_CONTEXT found, all tunnels are assumed to be cleared and not tunnels established when S10_CONTEXT_RESPONSE is received. */
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 S10_CONTEXT_RESPONSE local S10 TEID " TEID_FMT " ", s10_context_response_pP->teid);
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", s10_context_response_pP->teid);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 S10_CONTEXT_RESPONSe local S10 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
      s10_context_response_pP->teid, ue_context_p->imsi);
  /**
   * Check that the UE_Context is in correct state.
   */
  if(ue_context_p->mm_state != UE_UNREGISTERED){ /**< Should be in UNREGISTERED state, else nothing to be done in the source MME side, just send a reject back and detch the UE. */
    /** Deal with the error case. */
    OAILOG_ERROR(LOG_MME_APP, "UE MME context with IMSI " IMSI_64_FMT " and mmeS1apUeId %d is not in UNREGISTERED state but instead %d. "
        "Doing an implicit detach (todo: currently ignoring). \n",
        ue_context_p->imsi, ue_context_p->mme_ue_s1ap_id, ue_context_p->mm_state);
    _mme_app_send_nas_ue_context_response_err(ue_context_p->mme_ue_s1ap_id, REQUEST_REJECTED);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }

  /** Check the cause. */
  if(s10_context_response_pP->cause != REQUEST_ACCEPTED){
    OAILOG_ERROR(LOG_MME_APP, "Received an erroneous cause  value %d for S10 Context Request for UE with mmeS1apUeId " MME_UE_S1AP_ID_FMT ". "
        "Rejecting attach/tau & implicit detach. \n", s10_context_response_pP->cause, ue_context_p->mme_ue_s1ap_id, ue_context_p->mm_state);
    _mme_app_send_nas_ue_context_response_err(ue_context_p->mme_ue_s1ap_id, s10_context_response_pP->cause);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  /**
   * The UE was successfully authenticated at the source MME. We can sent a S10 Context acknowledge back.
   */
  message_p = itti_alloc_new_message (TASK_MME_APP, S10_CONTEXT_ACKNOWLEDGE);
  DevAssert (message_p != NULL);
  itti_s10_context_acknowledge_t * s10_context_ack_p = &message_p->ittiMsg.s10_context_acknowledge;
  memset(s10_context_ack_p, 0, sizeof(itti_s10_context_acknowledge_t));

  /** Fill up . */
  s10_context_ack_p->cause = REQUEST_ACCEPTED; /**< Since we entered UE_REGISTERED state. */
  /** Set the transaction: Peer IP, Peer Port, Peer TEID should be deduced from this. */
  s10_context_ack_p->trxn       = s10_context_response_pP->trxn;
  s10_context_ack_p->peer_ip    = s10_context_response_pP->s10_source_mme_teid.ipv4;
//  s10_context_ack_p->peer_port  = ue_context_p->tau_info->source_mme_s10_port;
  s10_context_ack_p->teid       = s10_context_response_pP->s10_source_mme_teid.teid;
  MSC_LOG_TX_MESSAGE (MSC_NAS_MME, MSC_S10_MME, NULL, 0, "0 S10 CONTEXT_ACK for UE " MME_UE_S1AP_ID_FMT "! \n", ue_context_p->mme_ue_s1ap_id);
  itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
  OAILOG_INFO(LOG_MME_APP, "Sent S10 Context Acknowledge to the source MME FTEID " TEID_FMT " for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT ". \n",
      ue_context_p->mme_ue_s1ap_id, s10_context_ack_p->teid);

  /**
   * Build a NAS_CONTEXT_INFO message and fill it.
   * Depending on the cause, NAS layer can perform an TAU_REJECT or move on with the TAU validation.
   * NAS layer.
   */
  message_p = itti_alloc_new_message (TASK_MME_APP, NAS_UE_CONTEXT_RSP);
  itti_nas_ue_context_rsp_t *nas_context_info = &message_p->ittiMsg.nas_ue_context_rsp; // todo: mme app handover reject
  memset ((void *)nas_context_info, 0, sizeof (itti_nas_ue_context_rsp_t)); // todo: currently not checking with HSS.. just sending an TAU_REJECT --> UE should perform an initial attach.

  /** Set the cause. */
  nas_context_info->cause = REQUEST_ACCEPTED;
  /** Set the UE identifiers. */
  nas_context_info->ue_id = ue_context_p->mme_ue_s1ap_id;
  /** Fill the elements of the NAS message from S10 CONTEXT_RESPONSE. */
  nas_context_info->imsi = imsi;
  /** Convert the GTPv2c IMSI struct to the NAS IMSI struct. */
  // todo: evtl. refactor this in idle mode TAU!
  clear_imsi(&nas_context_info->imsi);
  nas_context_info->_imsi.u.num.digit1 = s10_context_response_pP->imsi.digit[0];
  nas_context_info->_imsi.u.num.digit2 = s10_context_response_pP->imsi.digit[1];
  nas_context_info->_imsi.u.num.digit3 = s10_context_response_pP->imsi.digit[2];
  nas_context_info->_imsi.u.num.digit4 = s10_context_response_pP->imsi.digit[3];
  nas_context_info->_imsi.u.num.digit5 = s10_context_response_pP->imsi.digit[4];
  nas_context_info->_imsi.u.num.digit6 = s10_context_response_pP->imsi.digit[5];
  nas_context_info->_imsi.u.num.digit7 = s10_context_response_pP->imsi.digit[6];
  nas_context_info->_imsi.u.num.digit8 = s10_context_response_pP->imsi.digit[7];
  nas_context_info->_imsi.u.num.digit9 = s10_context_response_pP->imsi.digit[8];
  nas_context_info->_imsi.u.num.digit10 = s10_context_response_pP->imsi.digit[9];
  nas_context_info->_imsi.u.num.digit11 = s10_context_response_pP->imsi.digit[10];
  nas_context_info->_imsi.u.num.digit12 = s10_context_response_pP->imsi.digit[11];
  nas_context_info->_imsi.u.num.digit13 = s10_context_response_pP->imsi.digit[12];
  nas_context_info->_imsi.u.num.digit14 = s10_context_response_pP->imsi.digit[13];
  nas_context_info->_imsi.u.num.digit15 = s10_context_response_pP->imsi.digit[14];
  nas_context_info->_imsi.u.num.parity = ODD_PARITY; /**< todo: hardcoded ODD!. */

  /**
   * Update the pending PDN connection information from the received PDN-Connection.
   */
  memset (&(ue_context_p->pending_pdn_connectivity_req_imsi), 0, 16); /**< IMSI in create session request. */
  memcpy (&(ue_context_p->pending_pdn_connectivity_req_imsi), &(s10_context_response_pP->imsi.digit), s10_context_response_pP->imsi.length);
  ue_context_p->pending_pdn_connectivity_req_imsi_length = s10_context_response_pP->imsi.length;

  /** Set the MM EPS Context. */
  // todo: validate the MM context..
  memset((void*)&nas_context_info->mm_eps_context, 0, sizeof(mm_context_eps_t));
  memcpy((void*)&nas_context_info->mm_eps_context, (void*)&s10_context_response_pP->ue_eps_mm_context, sizeof(mm_context_eps_t));

  /** Get the PDN Connections IE and set the IP addresses. */
  pdn_connection_t * pdn_conn_pP = s10_context_response_pP->pdn_connections.pdn_connection;
  if(pdn_conn_pP->ip_address.present != 0x0){
    OAILOG_ERROR(LOG_MME_APP, "Received IP PDN type for IMSI  " IMSI_64_FMT " is not IPv4. Only IPv4 is accepted. \n", imsi);
    /**
     * Abort the Context Response procedure since the given IP is not supported.
     * No changes in the source MME side should occur.
     */
    _mme_app_send_nas_ue_context_response_err(ue_context_p->mme_ue_s1ap_id, REQUEST_REJECTED);
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  /**
   * Store the received PDN connectivity information as pending information in the MME_APP UE context.
   * todo: if normal attach --> Create Session Request will be sent from the subscription information ULA.
   * We could send the PDN Connection IE together to the NAS, but since we have subscription information yet, we still need the
   * method mme_app_send_s11_create_session_req_from_handover_tau which sends the CREATE_SESSION_REQUEST from the pending information.
   */
  mme_app_handle_pending_pdn_connectivity_information(ue_context_p, pdn_conn_pP);

  OAILOG_INFO(LOG_MME_APP, "MME_APP dealt with S10 Context Response. Updating the NAS layer for continuing with the attach/TAU procedure for IMSI " IMSI_64_FMT ". \n", imsi);
  rc = itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "MME_APP Sending S10 NAS UE Context response. \n.");
  OAILOG_FUNC_RETURN (LOG_MME_APP, rc);

  /**
   * Not performing state change. The MME_APP UE context will stay in the same state.
   * State change will be handled by EMM layer.
   */
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_s10_context_acknowledge(
    const itti_s10_context_acknowledge_t* const s10_context_acknowledge_pP
    )
{
  struct ue_context_s                    *ue_context_p = NULL;
  MessageDef                             *message_p = NULL;
  uint64_t                                imsi = 0;
  int16_t                                 bearer_id =0;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_MME_APP);
  DevAssert (s10_context_acknowledge_pP);

  OAILOG_DEBUG (LOG_MME_APP, "Handling S10 CONTEXT ACKNOWLEDGE for TEID " TEID_FMT ". \n", s10_context_acknowledge_pP->teid);

  ue_context_p = mme_ue_context_exists_s10_teid (&mme_app_desc.mme_ue_contexts, s10_context_acknowledge_pP->teid);
  /** Check that the UE_CONTEXT exists for the S10_FTEID. */
  if (ue_context_p == NULL) {
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 S10_CONTEXT_ACKNOWLEDGE local S11 teid " TEID_FMT " ", s10_context_acknowledge_pP->teid);
    OAILOG_DEBUG (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", s10_context_acknowledge_pP->teid);
    OAILOG_FUNC_RETURN (LOG_MME_APP, RETURNerror);
  }
  MSC_LOG_RX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME, NULL, 0, "0 S10_CONTEXT_ACKNOWLEDGE local S10 teid " TEID_FMT " IMSI " IMSI_64_FMT " ",
      s10_context_acknowledge_pP->teid, ue_context_p->imsi);
  /** Check the cause. */
  if(s10_context_acknowledge_pP->cause != REQUEST_ACCEPTED){
    OAILOG_ERROR(LOG_MME_APP, "The S10 Context Acknowledge for local teid " TEID_FMT " was not valid/could not be received. "
        "Ignoring the handover state. \n", s10_context_acknowledge_pP->teid);
    // todo: what to do in this case? Ignoring the S6a cancel location request?
  }
  // todo : Mark the UE context as invalid
  OAILOG_FUNC_OUT (LOG_MME_APP);
}


/**
 * Send a NAS UE Context Response with error code.
 * It shall not trigger a TAU/Attach reject at the local (TARGET) MME, since no UE context information could be retrieved.
 */
static
void _mme_app_send_nas_ue_context_response_err(mme_ue_s1ap_id_t ueId, MMECause_t mmeCause){
  MessageDef * message_p = NULL;
  OAILOG_FUNC_IN (LOG_MME_APP);

  /** Send a Context RESPONSE with error cause. */
  message_p = itti_alloc_new_message (TASK_MME_APP, NAS_UE_CONTEXT_RSP);
  DevAssert (message_p != NULL);
  itti_nas_ue_context_rsp_t *nas_ue_context_rsp = &message_p->ittiMsg.nas_ue_context_rsp;
  memset ((void *)nas_ue_context_rsp, 0, sizeof (itti_nas_ue_context_rsp_t));

  /** Set the cause. */
  nas_ue_context_rsp->cause = mmeCause;
  /** Set the UE identifiers. */
  nas_ue_context_rsp->ue_id = ueId;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "MME_APP Sending NAS UE CONTEXT_RSP to NAS");
  /** Sending a message to NAS. */
  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

/**
 * Send an S10 Context Response with error code.
 * It shall not trigger creating a local S10 tunnel.
 * Parameter is the TEID of the Source-MME.
 */
static
void _mme_app_send_s10_context_response_err(teid_t mme_source_s10_teid, uint32_t mme_source_ipv4_address, void *trxn,  MMECause_t mmeCause){
  OAILOG_FUNC_IN (LOG_MME_APP);

  /** Send a Context RESPONSE with error cause. */
  MessageDef * message_p = itti_alloc_new_message (TASK_MME_APP, S10_CONTEXT_RESPONSE);
  DevAssert (message_p != NULL);

  itti_s10_context_response_t *s10_context_response_p = &message_p->ittiMsg.s10_context_response;
  memset ((void*)s10_context_response_p, 0, sizeof (itti_s10_context_response_t));
  /** Set the TEID of the source MME. */
  s10_context_response_p->teid = mme_source_s10_teid; /**< Not set into the UE context yet. */
  /** Set the IPv4 address of the source MME. */
  s10_context_response_p->peer_ip = mme_source_ipv4_address;
  s10_context_response_p->cause = mmeCause;
  s10_context_response_p->trxn  = trxn;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "MME_APP Sending S10 CONTEXT_RESPONSE_ERR");

  /** Sending a message to S10. */
  itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);

  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_relocation_cancel_request(
     const itti_s10_relocation_cancel_request_t* const relocation_cancel_request_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;
 imsi64_t                                imsi64 = INVALID_IMSI64;
 itti_s10_relocation_cancel_response_t  *relocation_cancel_response_p = NULL;

 OAILOG_FUNC_IN (LOG_MME_APP);
 OAILOG_DEBUG (LOG_MME_APP, "Received S10_RELOCATION_CANCEL_REQUEST from S10. \n");

 /** Check that the UE does exist. */
 ue_context_p = mme_ue_context_exists_s10_teid (&mme_app_desc.mme_ue_contexts, relocation_cancel_request_pP->teid); /**< Get the UE context from the local TEID. */
 if (ue_context_p == NULL) {
   MSC_LOG_RX_DISCARDED_MESSAGE (MSC_MMEAPP_MME, MSC_S10_MME, NULL, 0, "0 RELOCATION_CANCEL_REQUEST local S10 teid " TEID_FMT,
       relocation_cancel_request_pP->teid);
   OAILOG_ERROR (LOG_MME_APP, "We didn't find this teid in list of UE: %08x\n", relocation_cancel_request_pP->teid);
   /** No response can be sent, because we are missing the UE_CONTEXT. */
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 message_p = itti_alloc_new_message (TASK_MME_APP, S10_RELOCATION_CANCEL_RESPONSE);
 DevAssert (message_p != NULL);
 relocation_cancel_response_p = &message_p->ittiMsg.s10_relocation_cancel_response;
 memset ((void*)relocation_cancel_response_p, 0, sizeof (itti_s10_relocation_cancel_response_t));
 relocation_cancel_response_p->teid    = ue_context_p->remote_mme_s10_teid; /**< Only a single target-MME TEID can exist at a time. */
 relocation_cancel_response_p->peer_ip = mme_config.nghMme.nghMme[0].ipAddr; /**< todo: Check this is correct. */
 relocation_cancel_response_p->trxn    = relocation_cancel_request_pP->trxn;

 IMSI_STRING_TO_IMSI64 (&relocation_cancel_request_pP->imsi, &imsi64);
 if(ue_context_p->imsi != imsi64) {
   OAILOG_ERROR (LOG_MME_APP, "IMSI " IMSI_64_FMT " not found for UE " MME_UE_S1AP_ID_FMT ". \n", imsi64, ue_context_p->mme_ue_s1ap_id);
   /** Set the cause. Since the UE context state has not been changed yet, nothing to do in the context if success or failure.*/
   relocation_cancel_response_p->cause = IMSI_NOT_KNOWN;
   itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Get the EMM context, too. */
 emm_data_context_t * ue_nas_ctx = emm_data_context_get_by_imsi(&_emm_data, imsi64);
 if(!ue_nas_ctx){
   OAILOG_ERROR (LOG_MME_APP, "No EMM Data Context exists for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " and IMSI " IMSI_64_FMT ". \n", ue_context_p->mme_ue_s1ap_id, imsi64);
   /** Set the cause. Since the UE context state has not been changed yet, nothing to do in the context if success or failure.*/
   relocation_cancel_response_p->cause = IMSI_NOT_KNOWN;
   itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Not checking if EMM context and MME_APP UE context IDs match.. */
 /**
  * Lastly, check if the UE is already REGISTERED in the TARGET cell (here).
  * In that case, its too late to remove for HO-CANCELLATION.
  * Assuming that it is an error on the source side.
  */
 if(ue_context_p->mm_state == UE_REGISTERED || ue_nas_ctx->_emm_fsm_status == EMM_REGISTERED){
   OAILOG_ERROR (LOG_MME_APP, "UE Context/EMM Data Context for IMSI " IMSI_64_FMT " and mmeUeS1apId " MME_UE_S1AP_ID_FMT " is already REGISTERED. "
       "Not purging due to Handover Cancellation. \n", ue_context_p->mme_ue_s1ap_id, imsi64);
   /** Set the cause. Since the UE context state has not been changed yet, nothing to do in the context if success or failure.*/
   relocation_cancel_response_p->cause = SYSTEM_FAILURE;
   itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 /** Respond with a Relocation Cancel Response (without waiting for the S10-Triggered detach to complete. */
 relocation_cancel_response_p->cause = REQUEST_ACCEPTED;
 itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);
 /**
  * Perform an UE Context Release with cause Handover Cancellation.
  * Will also cancel all MME_APP timers and send a S1AP Release Command with HO-Cancellation cause.
  */
 ue_context_p->ue_context_rel_cause = S1AP_HANDOVER_CANCELLED; /**< First the default bearers should be removed. Then the UE context in the eNodeB. */
 message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
 DevAssert (message_p != NULL);
 message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
 itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
 /** Triggered an Implicit Detach Message back. */
 OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_relocation_cancel_response(
     const itti_s10_relocation_cancel_response_t * const relocation_cancel_response_pP
    )
{
 struct ue_context_s                    *ue_context_p = NULL;
 MessageDef                             *message_p = NULL;

 OAILOG_FUNC_IN (LOG_MME_APP);
 OAILOG_DEBUG (LOG_MME_APP, "Received S10_RELOCATION_CANCEL_RESPONSE from S10. \n");

 /** Check that the UE does exist. */
 ue_context_p = mme_ue_context_exists_s10_teid(&mme_app_desc.mme_ue_contexts, relocation_cancel_response_pP->teid);
 if (ue_context_p == NULL) {
   OAILOG_ERROR(LOG_MME_APP, "An UE MME context does not exist for UE with s10 teid %d. \n", relocation_cancel_response_pP->teid);
   MSC_LOG_EVENT (MSC_MMEAPP_MME, "S10_RELOCATION_CANCEL_RESPONSE. No UE existing teid %d. \n", relocation_cancel_response_pP->teid);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }

 /**
  * Check the cause of the UE.
  * If it is SYSTEM_FAILURE, perform an implicit detach.
  */
 if(relocation_cancel_response_pP->cause != REQUEST_ACCEPTED){
   OAILOG_ERROR(LOG_MME_APP, "RELOCATION_CANCEL_REPONSE for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT " is not accepted, instead %d. \n",
       ue_context_p->mme_ue_s1ap_id, relocation_cancel_response_pP->cause);
   ue_context_p->ue_context_rel_cause = S1AP_NETWORK_ERROR;
   message_p = itti_alloc_new_message (TASK_MME_APP, NAS_IMPLICIT_DETACH_UE_IND);
   DevAssert (message_p != NULL);
   itti_nas_implicit_detach_ue_ind_t *nas_implicit_detach_ue_ind_p = &message_p->ittiMsg.nas_implicit_detach_ue_ind;
   memset ((void*)nas_implicit_detach_ue_ind_p, 0, sizeof (itti_nas_implicit_detach_ue_ind_t));
   message_p->ittiMsg.nas_implicit_detach_ue_ind.ue_id = ue_context_p->mme_ue_s1ap_id;
   itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
   OAILOG_FUNC_OUT (LOG_MME_APP);
 }
 OAILOG_INFO(LOG_MME_APP, "RELOCATION_CANCEL_REPONSE was accepted at TARGET-MME side for UE with mmeUeS1apId " MME_UE_S1AP_ID_FMT ". "
     "Accepting Handover Cancellation. \n", ue_context_p->mme_ue_s1ap_id);

 // todo: when to accept these values from the target-MME side.
 mme_app_send_s1ap_handover_cancel_acknowledge(ue_context_p->mme_ue_s1ap_id, ue_context_p->enb_ue_s1ap_id, ue_context_p->sctp_assoc_id_key);
 OAILOG_FUNC_OUT (LOG_MME_APP);
}
