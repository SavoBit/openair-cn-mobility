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



/* This file contains definitions related to mme applicative layer and should
 * not be included within other layers.
 * Use mme_app_extern.h to expose mme applicative layer procedures/data.
 */


#ifndef FILE_MME_APP_DEFS_SEEN
#define FILE_MME_APP_DEFS_SEEN
#include "intertask_interface.h"
#include "mme_app_ue_context.h"

// todo: need to extend this with enb's connected?!
typedef struct {
  /* UE contexts + some statistics variables */
  mme_ue_context_t mme_ue_contexts;

  long statistic_timer_id;
  uint32_t statistic_timer_period;
  uint32_t mme_mobility_management_timer_period;

  /* Reader/writer lock */
  pthread_rwlock_t rw_lock;
  
  /* ***************Statistics*************
   * number of attached UE,number of connected UE,
   * number of idle UE,number of default bearers, 
   * number of S1_U bearers,number of PDN sessions
   */ 
  
  uint32_t               nb_enb_connected;
  uint32_t               nb_ue_attached;
  uint32_t               nb_ue_connected;
  uint32_t               nb_default_eps_bearers;
  uint32_t               nb_s1u_bearers;
  
  /* ***************Changes in Statistics**************/

  uint32_t               nb_ue_attached_since_last_stat;
  uint32_t               nb_ue_detached_since_last_stat;
  uint32_t               nb_ue_connected_since_last_stat;
  uint32_t               nb_ue_disconnected_since_last_stat;
  uint32_t               nb_eps_bearers_established_since_last_stat;
  uint32_t               nb_eps_bearers_released_since_last_stat;
  uint32_t               nb_enb_connected_since_last_stat;
  uint32_t               nb_enb_released_since_last_stat;
  uint32_t               nb_s1u_bearers_released_since_last_stat;
  uint32_t               nb_s1u_bearers_established_since_last_stat;
} mme_app_desc_t;

extern mme_app_desc_t mme_app_desc;

int mme_app_handle_s1ap_ue_capabilities_ind  (const itti_s1ap_ue_cap_ind_t const * s1ap_ue_cap_ind_pP);

void mme_app_handle_s1ap_ue_context_release_complete (const itti_s1ap_ue_context_release_complete_t const
                                                       *s1ap_ue_context_release_complete);


int mme_app_send_s11_release_access_bearers_req (struct ue_context_s *const ue_context_pP);

int mme_app_send_s11_create_session_req      (struct ue_context_s * const ue_context_pP);

/** Trigger a Create_Session_Request from an Handover. */
int mme_app_send_s11_create_session_req_from_handover_tau ( mme_ue_s1ap_id_t ue_id);

int mme_app_send_s6a_update_location_req     (struct ue_context_s * const ue_context_pP);

int mme_app_handle_s6a_update_location_ans   (const s6a_update_location_ans_t * const ula_pP);

int mme_app_handle_s6a_cancel_location_req  (const s6a_cancel_location_req_t * const clr_pP);

int mme_app_handle_s6a_reset_req  (const s6a_reset_req_t * const rr_pP);

int mme_app_handle_nas_pdn_connectivity_req  ( itti_nas_pdn_connectivity_req_t * const nas_pdn_connectivity_req_p);

int mme_app_handle_nas_pdn_connectivity_fail ( itti_nas_pdn_connectivity_fail_t * const nas_pdn_connectivity_fail_pP);

void mme_app_handle_detach_req (const itti_nas_detach_req_t * const detach_req_p);

void mme_app_handle_conn_est_cnf             (const itti_nas_conn_est_cnf_t * const nas_conn_est_cnf_pP);

// Handover messaging
void mme_app_handle_handover_tau_cnf    (  const itti_nas_handover_tau_cnf_t * const nas_handover_tau_cnf_pP);

void mme_app_handle_handover_tau_rej (   const itti_nas_handover_tau_rej_t * const nas_handover_tau_rej_pP);

void mme_app_handle_initial_ue_message       (itti_mme_app_initial_ue_message_t * const conn_est_ind_pP);

void mme_app_handle_initial_ue_message_check_duplicate (itti_mme_app_initial_ue_message_check_duplicate_t * const initial_check_duplicate_pP);

int mme_app_handle_create_sess_resp          (const itti_s11_create_session_response_t * const create_sess_resp_pP); //not const because we need to free internal stucts

int mme_app_handle_modify_bearer_resp          (const itti_s11_modify_bearer_response_t * const modify_bearer_resp_pP);

void mme_app_handle_delete_session_rsp	     (const itti_s11_delete_session_response_t * const delete_sess_respP);

void mme_app_handle_downlink_data_notification (const itti_s11_downlink_data_notification_t * const saegw_dl_data_ntf_pP);

int mme_app_handle_establish_ind             (const nas_establish_ind_t * const nas_establish_ind_pP);

int mme_app_handle_authentication_info_answer(const s6a_auth_info_ans_t * const s6a_auth_info_ans_pP);

void  mme_app_handle_release_access_bearers_resp (const itti_s11_release_access_bearers_response_t * const rel_access_bearers_rsp_pP);

nas_cause_t s6a_error_2_nas_cause            (const uint32_t s6a_errorP, const int experimentalP);

void mme_app_handle_nas_auth_param_req       (const itti_nas_auth_param_req_t * const nas_auth_param_req_pP);

void mme_app_handle_initial_context_setup_rsp(const itti_mme_app_initial_context_setup_rsp_t * const initial_ctxt_setup_rsp_pP);

void mme_app_handle_initial_context_setup_failure(const itti_mme_app_initial_context_setup_failure_t * const initial_ctxt_setup_failure_pP);

bool mme_app_dump_ue_context (const hash_key_t keyP, void *const ue_context_pP, void *unused_param_pP, void **unused_result_pP);

int mme_app_handle_nas_dl_req ( itti_nas_dl_data_req_t *const nas_dl_req_pP);

void mme_ue_context_update_ue_sig_connection_state (mme_ue_context_t * const mme_ue_context_p,
                                                                            struct ue_context_s *ue_context_p,ecm_state_t new_ecm_state);

void mme_app_handle_mobile_reachability_timer_expiry (struct ue_context_s *ue_context_p);

void mme_app_handle_implicit_detach_timer_expiry (struct ue_context_s *ue_context_p); 

void mme_app_handle_mme_mobility_completion_timer_expiry (struct ue_context_s *ue_context_p);

void mme_app_handle_mme_s10_handover_completion_timer_expiry (struct ue_context_s *ue_context_p);

void mme_app_handle_mme_paging_timeout_timer_expiry (struct ue_context_s *ue_context_p);

void mme_app_handle_initial_context_setup_rsp_timer_expiry (struct ue_context_s *ue_context_p);

void mme_app_handle_enb_reset_req( const itti_s1ap_enb_initiated_reset_req_t const * enb_reset_req);

/** X2 Handover messaging. */
void mme_app_handle_path_switch_req(
     const itti_mme_app_path_switch_req_t * const path_switch_req_pP
    );

/** S1AP Handover messaging. */
void mme_app_handle_handover_required( const itti_s1ap_handover_required_t * const handover_required_pP );

void mme_app_handle_handover_cancel( const itti_s1ap_handover_cancel_t * const handover_cancel_pP );

/** Handling S10 Messages.
 * todo: handle errors..
 */
void mme_app_handle_forward_relocation_request( const itti_s10_forward_relocation_request_t * const forward_relocation_request_pP );

void mme_app_handle_nas_ho_forward_relocation_fail( const itti_nas_ho_forward_reloc_fail_t * const forward_relocation_fail_pP );

void mme_app_handle_forward_relocation_response(    const itti_s10_forward_relocation_response_t* const forward_relocation_response_pP );

void mme_app_handle_forward_access_context_notification( const itti_s10_forward_access_context_notification_t * const forward_access_context_notification_pP );

void mme_app_handle_forward_access_context_acknowledge( const itti_s10_forward_access_context_acknowledge_t* const forward_access_context_acknowledge_pP );

void mme_app_handle_handover_request_acknowledge(const itti_s1ap_handover_request_acknowledge_t * const handover_request_acknowledge_pP    );

void mme_app_handle_handover_failure(const itti_s1ap_handover_failure_t * const handover_failure_pP    );

void mme_app_handle_enb_status_transfer(const itti_s1ap_status_transfer_t* const s1ap_status_transfer_pP    );

void mme_app_handle_forward_relocation_complete_notification(const itti_s10_forward_relocation_complete_notification_t* const forward_relocation_complete_notification_pP    );

void mme_app_handle_forward_relocation_complete_acknowledge(const itti_s10_forward_relocation_complete_acknowledge_t* const forward_relocation_complete_acknowledge_pP    );

/** Relocation Cancel Request & Response. */
void
mme_app_handle_relocation_cancel_request(
     const itti_s10_relocation_cancel_request_t * const relocation_cancel_request_pP
    );

void
mme_app_handle_relocation_cancel_response(
     const itti_s10_relocation_cancel_response_t * const relocation_cancel_response_pP
    );

/** TAU Related Messaging. */
void mme_app_handle_nas_ue_context_req(const itti_nas_ue_context_req_t * const nas_ue_context_req_pP);

void mme_app_handle_s10_context_request( const itti_s10_context_request_t * const context_request_pP );

void mme_app_handle_s10_context_response( const itti_s10_context_response_t * const context_response_pP );

void mme_app_handle_s10_context_acknowledge( const itti_s10_context_acknowledge_t * const context_acknowledge_pP );

#define mme_stats_read_lock(mMEsTATS)  pthread_rwlock_rdlock(&(mMEsTATS)->rw_lock)
#define mme_stats_write_lock(mMEsTATS) pthread_rwlock_wrlock(&(mMEsTATS)->rw_lock)
#define mme_stats_unlock(mMEsTATS)     pthread_rwlock_unlock(&(mMEsTATS)->rw_lock)

#endif /* MME_APP_DEFS_H_ */
