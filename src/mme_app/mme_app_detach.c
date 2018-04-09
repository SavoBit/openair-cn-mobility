/*******************************************************************************
    OpenAirInterface
    Copyright(c) 1999 - 2014 Eurecom

    OpenAirInterface is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.


    OpenAirInterface is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with OpenAirInterface.The full GNU General Public License is
   included in this distribution in the file called "COPYING". If not,
   see <http://www.gnu.org/licenses/>.

  Contact Information
  OpenAirInterface Admin: openair_admin@eurecom.fr
  OpenAirInterface Tech : openair_tech@eurecom.fr
  OpenAirInterface Dev  : openair4g-devel@eurecom.fr

  Address      : Eurecom, Compus SophiaTech 450, route des chappes, 06451 Biot, France.

 *******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "assertions.h"
#include "msc.h"
#include "intertask_interface.h"
#include "mme_app_ue_context.h"
#include "mme_app_itti_messaging.h"
#include "mme_app_defs.h"

//------------------------------------------------------------------------------
void
mme_app_send_delete_session_request (
  struct ue_context_s                    *ue_context_p)
{
  MessageDef                             *message_p = NULL;
  OAILOG_FUNC_IN (LOG_MME_APP);

  message_p = itti_alloc_new_message (TASK_MME_APP, S11_DELETE_SESSION_REQUEST);
  AssertFatal (message_p , "itti_alloc_new_message Failed");
  memset ((void *)&message_p->ittiMsg.s11_delete_session_request, 0, sizeof (itti_s11_delete_session_request_t));
  S11_DELETE_SESSION_REQUEST (message_p).local_teid = ue_context_p->mme_s11_teid;
  S11_DELETE_SESSION_REQUEST (message_p).teid = ue_context_p->sgw_s11_teid;
  S11_DELETE_SESSION_REQUEST (message_p).lbi = ue_context_p->default_bearer_id;

  OAI_GCC_DIAG_OFF(pointer-to-int-cast);
  S11_DELETE_SESSION_REQUEST (message_p).sender_fteid_for_cp.teid = (teid_t) ue_context_p;
  OAI_GCC_DIAG_ON(pointer-to-int-cast);
  S11_DELETE_SESSION_REQUEST (message_p).sender_fteid_for_cp.interface_type = S11_MME_GTP_C;
  mme_config_read_lock (&mme_config);
  S11_DELETE_SESSION_REQUEST (message_p).sender_fteid_for_cp.ipv4_address = mme_config.ipv4.s11;
  mme_config_unlock (&mme_config);
  S11_DELETE_SESSION_REQUEST (message_p).sender_fteid_for_cp.ipv4 = 1;

  /*
   * S11 stack specific parameter. Not used in standalone epc mode
   */
  S11_DELETE_SESSION_REQUEST  (message_p).trxn = NULL;
  mme_config_read_lock (&mme_config);
  S11_DELETE_SESSION_REQUEST (message_p).peer_ip = mme_config.ipv4.sgw_s11;
  mme_config_unlock (&mme_config);

  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_S11_MME,
                      NULL, 0, "0  S11_DELETE_SESSION_REQUEST teid %u lbi %u",
                      S11_DELETE_SESSION_REQUEST  (message_p).teid,
                      S11_DELETE_SESSION_REQUEST  (message_p).lbi);

  itti_send_msg_to_task (TASK_S11, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_OUT (LOG_MME_APP);
}

//------------------------------------------------------------------------------
void
mme_app_handle_detach_req (
  const itti_nas_detach_req_t * const detach_req_p)
{
  struct ue_context_s *ue_context    = NULL;
  OAILOG_FUNC_IN (LOG_MME_APP);

  DevAssert(detach_req_p != NULL);
  ue_context = mme_ue_context_exists_mme_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, detach_req_p->ue_id);
  if (ue_context == NULL) {
    OAILOG_ERROR (LOG_MME_APP, "UE context doesn't exist -> Nothing to do :-) \n");
    OAILOG_FUNC_OUT (LOG_MME_APP);
  }
  /**
   * A Detach Request is sent by the EMM layer after all PDN sessions are removed.
   * We don't need to check for invalidated TEID fields!
   * Delete Session Response should invalidate the S11-TEID registration in the hashtable for MME_APP UE Context.
   * If the MME_APP UE context removal happens before the arrival of the delete session response, the existing TEIDs (not 0)
   * should be used to deregister the MME_APP UE context from the hashtables.
   * That is the reason why we send and wait for PDN_DISCONNECT_RSP --> To make it clear that !
   *
   * We check if the S1AP connection is standing or idle and remove the MME_APP UE context
   *
   * Check if If UE is already in idle state, skip asking eNB to release UE context and just clean up locally.
   */

  /**
   * UE was already in idle mode.
   * For UE triggered detach in idle mode, it had to be active again.
   * This is network triggered detach.
   */
  /**
   * The UE context must be in UNREGISTERED mode, since everything is controller via EMM,
   * and we enter this stage only if EMM has triggered detach (which sets EMM state to EMM_DEREGSITERED) --> todo: set to EMM_DEREGISTER initiated, if it is an implicit MME detach!
   *
   */
  /** Remove the local S10 Tunnel if one exist. */
  /**
   * Remove the S10 Tunnel Endpoint. No more messages to send.
   * Assuming that new S10 messages (if any, will be sent with new TEIDs).
   * todo: this as the only point to remove the S10 tunnel.
   */
  MessageDef *message_p = itti_alloc_new_message (TASK_MME_APP, S10_REMOVE_UE_TUNNEL);
  DevAssert (message_p != NULL);
  message_p->ittiMsg.s10_remove_ue_tunnel.remote_teid  = ue_context->remote_mme_s10_teid;
  message_p->ittiMsg.s10_remove_ue_tunnel.local_teid   = ue_context->local_mme_s10_teid;
  message_p->ittiMsg.s10_remove_ue_tunnel.peer_ip      = ue_context->remote_mme_s10_peer_ip;

//  message_p->ittiMsg.s10_remove_ue_tunnel.cause = LOCAL_DETACH;
  MSC_LOG_TX_MESSAGE (MSC_MMEAPP_MME, MSC_NAS_MME, NULL, 0, "0 NAS_IMPLICIT_DETACH_UE_IND_MESSAGE");
  itti_send_msg_to_task (TASK_S10, INSTANCE_DEFAULT, message_p);

  /**
   * todo: if it is an MME triggered implicit detach, the UE should be in EMM_DEREGISTER_INITIATED state --> from there determine if it is an implicit detach or not..
   * If it is concluded that it is an implicit detach --> perform paging, leave the state as it is in EMM_DEREGISTER_INITIATED
   */
  if (ECM_IDLE == ue_context->ecm_state) {
    // todo: perform paging, if the UE is in EMM_DEREGISTER_INITIATED! state (MME triggered detach).
    ue_context->ue_context_rel_cause = S1AP_IMPLICIT_CONTEXT_RELEASE; /**< No Release command will be sent, even if an S1AP context exists. */
    // Notify S1AP to release S1AP UE context locally. No
    mme_app_itti_ue_context_release (ue_context->enb_ue_s1ap_id, ue_context->ue_context_rel_cause, ue_context->e_utran_cgi.cell_identity.enb_id); /**< Set the signaling connection to ECM_IDLE when the Context-Removal-Completion has arrived. */
    // Free MME UE Context
    mme_remove_ue_context (&mme_app_desc.mme_ue_contexts, ue_context);
  } else {  /**< UE has an active context. Setting NAS_DETACH as S1AP cause and sending the context removal command! */
    if (ue_context->ue_context_rel_cause == S1AP_INVALID_CAUSE) {
      ue_context->ue_context_rel_cause = S1AP_NAS_DETACH;
    }
    /**
     * Notify S1AP to send UE Context Release Command to eNB. Signaling connection will be set to idle after context completion complete.
     * This starts a timer to wait for the context removal completion. If timeout happens, the S1AP UE reference will be notified and the MMME_APP will be called.
     * If the S1AP context removal response does not arrive, the MME_APP UE context may already be removed. Not a problem for the MME_APP. The S1AP UE reference will be removed.
     */
    mme_app_itti_ue_context_release (ue_context->enb_ue_s1ap_id, ue_context->ue_context_rel_cause, ue_context->e_utran_cgi.cell_identity.enb_id);
    /**
     * We may or may not expect a response from the eNodeB context removal depending on the set release cause, to remove the rest of the UE context and deregistrate the UE.
     * If the response does not arrive, the S1AP timeout will do the rest.
     * No further timeout in the NAS-EMM. NAS will send detach once. It will remove the EMM context immediately.
     * Nothing special to do for S10. Should be removed with mme_remove_ue_context!
     *
     * Not need to remove with successfully completing the handover on the target-MME side. Without removing a second handover from the target side should be possible!
     *
     * Just continue without waiting for a response from the eNodeB for the S1AP context removal, if its a general shutdown.
     */
    if (ue_context->ue_context_rel_cause == S1AP_SCTP_SHUTDOWN_OR_RESET) {
      /**
       * Just cleanup the MME APP state associated with s1. Set the connection state to invalid.. Acting like the S1AP connection is already released.
       * This will also deregister the ENB_UE_S1AP_ID key from the registration of the MME_APP.
       * Getting back from IDLE will always be with an INITIAL_UE_REQUEST. There the new ENB_ID will be registered for the MME_APP UE context!
       *
       * Signaling Transition:
       * The signaling connection is activated, after the UE has checked the initial context request and permitted.
       * This may not be eventually directly with initial ctx setup request (from eNB), but later after MME verifies.
       * In between the MME_APP context, which is directly created might be needed for the enb_ID, that's why register before and separately.
       * That's why, don't provide the enb_id as an argument.
       * Getting back from IDLE_TO_ACTIVE with this method won't register a new key, just acknowledgement by the MME and stop the any idle-timers.
       */
      mme_ue_context_update_ue_sig_connection_state (&mme_app_desc.mme_ue_contexts, ue_context, ECM_IDLE);
      // S1AP, nothing more to do. Free MME UE Context
      mme_remove_ue_context (&mme_app_desc.mme_ue_contexts, ue_context);
    } else if (ue_context->ue_context_rel_cause == S1AP_SUCCESSFUL_HANDOVER){ /**< Wait for a response. */
      OAILOG_DEBUG (LOG_MME_APP, "UE context will be released and resources removed due HANDOVER for UE with IMSI: " IMSI_64_FMT " and MME_UE_S1AP_ID : %d. \n",
          ue_context->imsi, ue_context->mme_ue_s1ap_id);
    }
  }
  OAILOG_FUNC_OUT (LOG_MME_APP);
}
