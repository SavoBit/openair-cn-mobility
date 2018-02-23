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

/*****************************************************************************
  Source      Detach.c

  Version     0.1

  Date        2013/05/07

  Product     NAS stack

  Subsystem   EPS Mobility Management

  Author      Frederic Maurel

  Description Defines the detach related EMM procedure executed by the
        Non-Access Stratum.

        The detach procedure is used by the UE to detach for EPS servi-
        ces, to disconnect from the last PDN it is connected to; by the
        network to inform the UE that it is detached for EPS services
        or non-EPS services or both, to disconnect the UE from the last
        PDN to which it is connected and to inform the UE to re-attach
        to the network and re-establish all PDN connections.

*****************************************************************************/

#include "log.h"
#include "msc.h"
#include "dynamic_memory_check.h"
#include "emmData.h"
#include "emm_proc.h"
#include "emm_sap.h"
#include "esm_sap.h"
#include "nas_itti_messaging.h"


/****************************************************************************/
/****************  E X T E R N A L    D E F I N I T I O N S  ****************/
/****************************************************************************/

/****************************************************************************/
/*******************  L O C A L    D E F I N I T I O N S  *******************/
/****************************************************************************/

/* String representation of the detach type */
static const char                      *_emm_detach_type_str[] = {
  "EPS", "IMSI", "EPS/IMSI",
  "RE-ATTACH REQUIRED", "RE-ATTACH NOT REQUIRED", "RESERVED"
};


void
_clear_emm_ctxt(emm_data_context_t *emm_ctx) {
  
  if (!emm_ctx) {
    return;
  }

  emm_data_context_stop_all_timers(emm_ctx);

  esm_sap_t                               esm_sap = {0};
  /*
   * Release ESM PDN and bearer context
   */

  esm_sap.primitive = ESM_EPS_BEARER_CONTEXT_DEACTIVATE_REQ;
  esm_sap.ue_id = emm_ctx->ue_id;
  esm_sap.ctx = emm_ctx;
  esm_sap.data.eps_bearer_context_deactivate.ebi = ESM_SAP_ALL_EBI;
  esm_sap_send (&esm_sap);

  if (emm_ctx->esm_msg) {
    bdestroy(emm_ctx->esm_msg);
  }

  // Change the FSM state to Deregistered
  if (emm_fsm_get_status (emm_ctx->ue_id, emm_ctx) != EMM_DEREGISTERED) {
    emm_fsm_set_status (emm_ctx->ue_id, emm_ctx, EMM_DEREGISTERED); 
  }

  /*
   * Release the EMM context
   */
  emm_data_context_remove(&_emm_data, emm_ctx);
  free_wrapper((void **) &emm_ctx);
}



/*
   --------------------------------------------------------------------------
        Internal data handled by the detach procedure in the UE
   --------------------------------------------------------------------------
*/


/*
   --------------------------------------------------------------------------
        Internal data handled by the detach procedure in the MME
   --------------------------------------------------------------------------
*/


/****************************************************************************/
/******************  E X P O R T E D    F U N C T I O N S  ******************/
/****************************************************************************/

/*
   --------------------------------------------------------------------------
            Detach procedure executed by the UE
   --------------------------------------------------------------------------
*/

/*
   --------------------------------------------------------------------------
            Detach procedure executed by the MME
   --------------------------------------------------------------------------
*/
/****************************************************************************
 **                                                                        **
 ** Name:    emm_proc_detach()                                         **
 **                                                                        **
 ** Description: Initiate the detach procedure to inform the UE that it is **
 **      detached for EPS services, or to re-attach to the network **
 **      and re-establish all PDN connections.                     **
 **                                                                        **
 **              3GPP TS 24.301, section 5.5.2.3.1                         **
 **      In state EMM-REGISTERED the network initiates the detach  **
 **      procedure by sending a DETACH REQUEST message to the UE,  **
 **      starting timer T3422 and entering state EMM-DEREGISTERED- **
 **      INITIATED.                                                **
 **                                                                        **
 ** Inputs:  ue_id:      UE lower layer identifier                  **
 **      type:      Type of the requested detach               **
 **      Others:    _emm_detach_type_str                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    RETURNok, RETURNerror                      **
 **      Others:    T3422                                      **
 **                                                                        **
 ***************************************************************************/
int
emm_proc_detach (
  mme_ue_s1ap_id_t ue_id,
  emm_proc_detach_type_t type)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  int                                     rc = RETURNerror;

  OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Initiate detach type = %s (%d)", _emm_detach_type_str[type], type);
  /*
   * TODO
   */
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

/****************************************************************************
 **                                                                        **
 ** Name:    emm_proc_detach_request()                                 **
 **                                                                        **
 ** Description: Performs the UE initiated detach procedure for EPS servi- **
 **      ces only When the DETACH REQUEST message is received by   **
 **      the network.                                              **
 **                                                                        **
 **              3GPP TS 24.301, section 5.5.2.2.2                         **
 **      Upon receiving the DETACH REQUEST message the network     **
 **      shall send a DETACH ACCEPT message to the UE and store    **
 **      the current EPS security context, if the detach type IE   **
 **      does not indicate "switch off". Otherwise, the procedure  **
 **      is completed when the network receives the DETACH REQUEST **
 **      message.                                                  **
 **      The network shall deactivate the EPS bearer context(s)    **
 **      for this UE locally without peer-to-peer signalling and   **
 **      shall enter state EMM-DEREGISTERED.                       **
 **                                                                        **
 ** Inputs:  ue_id:      UE lower layer identifier                  **
 **      type:      Type of the requested detach               **
 **      switch_off:    Indicates whether the detach is required   **
 **             because the UE is switched off or not      **
 **      native_ksi:    true if the security context is of type    **
 **             native                                     **
 **      ksi:       The NAS ket sey identifier                 **
 **      guti:      The GUTI if provided by the UE             **
 **      imsi:      The IMSI if provided by the UE             **
 **      imei:      The IMEI if provided by the UE             **
 **      Others:    _emm_data                                  **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    RETURNok, RETURNerror                      **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
int
emm_proc_detach_request (
  mme_ue_s1ap_id_t ue_id,
  emm_proc_detach_type_t type,
  int switch_off,
  ksi_t native_ksi,
  ksi_t ksi,
  guti_t * guti,
  imsi_t * imsi,
  imei_t * imei)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  int                                     rc;
  emm_data_context_t                     *emm_ctx = NULL;

  OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Detach type = %s (%d) requested (ue_id=" MME_UE_S1AP_ID_FMT ")", _emm_detach_type_str[type], type, ue_id);
  /*
   * Get the UE context
   */
  emm_ctx = emm_data_context_get (&_emm_data, ue_id);

  if (emm_ctx == NULL) {
    OAILOG_WARNING (LOG_NAS_EMM, "No EMM context exists for the UE (ue_id=" MME_UE_S1AP_ID_FMT ")", ue_id);
    // There may be MME APP Context. Trigger clean up in MME APP 
    nas_itti_detach_req(ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNok);
  }

  if (switch_off) {
    MSC_LOG_EVENT (MSC_NAS_EMM_MME, "0 Removing UE context ue id " MME_UE_S1AP_ID_FMT " ", ue_id);
    rc = RETURNok;
  } else {
    /*
     * Normal detach without UE switch-off
     */
    emm_sap_t                               emm_sap = {0};
    emm_as_data_t                          *emm_as = &emm_sap.u.emm_as.u.data;

    MSC_LOG_TX_MESSAGE (MSC_NAS_EMM_MME, MSC_NAS_EMM_MME, NULL, 0, "0 EMM_AS_NAS_INFO_DETACH ue id " MME_UE_S1AP_ID_FMT " ", ue_id);
    /*
     * Setup NAS information message to transfer
     */
    emm_as->nas_info = EMM_AS_NAS_INFO_DETACH;
    emm_as->nas_msg = NULL;
    /*
     * Set the UE identifier
     */
    emm_as->ue_id = ue_id;
    /*
     * Setup EPS NAS security data
     */
    emm_as_set_security_data (&emm_as->sctx, &emm_ctx->_security, false, true);
    /*
     * Notify EMM-AS SAP that Detach Accept message has to
     * be sent to the network
     */
    emm_sap.primitive = EMMAS_DATA_REQ;
    rc = emm_sap_send (&emm_sap);
  }

  /**
   * Although MME_APP and EMM contexts are separated, doing it like this causes the recursion problem.
   *
   * TS 23.401: 5.4.4.1 -> (Although dedicated bearers, works for me).
   *
   * If all the bearers belonging to a UE are released, the MME shall change the MM state of the UE to EMM-
   * DEREGISTERED and the MME sends the S1 Release Command to the eNodeB, which initiates the release of the RRC
   * connection for the given UE if it is not released yet, and returns an S1 Release Complete message to the MME.
   *
   * Don't do it recursively over MME_APP, do it over the EMM/ESM, that's what they're for.
   * So just triggering the ESM (before purging the context, to remove/purge all the PDN connections.
   *
   */

  /** Check if there are any active sessions, if so terminate them all. */
  OAILOG_INFO (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - Attach UE \n", emm_ctx->ue_id);
  /*
   * 3GPP TS 24.401, Figure 5.3.2.1-1, point 5a
   * At this point, all NAS messages shall be protected by the NAS security
   * functions (integrity and ciphering) indicated by the MME unless the UE
   * is emergency attached and not successfully authenticated.
   */

  /*
   * Notify ESM that PDN connectivity is requested
   */

  /*
   * Release ESM PDN and bearer context
   */

  // todo: check that any session exists.
  if(emm_ctx->esm_data_ctx.n_pdns){
    esm_sap_t                               esm_sap = {0};

    esm_sap.primitive = ESM_PDN_DISCONNECT_REQ;
    esm_sap.is_standalone = false;
    esm_sap.ue_id = emm_ctx->ue_id;
    esm_sap.ctx = emm_ctx;
    esm_sap.recv = emm_ctx->esm_msg;
//    esm_sap.data.eps_bearer_context_deactivate.ebi = 5; /**< Default Bearer Id of default APN. */

    ESM_msg                         esm_msg;
    memset (&esm_msg, 0, sizeof (ESM_msg));

    esm_msg.header.message_type = PDN_DISCONNECT_REQUEST;
    esm_msg.header.procedure_transaction_identity = PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED;
//    int
//    _emm_sap_process_esm_message(
//        ESM_msg                                *esm_msg_p,
//        int                                     esm_cause,
//        int                                     is_discarded,
//        int                                     triggered_by_ue,
//        int                                     pti,
//        unsigned int                            ebi,
//        int                                     is_standalone,
//        esm_sap_error_t                        *err,
//        esm_proc_procedure_t                    esm_procedure,
//        emm_data_context_t                     *ctx)

    esm_sap_error_t                         err = ESM_SAP_SUCCESS;
    esm_proc_procedure_t                    esm_procedure = NULL;
    int                                     esm_cause = (-1);
    unsigned int                            default_bearer_id = 5;

//    rc = _emm_sap_process_esm_message (&esm_msg, esm_cause, 0, 0, PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED,
//        default_bearer_id, 1, &err, esm_procedure, &emm_ctx->esm_data_ctx);

    /**
     * Use this temporary function until session removal is implemented in ESM.
     * Method just sends the S11 message. Not doing any deregistration.
     */
    // todo: still deregister the MME_APP UE context from the hashtable with the S11 key..
    rc = mme_api_delete_session_request(ue_id);
    /**
     * Just deal with this later properly.
     * The ESM context will be cleaned up later with the EMM context, without waiting for a response from the SAE-GW.
     */

    // todo: check rc

    /** Not needed anymore. */
    if (emm_ctx->esm_msg) {
      bdestroy(emm_ctx->esm_msg);
    }

    OAILOG_INFO (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - Deactivating PDN Connection via ESM for detach before continuing. \n", emm_ctx->ue_id);
    /**
     * Not waiting for a response. Will assume that the session is correctly purged.. Continuing with the detach and assuming that the SAE-GW session is purged.
     * Assuming, that in 5G AMF/SMF structure, it is like in PCRF, sending DELETE_SESSION_REQUEST and not caring about the response. Assuming the session is deactivated.
     */
  }else{
    /** No PDNs existing, continue with the EMM detach. */
    rc = RETURNok;
  }

  if (rc != RETURNerror) {

    emm_sap_t                               emm_sap = {0};

    /*
     * Notify EMM FSM that the UE has been implicitly detached
     */
    MSC_LOG_TX_MESSAGE (MSC_NAS_EMM_MME, MSC_NAS_EMM_MME, NULL, 0, "0 EMMREG_DETACH_REQ ue id " MME_UE_S1AP_ID_FMT " ", ue_id);
    emm_sap.primitive = EMMREG_DETACH_REQ;
    emm_sap.u.emm_reg.ue_id = ue_id;
    emm_sap.u.emm_reg.ctx = emm_ctx;
    rc = emm_sap_send (&emm_sap);
    // Notify MME APP to trigger S1 signaling release towards S1AP. (not triggering session release towards SGW).
    nas_itti_detach_req(ue_id);
  }

  // Release the emm context, not the ESM context.. Assert that the ESM context is already release.
  _clear_emm_ctxt(emm_ctx);

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNok);
}

/****************************************************************************/
/*********************  L O C A L    F U N C T I O N S  *********************/
/****************************************************************************/
