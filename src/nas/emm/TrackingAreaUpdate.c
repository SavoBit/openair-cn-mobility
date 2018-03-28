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
  Source      TrackingAreaUpdate.c

  Version     0.1

  Date        2013/05/07

  Product     NAS stack

  Subsystem   EPS Mobility Management

  Author      Frederic Maurel

  Description Defines the tracking area update EMM procedure executed by the
        Non-Access Stratum.

        The tracking area updating procedure is always initiated by the
        UE and is used to update the registration of the actual tracking
        area of a UE in the network, to periodically notify the availa-
        bility of the UE to the network, for MME load balancing, to up-
        date certain UE specific parameters in the network.

*****************************************************************************/
#include <string.h>             // memcmp, memcpy
#include <stdlib.h>             // malloc, free_wrapper

#include "dynamic_memory_check.h"
#include "assertions.h"
#include "log.h"
#include "msc.h"
#include "nas_timer.h"
#include "3gpp_requirements_24.301.h"
#include "emm_proc.h"
#include "emm_sap.h"
#include "mme_app_defs.h"
#include "emm_cause.h"


/****************************************************************************/
/****************  E X T E R N A L    D E F I N I T I O N S  ****************/
/****************************************************************************/

/****************************************************************************/
/*******************  L O C A L    D E F I N I T I O N S  *******************/
/****************************************************************************/

/*
   --------------------------------------------------------------------------
     Internal data handled by the tracking area update procedure in the MME
   --------------------------------------------------------------------------
*/
/*
   Internal data used for TAU accept procedure
*/
typedef struct tau_accept_data_s {
  unsigned int                            ue_id; /* UE identifier        */
  unsigned int                            active_flag; /* active flag IE in TAU Request  */
  unsigned int                            eps_update_type; /* EPS update type in TAU Request  */
#define TAU_COUNTER_MAX  5
  unsigned int                            retransmission_count; /* Retransmission counter   */

} tau_accept_data_t;

int emm_network_capability_have_changed (
  const emm_data_context_t * ctx,
  int eea,
  int eia,
  int ucs2,
  int uea,
  int uia,
  int gea,
  int umts_present,
  int gprs_present);

/** Check whetever TAU parameters have changed. */
static int
_emm_tau_have_changed (
  const emm_data_context_t * ctx,
  ksi_t ksi,
  guti_t * old_guti,
  int eea,
  int eia,
  int ucs2,
  int uea,
  int uia,
  int gea,
  int umts_present,
  int gprs_present);

/* TODO Commented some function declarations below since these were called from the code that got removed from TAU request
 * handling function. Reason this code was removed: This portion of code was incomplete and was related to handling of
 * some optional IEs /scenarios that were not relevant for the TAU periodic update handling and might have resulted in 
 * unexpected behaviour/instability.
 * At present support for TAU is limited to handling of perodic TAU request only  mandatoty IEs . 
 * Other aspects of TAU are TODOs for future.
 */

//static int _emm_tracking_area_update (void *args);
//static int _emm_tracking_area_update_security (void *args);
static int _emm_tracking_area_update_reject (mme_ue_s1ap_id_t ue_id, int emm_cause);
static int _emm_tracking_area_update_accept (emm_data_context_t * emm_ctx,tau_accept_data_t * data);
static int _emm_tracking_area_update_abort (void *args);

static int
_emm_tracking_area_update_accept_retx (
  emm_data_context_t * emm_ctx,
  tau_accept_data_t * data);
//static int _emm_tracking_area_update_reject_cb(void *args) ;


/****************************************************************************/
/******************  E X P O R T E D    F U N C T I O N S  ******************/
/****************************************************************************/
int
emm_network_capability_have_changed (
  const emm_data_context_t * ctx,
  int eea,
  int eia,
  int ucs2,
  int uea,
  int uia,
  int gea,
  int umts_present,
  int gprs_present)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);

  /*
   * Supported EPS encryption algorithms
   */
  if (eea != ctx->eea) {
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  _emm_network_capability_have_changed: eea 0x%x/0x%x (ctxt)", eea, ctx->eea);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  /*
   * Supported EPS integrity algorithms
   */
  if (eia != ctx->eia) {
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  _emm_network_capability_have_changed: eia 0x%x/0x%x (ctxt)", eia, ctx->eia);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  if (umts_present != ctx->umts_present) {
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  _emm_network_capability_have_changed: umts_present %u/%u (ctxt)", umts_present, ctx->umts_present);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  if ((ctx->umts_present) && (umts_present)) {
    if (ucs2 != ctx->ucs2) {
      OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  _emm_network_capability_have_changed: ucs2 %u/%u (ctxt)", ucs2, ctx->ucs2);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }

    /*
     * Supported UMTS encryption algorithms
     */
    if (uea != ctx->uea) {
      OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  _emm_network_capability_have_changed: uea 0x%x/0x%x (ctxt)", uea, ctx->uea);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }

    /*
     * Supported UMTS integrity algorithms
     */
    if (uia != ctx->uia) {
      OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  _emm_network_capability_have_changed: uia 0x%x/0x%x (ctxt)", uia, ctx->uia);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }
  }

  if (gprs_present != ctx->gprs_present) {
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  _emm_network_capability_have_changed: gprs_present %u/%u (ctxt)", gprs_present, ctx->gprs_present);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  if ((ctx->gprs_present) && (gprs_present)) {
    if (gea != ctx->gea) {
      OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  _emm_network_capability_have_changed: gea 0x%x/0x%x (ctxt)", gea, ctx->gea);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }
  }
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, false);
}

/**
 * Returns SUCCESS --> if the TAU-Request could be validated/not rejected/no retransmission of a previous attach-accept. In that we continue with the handling of the TAU_Request.
 * Return  ERROR   --> ignore the request (might be rejected or the previous attach accept might be retransmitted).
 */
static
int emm_proc_tracking_area_update_validity (emm_data_context_t *emm_ctx, const mme_ue_s1ap_id_t ue_id, const tracking_area_update_request_msg * msg,
    const guti_t * old_guti,
    const int gea, const bool gprs_present){
  emm_sap_t                               emm_sap = {0};
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  mme_ue_s1ap_id_t                        old_ue_id = emm_ctx->ue_id;
  int                                     emm_cause = EMM_CAUSE_SUCCESS;
  int                                     rc = RETURNerror;

  memset((void*)&emm_sap, 0, sizeof(emm_sap_t));

  /**
   * We don't resend the GUTI after it is validated, so the GUTI will never be invalidated.
   * If we have an context without a valid GUTI, this means TAU_ACCEPT is sent but no TAU_COMPLETE is received or the UE is sending TAU_REQ without sending ATTACH_ACCEPT.
   */
  REQUIREMENT_3GPP_24_301(R10_5_5_1_2_7_g);
  if (EMM_REGISTERED != emm_ctx->_emm_fsm_status && !emm_ctx->is_attached && emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_ATTACH_ACCEPT_SENT)) {
    OAILOG_TRACE (LOG_NAS_EMM, "EMM-PROC  - the received TAU request came before the ATTACH_COMPLETE. \n");
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Stop timer T3450 (%d)\n", emm_ctx->T3450.id);
    emm_ctx->T3450.id = nas_timer_stop (emm_ctx->T3450.id);
    MSC_LOG_EVENT (MSC_NAS_EMM_MME, "T3450 stopped UE " MME_UE_S1AP_ID_FMT " ", ue_id);
    /** GUTI must be validated. */
    emm_ctx_set_attribute_valid(emm_ctx, EMM_CTXT_MEMBER_GUTI);
    /**
     * Abort the COMMON procedure of the EMM_CTX.
     * Additionally sending a reject cause back.
     */
    emm_sap.primitive = EMMREG_PROC_ABORT;
    emm_sap.u.emm_reg.ue_id = emm_ctx->ue_id;
    emm_sap_send (&emm_sap); /**< Implicitly detaching the existing UE context. */
    memset((void*)&emm_sap, 0, sizeof(emm_sap_t));
    emm_sap.primitive = EMMCN_IMPLICIT_DETACH_UE;
    emm_sap.u.emm_cn.u.emm_cn_implicit_detach.ue_id = emm_ctx->ue_id;
    emm_sap_send (&emm_sap); /**< Assuming, will set the old_ue_ctx to NULL. */
    rc = emm_proc_tracking_area_update_reject(ue_id, EMM_CAUSE_IMPLICITLY_DETACHED); /**< Will remove the contexts for the TAU-Req. */
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  }
  /** If SMC operation is running on the old UE context, abort it and continue with the new UE initiated TAC. */
  if (emm_ctx_is_common_procedure_running(emm_ctx, EMM_CTXT_COMMON_PROC_SMC)) {
    REQUIREMENT_3GPP_24_301(R10_5_4_3_7_c);
    emm_sap.primitive = EMMREG_PROC_ABORT;
    emm_sap.u.emm_reg.ue_id = emm_ctx->ue_id;
    // TODOdata->notify_failure = true;
    rc = emm_sap_send (&emm_sap);
    /**
     * Aborting a common procedure, not necessarily purges the EMM_CTX, so do it manually.
     * Depends on the abort handler of that common procedure.
     */
    // Allocate new context and process the new request as fresh attach request
    memset((void*)&emm_sap, 0, sizeof(emm_sap_t));
    emm_sap.primitive = EMMCN_IMPLICIT_DETACH_UE;
    emm_sap.u.emm_cn.u.emm_cn_implicit_detach.ue_id = emm_ctx->ue_id;
    rc = emm_sap_send (&emm_sap); /**< Assuming, will set the old_ue_ctx to NULL. */
    /** Continue with the tracking area update request. The old emm_ue_ctx should be NULL. */
    OAILOG_NOTICE (LOG_NAS_EMM, "EMM-PROC  - Removing old UE context in SMC procedure for the UE & continuing with the TAU request for ue_id = " MME_UE_S1AP_ID_FMT "\n", ue_id);
    /** Creating a new EMM_DATA UE context and continuing to process the TAU-Request. */
  }
  // todo: how to guarantee that SMC & IDENT don't run together!
  else if (emm_ctx_is_common_procedure_running(emm_ctx, EMM_CTXT_COMMON_PROC_IDENT)) {
    /** If an identification procedure is running, leave it as it is. Continue as the ue_context is valid. */
    REQUIREMENT_3GPP_24_301(R10_5_4_4_6_f); // continue
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Leaving the old UE context in IDENTIFICATION procedure as it is for IMSI " IMSI_64_FMT " and & continuing with the TAU request for ue_id = " MME_UE_S1AP_ID_FMT "\n",
        emm_ctx->_imsi64, ue_id);
    /**
     * Old EMM_CONTEXT will be in COMMON state.
     * todo: If TAU_COMPLETE comes or Identification Response comes, UE will enter REGISTERED from common?
     */
    // todo: handle this case better (handling 2 common procedures simultaneously).
  }
  /**
   * We set directly the UE & MS network capabilities.
   * If additionally we get them via S10, we will ignore them and receive what is here.
   * Don't validate the UE/MS network capabilities until TAU_ACCEPT is sent (with the existing ones).
   */
  else if (emm_ctx->_emm_fsm_status == EMM_COMMON_PROCEDURE_INITIATED && emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU_ACCEPT_SENT)) {
    if (_emm_tau_have_changed(emm_ctx, msg->naskeysetidentifier.naskeysetidentifier, old_guti,
        msg->uenetworkcapability.eea, msg->uenetworkcapability.eia, msg->uenetworkcapability.ucs2, msg->uenetworkcapability.uea, msg->uenetworkcapability.uia,
        gea, msg->uenetworkcapability.umts_present, gprs_present)) {
      OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - TAU parameters have changed\n");
      REQUIREMENT_3GPP_24_301(R10_5_5_3_2_7_d__1);
      /*
       * If one or more of the information elements in the TRACKING AREA UPDATE REQUEST message differ
       * from the ones received within the previous TRACKING AREA UPDATE REQUEST message, the
       * previously initiated tracking area updating procedure shall be aborted if the TRACKING AREA UPDATE COMPLETE message has not
       * been received and the new tracking area updating procedure shall be progressed;
       */
      emm_ctx->T3450.id = nas_timer_stop (emm_ctx->T3450.id); /**<  Stop the T3450 timer and progress the UE. If the context has been pulled from the MME, & ULA is received continue with the received parameters. */
      // todo: how to clear the "EMM_CTXT_SPEC_PROC_TAU_ACCEPT_SENT" procedure? (assuming not set at all).
      emm_sap.primitive = EMMREG_PROC_ABORT; /**< The TAU_ABORT should set the UE into EMM-DEREGISTERED state. Implicit detach will be performed here. */
      emm_sap.u.emm_reg.ue_id = emm_ctx->ue_id;
      emm_sap.u.emm_reg.ctx = emm_ctx;
      rc = emm_sap_send (&emm_sap);

      memset((void*)&emm_sap, 0, sizeof(emm_sap_t));
      emm_sap.primitive = EMMCN_IMPLICIT_DETACH_UE;
      emm_sap.u.emm_cn.u.emm_cn_implicit_detach.ue_id = emm_ctx->ue_id;
      rc = emm_sap_send (&emm_sap); /**< Assuming, will set the old_ue_ctx to NULL. */
      /** Will continue processing the current TAU-Request. */
    } else {
      REQUIREMENT_3GPP_24_301(R10_5_5_3_2_7_d__2);
      /*
       * - if the information elements do not differ, then the TRACKING AREA UPDATE ACCEPT message shall be resent and the timer
       * T3450 shall be restarted if an ATTACH COMPLETE message is expected. In that case, the retransmission
       * counter related to T3450 is not incremented.
       */
      /** Drop the current TAU-Request, leave the old EMM_CTX. */
      emm_ctx->num_tau_request++;
      tau_accept_data_t *data = (tau_accept_data_t *) emm_proc_common_get_args (ue_id);
      rc = _emm_tracking_area_update_accept_retx(emm_ctx, data);
      /** Error also in case of retransmission. */
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
    }
  } else if ((0 < emm_ctx->num_tau_request) &&
      (!emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU_ACCEPT_SENT) && !emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU_REJECT_SENT))) {
    if (_emm_tau_have_changed(emm_ctx, msg->naskeysetidentifier.naskeysetidentifier, old_guti,
        msg->uenetworkcapability.eea, msg->uenetworkcapability.eia, msg->uenetworkcapability.ucs2, msg->uenetworkcapability.uea, msg->uenetworkcapability.uia,
        gea,
        msg->uenetworkcapability.umts_present,
        gprs_present)) {
      OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - TAU parameters have changed\n");
      REQUIREMENT_3GPP_24_301(R10_5_5_3_2_7_e__1);
      /**
       * If one or more of the information elements in the TAU REQUEST message differs from the ones
       * received within the previous TAU REQUEST message, the previously initiated attach procedure shall
       * be aborted and the new tau procedure shall be executed;
       */
      /**
       * The TAU accept/reject has not been sent yet. Check if this UE has been attached to the current MME or is trying to do an inter-MME TAU.
       */
      /** The UE has not been attached to the current MME. Abort the process and purge the current context. */
      emm_sap.primitive = EMMREG_PROC_ABORT;
      emm_sap.u.emm_reg.ue_id = emm_ctx->ue_id;
      emm_sap.u.emm_reg.ctx = emm_ctx;
      rc = emm_sap_send (&emm_sap);
      // trigger clean up
      memset((void*)&emm_sap, 0, sizeof(emm_sap_t));
      emm_sap.primitive = EMMCN_IMPLICIT_DETACH_UE;
      emm_sap.u.emm_cn.u.emm_cn_implicit_detach.ue_id = emm_ctx->ue_id;
      rc = emm_sap_send (&emm_sap);
      /** Continue with the TAU request fresh. */
    } else {
      REQUIREMENT_3GPP_24_301(R10_5_5_3_2_7_e__2);
      /*
       * If the information elements do not differ, then the network shall continue with the previous tau procedure
       * and shall ignore the second TAU REQUEST message.
       */
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
    }
  }
  /** Return Ok. */
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNok);
}

int
emm_proc_tracking_area_update_request (
  const mme_ue_s1ap_id_t ue_id,
  const tracking_area_update_request_msg * msg,
  int *emm_cause,
  const tai_t *new_tai,
  const tai_t           *last_visited_registered_tai,
  const guti_t * old_guti,
  const int gea,
  const bool gprs_present,
  const nas_message_decode_status_t  * decode_status,
  const bstring nas_msg)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  int                                     rc = RETURNerror;
  emm_data_context_t                     *emm_ctx = NULL;
  ue_context_t                           *ue_context_p = NULL;
  emm_fsm_state_t                         fsm_state = EMM_DEREGISTERED;
  uint8_t                                 active_flag = 0;
  bool                                    ignore_tau_req = false; /**< Will check the condition to ignore the received  TAU there is a duplicate request or not. */

  *emm_cause = EMM_CAUSE_SUCCESS;

  /**
   * Get the UE's EMM context if it exists.
   * Checking if the UE has subscription information.
   */
  ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, ue_id);
  DevAssert(ue_context_p);
  emm_ctx = emm_data_context_get (&_emm_data, ue_id);
  if(!emm_ctx){
    /** Get it via GUTI (S-TMSI not set, getting via GUTI). */
    if((emm_ctx = emm_data_context_get_by_guti (&_emm_data, old_guti) != NULL)){ /**< May be set if S-TMSI is set. */
      OAILOG_DEBUG(LOG_NAS_EMM, "EMM-PROC-  Found a valid UE with correct GUTI " GUTI_FMT " and (old) ue_id " MME_UE_S1AP_ID_FMT ". "
          "Continuing with the Tracking Area Update Request. \n", GUTI_ARG(&emm_ctx->_guti), emm_ctx->ue_id);
    }
  }else{
    OAILOG_DEBUG(LOG_NAS_EMM, "EMM-PROC-  Found a valid UE with new mmeUeS1apId " MME_UE_S1AP_ID_FMT " and GUTI " GUTI_FMT ". "
        "Continuing with the Tracking Area Update Request. \n", ue_id, GUTI_ARG(&emm_ctx->_guti));
  }
  if(emm_ctx){
    mme_ue_s1ap_id_t old_mme_ue_id = emm_ctx->ue_id;
    rc = emm_proc_tracking_area_update_validity (emm_ctx, ue_id, msg, gea, gprs_present, old_guti);
    /** Check if the old emm_ctx is still existing. */
    if(emm_ctx){
      /** We still have the old emm_ctx (was not invalidated/implicitly detached). */
      if(emm_ctx->ue_id != ue_id){
        /** Clean up new UE context that was created to handle new tau request. */
        nas_itti_detach_req(ue_id);  /**< Not sending TAU Reject back. */
        OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - For TAU-Request handling, removing the old ue_id " MME_UE_S1AP_ID_FMT ". \n", ue_id);
      }
    } else{
      OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - For TAU-Request handling, we removed the old UE with ue_id " MME_UE_S1AP_ID_FMT ". \n", old_mme_ue_id);
      /** Continuing depending on the error status. */
    }
    if(rc != RETURNok){
      /** Not continuing with the TAU-Request (it might be rejected, a previous tau accept might have been resent or just ignored). */
      OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - Not continuing with the TAU-Request. \n");
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }else{
      OAILOG_INFO(LOG_NAS_EMM, "EMM-PROC  - Continuing to handle the TAU-Request with the old EMM-CTX for IMSI " IMSI_64_FMT " and " MME_UE_S1AP_ID_FMT ". \n",
          emm_ctx->_imsi64, emm_ctx->ue_id);
    }
  } else{
    OAILOG_INFO(LOG_NAS_EMM, "EMM-PROC  - No old UE_CTX could be found. Continuing to handle the TAU-Request with a new EMM-CTX for mmeUeS1apId " MME_UE_S1AP_ID_FMT ". \n", ue_id);
    /**
     * In both cases, if the the EMM_UE_CONTEXT is removed (old already existing one), check its ue_id. If its the same as the new the new ue_id, then ignore the message,
     * since we purged the MME_APP UE context to answer the message.
     * If the old UE_Context stays and the mme_ue_s1ap_id differs from the new one, just remove the contexts of the new one.
     * The response (or reaction) will be through the old EMM_CTX.
     *
     */
  }
  /** After validation: The TAU-Request can be processed and we have sorted out old EMM_CTX's. */
  if (!emm_ctx) {
    OAILOG_INFO(LOG_NAS_EMM, "EMM-PROC  - Creating a new EMM_CTX for mmeUeS1apId " MME_UE_S1AP_ID_FMT ". \n", ue_id);
    //    if(decode_status->integrity_protected_message != 0 && decode_status->mac_matched == 0){
    /** No matter if it is a security protected message or not, MAC will not be matched. If TAU-Req is handled, the last TAI, should point to the current MME. */
    /** If a security context is available, the message will be discarded. */
    OAILOG_NOTICE (LOG_NAS_EMM, "EMM-PROC  - NAS message IS existing//TAU_MAC not set. Will create a new UE NAS EMM context and forward request to source MME for ue_id = " MME_UE_S1AP_ID_FMT "\n", ue_id);
    /**
     * Before creating UE context check that the originating TAI is reachable.
     * If so, create the UE context, if not send directly an TAU reject back and abort the TAU procedure.
     * No matter if the original NAS message is in or not.
     */
    if(!last_visited_registered_tai){
      OAILOG_ERROR(LOG_NAS_EMM, "EMM-PROC  - Last visited TAI " TAI_FMT " is not present in TAU-Request for UE ue_id = " MME_UE_S1AP_ID_FMT ", where UE has no UE context. Context needs to be created via an initial attach. Cannot get UE context via S10. \n", *last_visited_registered_tai, ue_id);
      rc = emm_proc_tracking_area_update_reject (ue_id, EMM_CAUSE_ILLEGAL_UE);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
    /** Check that the origin TAI is not local. */
    if(mme_api_check_tai_local_mme(last_visited_registered_tai)){
      OAILOG_ERROR(LOG_NAS_EMM, "EMM-PROC  - Originating TAI " TAI_FMT " is configured as the current MME but no UE context exists. Proceeding with TAU_Reject for ue_id = " MME_UE_S1AP_ID_FMT "\n", *last_visited_registered_tai, ue_id);
      rc = emm_proc_tracking_area_update_reject (ue_id, EMM_CAUSE_IMPLICITLY_DETACHED);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
    /** TAI is configured as a neighbor MME. */
    if(!mme_api_check_tai_ngh_existing(last_visited_registered_tai)){
      OAILOG_ERROR(LOG_NAS_EMM, "EMM-PROC  - Last visited TAI " TAI_FMT " is not configured as a MME S10 neighbor. Proceeding with TAU_Reject for ue_id = " MME_UE_S1AP_ID_FMT "\n", *last_visited_registered_tai, ue_id);
      rc = emm_proc_tracking_area_update_reject (ue_id, EMM_CAUSE_IMPLICITLY_DETACHED);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
    /**
     * Originating TAI is configured as an MME neighbor.
     * Will create the UE context and send an S10 UE Context Request. */
    OAILOG_INFO(LOG_NAS_EMM, "EMM-PROC  - Originating TAI is configured as a MME S10 neighbor. Will request UE context from source MME for ue_id = " MME_UE_S1AP_ID_FMT ". Creating a new EMM context. \n", *last_visited_registered_tai, ue_id);
    /** Create a new UE EMM context (may be removed in an error case). */
    emm_ctx = (emm_data_context_t *) calloc (1, sizeof (emm_data_context_t));
    if (!emm_ctx) {
      OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - Failed to create EMM context\n");
      emm_ctx->emm_cause = EMM_CAUSE_ILLEGAL_UE;
      /** Do not accept the UE to attach to the network. */
      rc = _emm_tracking_area_update_reject(ue_id, EMM_CAUSE_NETWORK_FAILURE);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
    /** Initialize the newly created UE context for TAU!. */
    emm_ctx->num_attach_request = 0; /**< Don't increment number of attach requests. */
    emm_ctx->_security.ncc = 0;  /**< Since it did not came from handover, the ENB status is initialized.. NCC can begin from 0. */
    emm_ctx->ue_id = ue_id;
    OAILOG_NOTICE (LOG_NAS_EMM, "EMM-PROC  - Create EMM context ue_id = " MME_UE_S1AP_ID_FMT "\n", ue_id);
    emm_ctx->is_dynamic = true;
    emm_ctx->attach_type = EMM_ATTACH_TYPE_EPS; // todo: can this value be retrieved via S10? Forcing to EPS attach.
    emm_ctx->additional_update_type = msg->additionalupdatetype;
    emm_ctx->emm_cause = EMM_CAUSE_SUCCESS;
    emm_ctx->_emm_fsm_status = EMM_INVALID;
    emm_ctx->T3450.id = NAS_TIMER_INACTIVE_ID;
    emm_ctx->T3450.sec = T3450_DEFAULT_VALUE;
    emm_ctx->T3460.id = NAS_TIMER_INACTIVE_ID;
    emm_ctx->T3460.sec = T3460_DEFAULT_VALUE;
    emm_ctx->T3470.id = NAS_TIMER_INACTIVE_ID;
    emm_ctx->T3470.sec = T3470_DEFAULT_VALUE;
    emm_ctx->timer_s6a_auth_info_rsp.id = NAS_TIMER_INACTIVE_ID;
    emm_ctx->timer_s6a_auth_info_rsp.sec = TIMER_S6A_AUTH_INFO_RSP_DEFAULT_VALUE;
    emm_ctx->timer_s6a_auth_info_rsp_arg = NULL;
    emm_fsm_set_status (ue_id, emm_ctx, EMM_DEREGISTERED); /**< The context will be EMM_DEREGISTERED, untill the UE_CONTEXT is received via S10 from the source MME. */

    /** Clear GUTI, which will be newly allocated and sent with TAU-Accept. */
    emm_ctx_clear_guti(emm_ctx);
    emm_ctx_clear_old_guti(emm_ctx); /**< Set the old GUTI. */
    emm_ctx_clear_imsi(emm_ctx);     // todo
    emm_ctx_clear_imei(emm_ctx);
    emm_ctx_clear_imeisv(emm_ctx);
    emm_ctx_clear_lvr_tai(emm_ctx);  /**< Will be set later in this method. */
    emm_ctx_clear_security(emm_ctx); /**< Will be set with the S10 Context Response. Todo: HSS authentication. */
    emm_ctx_clear_non_current_security(emm_ctx);
    emm_ctx_clear_auth_vectors(emm_ctx);
    emm_ctx_clear_ms_nw_cap(emm_ctx);              /**< Will be set in this method & validated with TAU_ACCEPT (not sent to the UE). */
    emm_ctx_clear_ue_nw_cap_ie(emm_ctx);           /**< Will be set in this method & validated with TAU_ACCEPT (not sent to the UE). */
    emm_ctx_clear_current_drx_parameter(emm_ctx);  /**< Will be set in this method & validated with TAU_ACCEPT (not sent to the UE). */
    emm_ctx_clear_pending_current_drx_parameter(emm_ctx); // todo: unknown parameter!
    emm_ctx_clear_eps_bearer_context_status(emm_ctx);    /**< Will be set present in this method and validated in TAU_COMPLETE (resent with TAU_ACCEPT). */
    /**
     * Set the capability parameters here.
     * Compare with what is in the UE context already stored, they should not be changed.
     * Also compare with what is received from S10. They should stay the same.
     * Validated with TAU-Accept.
     * Supported EPS encryption algorithms
     */
    emm_ctx->eea = msg->uenetworkcapability.eea;
    /** Supported EPS integrity algorithms. */
    emm_ctx->eia = msg->uenetworkcapability.eia;
    emm_ctx->ucs2 = msg->uenetworkcapability.ucs2;
    emm_ctx->uea = msg->uenetworkcapability.uea;
    emm_ctx->uia = msg->uenetworkcapability.uia;
    emm_ctx->gea = gea;
    emm_ctx->umts_present = msg->uenetworkcapability.umts_present;
    emm_ctx->gprs_present = gprs_present;
    // todo: when to set them PRESENT? difference PRESENT/VALID (when setting separately present & valid, when together?) defined in specification?
    /**
     * Initialize EMM timers
     */
    emm_ctx->ue_id = ue_id;
    /**
     * Register the newly created EMM_DATA context.
     * The key in the EMM_DATA_CONTEXT hash table will be the MME_UE_S1AP_ID.
     * Later IMSI will be added, will refer to the ID.
     */
    if (RETURNok != emm_data_context_add (&_emm_data, emm_ctx)) {
      OAILOG_CRITICAL(LOG_NAS_EMM, "EMM-PROC  - Attach EMM Context could not be inserted in hastables\n");
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
    }
    OAILOG_DEBUG(LOG_NAS_EMM, "EMM-PROC-  Will request security context for newly created UE context by Tracking Area Update for ue_id = " MME_UE_S1AP_ID_FMT "from originating TAI " TAI_FMT, "! \n", ue_id, *last_visited_registered_tai);
  }
  /**
   * Increase the TAU_Request counter. No matter if the EMM UE context is new or old, it is validated, that it can handle the TAU Request.
   * This means: TAU_Request is not a duplicate, and we can work with the TAU_REQUEST.
   * This does not mean: TAU_REQUEST has to be accepted.. Still check the reject conditions! */

  emm_ctx->num_tau_request++; /**< Increment number of TAU requests. */
  OAILOG_DEBUG(LOG_NAS_EMM, "EMM-PROC-  Num TAU_REQUESTs for UE with GUTI " GUTI_FMT " and ue_id " MME_UE_S1AP_ID_FMT " is: %d. \n", GUTI_ARG(&emm_ctx->_guti), ue_id, emm_ctx->num_tau_request);

  /** Check for TAU Reject after validating the old context or creating a new one! */
  // todo: further TAU_REJECT conditions!
  if(msg->epsbearercontextstatus){
    OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC- Sending Tracking Area Update: Bearer context update not implemented.\n");
  }

  /** Updated the last visited TA via the new_tai received from the S1AP IEs. */
  if(last_visited_registered_tai){
    OAILOG_INFO (LOG_NAS_EMM, "TrackingAreaUpdate - UPDATING LAST VISITED REGISTERED TAI\n");
    emm_ctx_set_valid_lvr_tai(emm_ctx, last_visited_registered_tai);
    OAILOG_INFO (LOG_NAS_EMM, "TrackingAreaUpdate - UPDATED LAST VISITED REGISTERED TAI\n");
  }else{
    OAILOG_ERROR (LOG_NAS_EMM, "TrackingAreaUpdate - No LAST VISITED REGISTERED TAI PRESENT IN TAU!\n", ue_id);
    /** Deal with it.. */
    emm_ctx_clear_lvr_tai(emm_ctx);
  }

  /** Update the TAI List with the new TAI parameters in the S1AP message. */
  rc = mme_api_add_tai(&emm_ctx->ue_id, &new_tai, &emm_ctx->_tai_list);
  if ( RETURNok == rc) {
    OAILOG_INFO(LOG_NAS_EMM, "TrackingAreaUpdate - Successfully updated TAI list of EMM context!\n");
  } else {
    OAILOG_ERROR(LOG_NAS_EMM, "TrackingAreaUpdate - Error updating TAI list of EMM context!\n");
    rc = emm_proc_tracking_area_update_reject (ue_id, EMM_CAUSE_TA_NOT_ALLOWED);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }

  /** Set the Old-GUTI (event is context there). */
  emm_ctx_set_old_guti((emm_data_context_t * const)emm_ctx, old_guti);
  /** The UE context may have a valid GUTI. It might be equal to the old GUTI? .*/

  /** Set the GUTI-Type (event is context there). */
  if (msg->presencemask & TRACKING_AREA_UPDATE_REQUEST_OLD_GUTI_TYPE_IEI) {
    /** Old GUTI Type present. Not setting anything in the EMM_CTX. */
  }else{
  }

  /**
   * Requirements MME24.301R10_5.5.3.2.4_2
   */
  if (msg->presencemask & TRACKING_AREA_UPDATE_REQUEST_UE_NETWORK_CAPABILITY_IEI) {
    emm_ctx_set_ue_nw_cap_ie((emm_data_context_t * const)emm_ctx, &msg->uenetworkcapability);
  }
  if (msg->presencemask & TRACKING_AREA_UPDATE_REQUEST_MS_NETWORK_CAPABILITY_IEI) {
    emm_ctx_set_attribute_present(emm_ctx, EMM_CTXT_MEMBER_MS_NETWORK_CAPABILITY_IE);
    emm_ctx->_ms_network_capability_ie = msg->msnetworkcapability;
    emm_ctx->gea = (msg->msnetworkcapability.gea1 << 6)| msg->msnetworkcapability.egea;
    emm_ctx->gprs_present = true; /**< Todo: how to find this out? */
  }

  /*
   * Requirements MME24.301R10_5.5.3.2.4_3
   */
  if (msg->presencemask & TRACKING_AREA_UPDATE_REQUEST_UE_RADIO_CAPABILITY_INFORMATION_UPDATE_NEEDED_IEI) {
    if (0 != msg->ueradiocapabilityinformationupdateneeded) {
      // Note: this is safe from double-free errors because it sets to NULL
      // after freeing, which free treats as a no-op.
      free_wrapper((void**) &ue_context_p->ue_radio_capabilities);
      ue_context_p->ue_radio_cap_length = 0;  // Logically "deletes" info
    }
  }

  /*
   * Requirements MME24.301R10_5.5.3.2.4_4
   */
  if (msg->presencemask & TRACKING_AREA_UPDATE_REQUEST_DRX_PARAMETER_IEI) {
    emm_ctx_set_current_drx_parameter((emm_data_context_t * const)emm_ctx, &msg->drxparameter);
  }

  /*
   * Requirement MME24.301R10_5.5.3.2.4_5a
   */
  if (msg->presencemask & TRACKING_AREA_UPDATE_REQUEST_EPS_BEARER_CONTEXT_STATUS_IEI) { /**< Shows which bearer contexts are active. */
    emm_ctx_set_eps_bearer_context_status(emm_ctx, &msg->epsbearercontextstatus); /**< This will indicate bearers in active mode. */
    //#pragma message  "TODO Requirement MME24.301R10_5.5.3.2.4_5a: TAU Request: Deactivate EPS bearers if necessary (S11 Modify Bearer Request)"
    // todo:
  }

  // todo: DRX, UE/MS Network Capabilities, .. etc.. (any old valid parameters could be invalidated again?) with arrival of TAU_REQ after TAU/ATTACH_COMPLETE?.

  /**
   * Requirement MME24.301R10_5.5.3.2.4_6:
   * todo: location area not handled
   *
   * MME24.301R10_5.5.3.2.4_6 Normal and periodic tracking area updating procedure accepted by the network UE - EPS update type
   * If the EPS update type IE included in the TRACKING AREA UPDATE REQUEST message indicates "periodic updating", and the UE was
   * previously successfully attached for EPS and non-EPS services, subject to operator policies the MME should allocate a TAI
   * list that does not span more than one location area.
   */
  /**
   * Mark the specific procedure TAU.
   * todo: Unmark when Reject is sent or timer TAU_ACCEPT runs out (before TAU_COMPLETE)
   * or TAU_COMPLETE arrives. */
  emm_ctx_mark_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU); /**< Just marking and not setting timer (will be set later with TAU_ACCEPT). */
  /**
   * No matter if security context exists or not, request the UE context.
   * It may or may not send an S10 request, depending on pending information.
   * So, for TAU, handover will be transparent.
   */
  if(!IS_EMM_CTXT_PRESENT_SECURITY(emm_ctx)){
    /**
     * Send an S10 context request. Send the PLMN together (will be serving network IE). New TAI not need to be sent.
     * Set the new TAI and the new PLMN to the UE context. In case of a TAC-Accept, will be sent and registered.
     */
    OAILOG_DEBUG (LOG_NAS_EMM, "EMM-PROC- Sending a S10 context request for UE with ue_id=" MME_UE_S1AP_ID_FMT " to old MME. \n", ue_id);
    ue_context_p->pending_tau_epsUpdateType = msg->epsupdatetype;
    /**
     * Directly inform the MME_APP of the new context.
     * Depending on if there is a pending MM_EPS_CONTEXT or not, it should send S10 message..
     * MME_APP needs to register the MME_APP context with the IMSI before sending S6a ULR.
     */
    rc = nas_itti_ue_context_req(ue_id, &emm_ctx->_old_guti, new_tai, last_visited_registered_tai, COMPLETE_TAU_REQUEST_TYPE, nas_msg);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }
  OAILOG_INFO(LOG_NAS_EMM, "EMM-PROC- THE UE with ue_id=" MME_UE_S1AP_ID_FMT ", has already a security context. Checking for a subscription profile. \n", ue_id);
  /** Check if any S6a Subscription information exist, if not pull them from the HSS. */
  if(ue_context_p->subscription_known == SUBSCRIPTION_UNKNOWN) { /**< Means, that the MM UE context is received from the sourc MME already due HO (and only due HO). */
    OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC- THE UE with ue_id=" MME_UE_S1AP_ID_FMT ", does not have a subscription profile set. Requesting a new subscription profile. \n",
        ue_id, EMM_CAUSE_IE_NOT_IMPLEMENTED);
    /** Save the EPS update type. */
    ue_context_p->pending_tau_epsUpdateType = msg->epsupdatetype;
    rc = mme_app_send_s6a_update_location_req(ue_context_p);
  } else{
    OAILOG_DEBUG (LOG_NAS_EMM, "EMM-PROC- Sending Tracking Area Update Accept for UE with valid subscription ue_id=" MME_UE_S1AP_ID_FMT ", active flag=%d)\n", ue_id, active_flag);
    // Handle periodic TAU
    rc = emm_proc_tracking_area_update_accept (ue_id, &msg->epsupdatetype);
  }
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}


/****************************************************************************
 **                                                                        **
 ** Name:    emm_proc_tracking_area_update_complete()                      **
 **                                                                        **
 ** Description: Terminates the TAU procedure upon receiving TAU           **
 **      Complete message from the UE.                             **
 **                                                                        **
 **              3GPP TS 24.301, section 5.5.3.2.4                         **
 **      Upon receiving an TRACKING AREA UPDATE COMPLETE message, the MME  **
 **      shall stop timer T3450, enter state EMM-REGISTERED and consider   **
 **      the GUTI sent in the TRACKING AREA UPDATE ACCEPT message as valid.**
 **                                                                        **
 ** Inputs:  ue_id:      UE lower layer identifier                  **
 **      Others:    _emm_data                                  **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    RETURNok, RETURNerror                      **
 **      Others:    _emm_data, T3450                           **
 **                                                                        **
 ***************************************************************************/
int
emm_proc_tracking_area_update_complete (
  mme_ue_s1ap_id_t ue_id)
{
  emm_data_context_t                     *emm_ctx = NULL;
  int                                     rc = RETURNerror;
  emm_sap_t                               emm_sap = {0};

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - EPS attach complete (ue_id=" MME_UE_S1AP_ID_FMT ")\n", ue_id);
  REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__20);
  /*
   * Release retransmission timer parameters
   */
  emm_proc_common_clear_args(ue_id);

  /*
   * Get the UE context
   */
  emm_ctx = emm_data_context_get (&_emm_data, ue_id);

  if (emm_ctx) {
    /*
     * Upon receiving an ATTACH COMPLETE message, the MME shall stop timer T3450
     */
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Stop timer T3450 (%d)\n", emm_ctx->T3450.id);
    emm_ctx->T3450.id = nas_timer_stop (emm_ctx->T3450.id);
    MSC_LOG_EVENT (MSC_NAS_EMM_MME, "T3450 stopped UE " MME_UE_S1AP_ID_FMT " ", ue_id);
    /*
     * Upon receiving an ATTACH COMPLETE message, the MME shall enter state EMM-REGISTERED
     * and consider the GUTI sent in the ATTACH ACCEPT message as valid.
     */
    emm_ctx_set_attribute_valid(emm_ctx, EMM_CTXT_MEMBER_GUTI);
    emm_data_context_add_guti(&_emm_data, emm_ctx);
    emm_ctx_clear_old_guti(emm_ctx);

    /** No ESM-SAP message. */
  } else {
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - No EMM context exists\n");
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  }

  /*
   * Set the network attachment indicator
   * todo: if the UE is registered via TAU+S10, it will never set as attached?
   */
  if(!emm_ctx->is_attached){
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - EMM context with IMSI " IMSI_64_FMT" for which TAU-Complete is received and GUTI validated, will marked as ATTACHED to enter EMM-REGISTERED state. \n",
        emm_ctx->_imsi64);
    emm_ctx->is_attached = true;
  }else{
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - EMM context with IMSI " IMSI_64_FMT" for which TAU-Complete is received and GUTI validated, is already marked as ATTACHED. \n",
        emm_ctx->_imsi64);
  }
  /*
   * Notify EMM that TAU procedure has successfully completed.
   * This should set the UE into EMM-REGISTERED state.
   */
  emm_sap.primitive = EMMREG_TAU_CNF; /**< There is no reject procedure since nothing is expected. */
  emm_sap.u.emm_reg.ue_id = ue_id;
  emm_sap.u.emm_reg.ctx = emm_ctx;
  rc = emm_sap_send (&emm_sap);
  emm_ctx_unmark_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU); /**< Just marking and not setting timer (will be set later with TAU_ACCEPT). */
  emm_ctx_unmark_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU_ACCEPT_SENT); /**< Just marking and not setting timer (will be set later with TAU_ACCEPT). */
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

/****************************************************************************
 **                                                                        **
 ** Name:    _emm_tau_have_changed()                                **
 **                                                                        **
 ** Description: Check whether the given attach parameters differs from    **
 **      those previously stored when the tau procedure has     **
 **      been initiated.                                           **
 **                                                                        **
 ** Inputs:  ctx:       EMM context of the UE in the network       **
 **      type:      Type of the requested tau                      **
 **      guti:      The GUTI provided by the UE                **
 **      imsi:      The IMSI provided by the UE                **
 **      imei:      The IMEI provided by the UE                **
 **      eea:       Supported EPS encryption algorithms        **
 **      eia:       Supported EPS integrity algorithms         **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    true if at least one of the parameters     **
 **             differs; false otherwise.                  **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
static int
_emm_tau_have_changed (
  const emm_data_context_t * ctx,
  ksi_t ksi,
  guti_t * old_guti,
  int eea,
  int eia,
  int ucs2,
  int uea,
  int uia,
  int gea,
  int umts_present,
  int gprs_present)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);

  /*
   * todo: Emergency bearer services indicator.. Attach type in general?
   */
//  if ((type == EMM_ATTACH_TYPE_EMERGENCY) != ctx->is_emergency) {
//    OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: type EMM_ATTACH_TYPE_EMERGENCY \n", ctx->ue_id);
//    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
//  }

  /*
   * Security key set identifier
   */
  if (ksi != ctx->ue_ksi) {
    OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: ue_ksi %d -> %d \n", ctx->ue_id, ctx->ue_ksi, ksi);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  /*
   * Supported EPS encryption algorithms
   */
  if (eea != ctx->eea) {
    OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: eea 0x%x -> 0x%x \n", ctx->ue_id, ctx->eea, eea);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  /*
   * Supported EPS integrity algorithms
   */
  if (eia != ctx->eia) {
    OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: eia 0x%x -> 0x%x \n", ctx->ue_id, ctx->eia, eia);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  if (umts_present != ctx->umts_present) {
    OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: umts_present %d -> %d \n", ctx->ue_id, ctx->umts_present, umts_present);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  if ((ctx->umts_present) && (umts_present)) {
    if (ucs2 != ctx->ucs2) {
      OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: ucs2 %u -> %u \n", ctx->ue_id, ctx->ucs2, ucs2);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }

    /*
     * Supported UMTS encryption algorithms
     */
    if (uea != ctx->uea) {
      OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: uea %u -> %u \n", ctx->ue_id, ctx->uea, uea);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }

    /*
     * Supported UMTS integrity algorithms
     */
    if (uia != ctx->uia) {
      OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: uia %u -> %u \n", ctx->ue_id, ctx->uia, uia);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }
  }

  if (gprs_present != ctx->gprs_present) {
    OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: gprs_present %u -> %u \n", ctx->ue_id, ctx->gprs_present, gprs_present);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
  }

  if ((ctx->gprs_present) && (gprs_present)) {
    if (gea != ctx->gea) {
      OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed: gea 0x%X -> 0x%X \n", ctx->ue_id, ctx->gea, gea);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }
  }

  /*
   * If the EMM context has a GUTI, the received OLD GUTI should be equal to the stored GUTI.
   */
  if ((old_guti) && (IS_EMM_CTXT_PRESENT_GUTI(ctx))) {
    if (old_guti->m_tmsi != ctx->_guti.m_tmsi) {
      OAILOG_INFO (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed:  old_guti/tmsi " GUTI_FMT " -> " GUTI_FMT "\n", ctx->ue_id, GUTI_ARG(&ctx->_guti), GUTI_ARG(old_guti));
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }
    if ((old_guti->gummei.mme_code != ctx->_guti.gummei.mme_code) ||
        (old_guti->gummei.mme_gid != ctx->_guti.gummei.mme_gid) ||
        (old_guti->gummei.plmn.mcc_digit1 != ctx->_guti.gummei.plmn.mcc_digit1) ||
        (old_guti->gummei.plmn.mcc_digit2 != ctx->_guti.gummei.plmn.mcc_digit2) ||
        (old_guti->gummei.plmn.mcc_digit3 != ctx->_guti.gummei.plmn.mcc_digit3) ||
        (old_guti->gummei.plmn.mnc_digit1 != ctx->_guti.gummei.plmn.mnc_digit1) ||
        (old_guti->gummei.plmn.mnc_digit2 != ctx->_guti.gummei.plmn.mnc_digit2) ||
        (old_guti->gummei.plmn.mnc_digit3 != ctx->_guti.gummei.plmn.mnc_digit3)) {
      OAILOG_INFO (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "  tau changed:  old_guti/tmsi " GUTI_FMT " -> " GUTI_FMT "\n", ctx->ue_id, GUTI_ARG(&ctx->_guti), GUTI_ARG(old_guti));
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, true);
    }
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, false);
}

/****************************************************************************
 **                                                                        **
 ** Name:        emm_proc_tracking_area_update_reject()                    **
 **                                                                        **
 ** Description:                                                           **
 **                                                                        **
 ** Inputs:  ue_id:              UE lower layer identifier                  **
 **                  emm_cause: EMM cause code to be reported              **
 **                  Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **                  Return:    RETURNok, RETURNerror                      **
 **                  Others:    _emm_data                                  **
 **                                                                        **
 ***************************************************************************/
int emm_proc_tracking_area_update_reject (
  const mme_ue_s1ap_id_t ue_id,
  const int emm_cause)
{
  int                                     rc = RETURNerror;
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  rc = _emm_tracking_area_update_reject (ue_id, emm_cause);
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

/****************************************************************************/
/*********************  L O C A L    F U N C T I O N S  *********************/
/****************************************************************************/
int emm_proc_tracking_area_update_accept (
  const mme_ue_s1ap_id_t ue_id, const EpsUpdateType *epsupdatetype)
{
  int                                     rc = RETURNerror;
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_data_context_t                     *emm_ctx_p = emm_data_context_get (&_emm_data, ue_id);
  tau_accept_data_t                      *tau_accept_data_p;
  DevAssert(emm_ctx_p != NULL);
  if (!emm_ctx_p) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  -No EMM context for ue_id %u\n", ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }
  /**
   * Check the EPS Update type:
   * If it is PERIODIC, no common procedure needs to be activated.
   * UE will stay in the same EMM (EMM-REGISTERED) state.
   *
   * Else allocate a new GUTI.
   */
  if(epsupdatetype->epsupdatetypevalue == EPS_UPDATE_TYPE_PERIODIC_UPDATING){
    /**
     * No common procedure needs to be triggered, and no TAU_ACCEPT_DATA needs to be stored.
     * UE will be in the same EMM_REGISTERED state.
     */
    if(emm_ctx_p->_emm_fsm_status != EMM_REGISTERED){
      OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - IMSI " IMSI_64_FMT " is not in EMM_REGISTERED mode but instead %d for PERIODIC_TAU_ACCEPT. "
          "Sending TAU REJECT back and implicitly removing contexts. \n", emm_ctx_p->_imsi64, emm_ctx_p->_emm_fsm_status);
      rc = _emm_tracking_area_update_reject (emm_ctx_p->ue_id, SYSTEM_FAILURE);
    }else{
      /** Send a periodic TAU_ACCEPT back without GUTI, COMMON_PROCEDURE initiation or expecting a TAU_COMPLETE. */
      tau_accept_data_p = &(tau_accept_data_t){.ue_id = emm_ctx_p->ue_id, .retransmission_count = 0, .active_flag = epsupdatetype->activeflag, .eps_update_type = epsupdatetype->epsupdatetypevalue};
      /** Send the TAU accept. */
      // todo: GUTI for periodic TAU?!
      rc = _emm_tracking_area_update_accept (emm_ctx_p, tau_accept_data_p);
      /**
       * All parameters must be validated at this point since valid GUTI.
       * Since we area in EMM_REGISTERED state, check the pending session releasion flag and release the state.
       * Sending 2 consecutive SAP messages are anyway possible.
       */
      DevAssert(emm_ctx_p->_emm_fsm_status == EMM_REGISTERED);
      /**
       * The NAS_INFO (EMM_AS_NAS_DATA_TAU) --> will trigger a bearer removal if the UE is in EMM_REGISTERED state, later in (_emm_as_data_req),
       * depending on the pending bearer removal flag.
       */
      emm_ctx_unmark_specific_procedure(emm_ctx_p, EMM_CTXT_SPEC_PROC_TAU); /**< Just marking and not setting timer (will be set later with TAU_ACCEPT). */

    }
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  }

  /**
   * If no valid GUTI is present, a new GUTI will be allocated in the following tau_accept method.
   * It will determine if COMMON procedure is activated or the timer T3450 will be started.
   * If a GUTI exists, the UE must be in EMM-REGISTERED state, else we send a reject and implicitly detach the UE context.
   */
  if (IS_EMM_CTXT_VALID_GUTI(emm_ctx_p)) { /**< If its invalid --> directly enter EMM-REGISTERED state from EMM-DEREGISTERED state, no T3450, no COMMON_PROCEDURE. */
    /** Assert that the UE is in REGISTERED state. */
    if(emm_ctx_p->_emm_fsm_status != EMM_REGISTERED){
      OAILOG_ERROR(LOG_NAS_EMM, "EMM-PROC  - IMSI " IMSI_64_FMT " has already a valid GUTI "GUTI_FMT " but is not in EMM-REGISTERED state, instead %d. \n",
          emm_ctx_p->_imsi64, GUTI_ARG(&emm_ctx_p->_guti), emm_ctx_p->_emm_fsm_status);
      rc = _emm_tracking_area_update_reject (emm_ctx_p->ue_id, SYSTEM_FAILURE);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
    }
    OAILOG_WARNING(LOG_NAS_EMM, "EMM-PROC  - IMSI " IMSI_64_FMT " has already a valid GUTI "GUTI_FMT ". A new GUTI will not be allocated and send. UE staying in EMM_REGISTERED state. \n",
        emm_ctx_p->_imsi64, GUTI_ARG(&emm_ctx_p->_guti));
    /**
     * Not allocating GUTI. No parameters should be validated here.
     * All the parameters should already be validated with the TAU_COMPLETE/ATTACH_COMPLETE before!
     * todo: check that there are no new parameters (DRX, UE/MS NC,).
     */
    DevAssert(IS_EMM_CTXT_VALID_UE_NETWORK_CAPABILITY(emm_ctx_p));
    DevAssert(IS_EMM_CTXT_VALID_MS_NETWORK_CAPABILITY(emm_ctx_p));
    DevAssert(IS_EMM_CTXT_VALID_CURRENT_DRX_PARAMETER(emm_ctx_p));

    /**
     * Send a TAU-Accept without GUTI.
     * Not waiting for TAU-Complete.
     * Might release bearers depending on the ECM state and the active flag without waiting for TAU-Complete.
     */
    tau_accept_data_p = &(tau_accept_data_t){.ue_id = emm_ctx_p->ue_id, .retransmission_count = 0, .active_flag = epsupdatetype->activeflag, .eps_update_type = epsupdatetype->epsupdatetypevalue};
    /** Send the TAU accept. */
    // todo: GUTI for periodic TAU?!
    rc = _emm_tracking_area_update_accept (emm_ctx_p, tau_accept_data_p);
    emm_ctx_unmark_specific_procedure(emm_ctx_p, EMM_CTXT_SPEC_PROC_TAU); /**< Just marking and not setting timer (will be set later with TAU_ACCEPT). */

    /** No GUTI will be set. State should not be changed. */
    /**
     * All parameters must be validated at this point since valid GUTI.
     * Since we area in EMM_REGISTERED state, check the pending session releasion flag and release the state.
     * Sending 2 consecutive SAP messages are anyway possible.
     */
    DevAssert(emm_ctx_p->_emm_fsm_status == EMM_REGISTERED);
    /**
     * The NAS_INFO (EMM_AS_NAS_DATA_TAU) --> will trigger a bearer removal if the UE is in EMM_REGISTERED state, later in (_emm_as_data_req),
     * depending on the pending bearer removal flag.
     */

    // todo: if later a new GUTI is still send, although a VALID GUTI exists, invalidate the existing valid GUTI of the emm_ctx before sending tau_accept with new_guti.
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }else if (IS_EMM_CTXT_PRESENT_GUTI(emm_ctx_p)){
    /** This case should be handled in the old_context verification when the TAU_REQUEST is arrived. */
    OAILOG_ERROR(LOG_NAS_EMM, "EMM-PROC  - IMSI " IMSI_64_FMT " has a PRESENT but INVALID GUTI "GUTI_FMT ". This indicated a TAU/ATTACH Request "
        "message is received before the complete message for the request before is received by the MME. UE_State %d. \n",
        emm_ctx_p->_imsi64, GUTI_ARG(&emm_ctx_p->_guti), emm_ctx_p->_emm_fsm_status);
    rc = _emm_tracking_area_update_reject (emm_ctx_p->ue_id, SYSTEM_FAILURE);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  } else if (!IS_EMM_CTXT_PRESENT_OLD_GUTI(emm_ctx_p)) {  /**< Cleared with TAU/ATTACH Complete. Should be received with TAU_REQUEST. */
    /** If we received a TAU-Request where no OLD-GUTI is present and also no VALID GUTI, its an error. */
    OAILOG_ERROR(LOG_NAS_EMM, "EMM-PROC  - IMSI " IMSI_64_FMT " has not valid GUTI and OLD-GUTI is not present. UE_State %d. \n",
        emm_ctx_p->_imsi64, emm_ctx_p->_emm_fsm_status);
    rc = _emm_tracking_area_update_reject (emm_ctx_p->ue_id, SYSTEM_FAILURE);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  }
  /**
   * Neither valid nor present GUTI at the MME. Allocating a new GUTI, entering the COMMON_PROCEDURE_INITIATEd state and starting the T3450 timer.
   * Allocate TAU_Accept Data.
   */
  tau_accept_data_p = (tau_accept_data_t *) calloc (1, sizeof (tau_accept_data_t));
  /**
   * Allocate the TAU_ACCEPT data and store it as argument in the common procedure initialization.
   * Initialize common procedure due GUTI reallocation.
   */
  DevAssert(tau_accept_data_p != NULL);
  if (!tau_accept_data_p) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - Memory allocation failure while processing TAU Request. ue_id %u\n", ue_id);
    emm_ctx_p->emm_cause = EMM_CAUSE_PROTOCOL_ERROR;
    rc = _emm_tracking_area_update_reject (emm_ctx_p->ue_id, SYSTEM_FAILURE);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }
  /**
   * Setup ongoing EMM procedure callback functions for common procedure initialization (GUTI-Reallocation).
   * Allocated a emm_common_data_s and sets the allocated argument.
   */
  rc = emm_proc_common_initialize (emm_ctx_p->ue_id, NULL, NULL, NULL, NULL, NULL, _emm_tracking_area_update_abort, tau_accept_data_p);
  /**
   * Set the UE identifier
   */
  tau_accept_data_p->ue_id = emm_ctx_p->ue_id;
  /*
   * Reset the retransmission counter (will increase with each T3450 timeout).
   */
  tau_accept_data_p->retransmission_count = 0;
  /**
   * Set the active_flag indicator and t
   */
  tau_accept_data_p->active_flag = epsupdatetype->activeflag;
  tau_accept_data_p->eps_update_type = epsupdatetype->epsupdatetypevalue;
  /** Send TAU accept to the UE. */
  rc = _emm_tracking_area_update_accept (emm_ctx_p, tau_accept_data_p);
  /**
   * No need to free the tau_data, since in this case, we always send new GUTI and expect TAU_COMPLETE!
   * Inside the TAU_ACCEPT procedure, it will be checked if a new GUTI is/will be allocated (currently depends on active_flag.
   * If so, the T3450 timer will be started in the TAU_ACCEPT method already.
   *
   * The pending bearer removal flag may or may not be set. If the state is COMMON, the bearer will be idled when TAU_COMPLETE received and
   * UE enters EMM_REGISTERED state (in the callback function).
   * If TAU_COMPLETE does not arrive, the T3450 timer will implicitly detach the UE anyway.
   *
   */
  if (rc != RETURNerror) {
    /**
     * A new GUTI must be allocated at this point (PRESENT).
     * OLD_GUTI will be set with TAU_REQUEST (S10/initial).
     */
    if (IS_EMM_CTXT_PRESENT_OLD_GUTI(emm_ctx_p) &&
        (memcmp(&emm_ctx_p->_old_guti, &emm_ctx_p->_guti, sizeof(emm_ctx_p->_guti)))) {
      /**
       * Implicit GUTI reallocation;
       * * * * Notify EMM that common procedure has been initiated
       */
      emm_sap_t                               emm_sap = {0};

      emm_sap.primitive = EMMREG_COMMON_PROC_REQ;
      emm_sap.u.emm_reg.ue_id = ue_id;
      emm_sap.u.emm_reg.ctx  = emm_ctx_p;
      rc = emm_sap_send (&emm_sap);
    } else{
      OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - No new GUTI could be allocated for IMSI " IMSI_64_FMT". \n", emm_ctx_p->_imsi64);
      rc = _emm_tracking_area_update_reject (emm_ctx_p->ue_id, SYSTEM_FAILURE);
    }
  }
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

/* TODO - Compiled out this function to remove compiler warnings since we don't expect TAU Complete from UE as we don't support implicit
 * GUTI re-allocation during TAU procedure.
 */
/*
 * --------------------------------------------------------------------------
 * Timer handlers
 * --------------------------------------------------------------------------
 */

/** \fn void _emm_tau_t3450_handler(void *args);
\brief T3450 timeout handler
On the first expiry of the timer, the network shall retransmit the TRACKING AREA UPDATE ACCEPT
message and shall reset and restart timer T3450. The retransmission is performed four times, i.e. on the fifth
expiry of timer T3450, the tracking area updating procedure is aborted. Both, the old and the new GUTI shall be
considered as valid until the old GUTI can be considered as invalid by the network (see subclause 5.4.1.4).
During this period the network acts as described for case a above.
@param [in]args TAU accept data
*/
//------------------------------------------------------------------------------
static void                            *
_emm_tau_t3450_handler (
  void *args)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  tau_accept_data_t                      *data = (tau_accept_data_t *) (args);

  // Requirement MME24.301R10_5.5.3.2.7_c Abnormal cases on the network side - T3450 time-out
  /*
   * Increment the retransmission counter
   */
  data->retransmission_count += 1;
  OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - T3450 timer expired, retransmission counter = %d", data->retransmission_count);
  /*
   * Get the UE's EMM context
   */
  emm_data_context_t *emm_ctx = emm_ctx = emm_data_context_get (&_emm_data, data->ue_id);

  if (data->retransmission_count < TAU_COUNTER_MAX) {
    /*
     * Send attach accept message to the UE
     */
    _emm_tracking_area_update_accept (emm_ctx, data);
  } else {
    /*
     * Abort the attach procedure
     */
    _emm_tracking_area_update_abort (data);
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, NULL);
}

/* TODO - Compiled out this function to remove compiler warnings since we don't support reauthetication and change in
 * security context during periodic TAU procedure.
  */
#if 0
/** \fn void _emm_tracking_area_update_security(void *args);
    \brief Performs the tracking area update procedure not accepted by the network.
     @param [in]args UE EMM context data
     @returns status of operation
*/
//------------------------------------------------------------------------------
static int
_emm_tracking_area_update_security (
  void *args)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  int                                     rc = RETURNerror;
  emm_data_context_t                     *emm_ctx = (emm_data_context_t *) (args);

  OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Setup NAS security (ue_id=" MME_UE_S1AP_ID_FMT ")", emm_ctx->ue_id);

  /*
   * Create new NAS security context
   */

  emm_ctx_clear_security(emm_ctx);

  /*
   * Initialize the security mode control procedure
   */
  rc = emm_proc_security_mode_control (emm_ctx->ue_id, 0,        // TODO: eksi != 0
                                       emm_ctx->eea, emm_ctx->eia, emm_ctx->ucs2,
                                       emm_ctx->uea, emm_ctx->uia, emm_ctx->gea,
                                       emm_ctx->umts_present, emm_ctx->gprs_present,
                                       _emm_tracking_area_update,
                                       _emm_tracking_area_update_reject_cb,
                                       _emm_tracking_area_update_reject_cb);

  if (rc != RETURNok) {
    /*
     * Failed to initiate the security mode control procedure
     */
    OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - Failed to initiate security mode control procedure");
    emm_ctx->emm_cause = EMM_CAUSE_ILLEGAL_UE;
    /*
     * Do not accept the UE to attach to the network
     */
    rc = _emm_tracking_area_update_reject (emm_ctx->ue_id,emm_ctx->emm_cause);
  }
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}
#endif

/** \fn  _emm_tracking_area_update_reject();
    \brief Performs the tracking area update procedure not accepted by the network.
     @param [in]args UE EMM context data
     @returns status of operation
*/
//------------------------------------------------------------------------------
static int
_emm_tracking_area_update_reject (mme_ue_s1ap_id_t ue_id, int emm_cause) 
  
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  int                                     rc = RETURNok;
  emm_data_context_t                     *emm_ctx = emm_data_context_get (&_emm_data, ue_id);
  emm_sap_t                               emm_sap = {0};

  OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC- Sending Tracking Area Update Reject. ue_id=" MME_UE_S1AP_ID_FMT ", cause=%d)\n",
        ue_id, emm_cause);
  /*
   * Notify EMM-AS SAP that Tracking Area Update Reject message has to be sent
   * onto the network.
   *
   */
  emm_sap.primitive = EMMAS_ESTABLISH_REJ;  /**< To terminate the NAS signaling connection.
                                                 Does not determine in which S1AP message it will be sent.
                                                 Setting NAS_ERR flag evaluated by MME_APP to determine an UE Deregistration. */
  emm_sap.u.emm_as.u.establish.ue_id = ue_id;
  emm_sap.u.emm_as.u.establish.eps_id.guti = NULL;

  emm_sap.u.emm_as.u.establish.emm_cause = emm_cause;
  emm_sap.u.emm_as.u.establish.nas_info = EMM_AS_NAS_INFO_TAU;
  emm_sap.u.emm_as.u.establish.nas_msg = NULL;

  if(_emm_data.conf.t3346_reattachment_timeout > 0 ){
    emm_sap.u.emm_as.u.establish.t3346 = &_emm_data.conf.t3346_reattachment_timeout;
  }

  /*
   * Setup EPS NAS security data
   */
  if (emm_ctx) {
     emm_as_set_security_data (&emm_sap.u.emm_as.u.establish.sctx, &emm_ctx->_security, false, false);
  } else {
      emm_as_set_security_data (&emm_sap.u.emm_as.u.establish.sctx, NULL, false, false);
  }
  rc = emm_sap_send (&emm_sap);

  // Release EMM context 
  if (emm_ctx) {
    if(emm_ctx->is_dynamic) {
      _clear_emm_ctxt(emm_ctx); 
    }
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}
/* TODO Compiled out since it was called in function _emm_tracking_area_update_security that itself is compiled out
 */
#if 0
static int
_emm_tracking_area_update_reject_cb(void *args) {
  int rc = RETURNerror;
  emm_data_context_t *emm_ctx = (emm_data_context_t *) (args);
  if (emm_ctx) {
    return _emm_tracking_area_update_reject(emm_ctx->ue_id, emm_ctx->emm_cause);
  }
  return rc;
}
#endif
/** \fn void _emm_tracking_area_update_accept (emm_data_context_t * emm_ctx,tau_accept_data_t * data);
    \brief Sends ATTACH ACCEPT message and start timer T3450.
     @param [in]emm_ctx UE EMM context data
     @param [in]data    UE TAU accept data
     @returns status of operation (RETURNok, RETURNerror)
*/
//------------------------------------------------------------------------------
static int
_emm_tracking_area_update_accept (
  emm_data_context_t * emm_ctx,
  tau_accept_data_t * data)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  int                                     rc = RETURNok;
  emm_sap_t                               emm_sap = {0};
  int                                     i = 0;

  memset((void*)&emm_sap, 0, sizeof(emm_sap_t)); /**< Set all to 0. */

  /** Get the ECM mode. */
  struct ue_context_s * ue_context_p = mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts, emm_ctx->ue_id);
  DevAssert(ue_context_p);

  if (emm_ctx) {
    /**
     * Fill the "data" IE (instead establish).
     * Should work fine, since everything also included in data.
     *
     * If its an ESTABLISH or DATA message does not depend on the active flag.
     * It depends on the ECM connection state.
     */

    /* If active flag is not set to true in TAU request then just send TAU accept. After sending TAU accept initiate
       * S1 context release procedure for the UE if new GUTI is not sent in TAU accept message. Note - At present implicit GUTI
       * reallocation is not supported and hence GUTI is not sent in TAU accept message.
       */
    if(ue_context_p->ecm_state != ECM_CONNECTED){
       /**
       * Check the active flag. If false, set a notification to release the bearers after TAU_ACCEPT/COMPLETE (depending on the EMM state).
       */
      if(!data->active_flag){
        ue_context_p->pending_bearer_deactivation = true; /**< No matter if we send GUTI and wait for TAU_COMPLETE or not. */
        emm_sap.primitive = EMMAS_DATA_REQ;
      }else{
        /**
         * Notify EMM-AS SAP that Tracking Area Update Accept message together with an Activate
         * Default EPS Bearer Context Request message has to be sent to the UE.
         *
         * When the "Active flag" is not set in the TAU Request message and the Tracking Area Update was not initiated
         * in ECM-CONNECTED state, the new MME releases the signaling connection with UE, according to clause 5.3.5.
         */
        emm_sap.primitive = EMMAS_ESTABLISH_CNF;
        ue_context_p->pending_bearer_deactivation = false; /**< No matter if we send GUTI and wait for TAU_COMPLETE or not. */
      }
    }else{
      emm_sap.primitive = EMMAS_DATA_REQ;
      ue_context_p->pending_bearer_deactivation = false; /**< No matter if we send GUTI and wait for TAU_COMPLETE or not. */
    }
    /** Set the rest as data. */
    emm_sap.u.emm_as.u.data.ue_id = emm_ctx->ue_id; /**< These should also set for data. */
    emm_sap.u.emm_as.u.data.nas_info = EMM_AS_NAS_DATA_TAU;

    NO_REQUIREMENT_3GPP_24_301(R10_5_5_3_2_4__3);
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_3_2_4__4);
    emm_ctx_set_attribute_valid(emm_ctx, EMM_CTXT_MEMBER_UE_NETWORK_CAPABILITY_IE);
    emm_ctx_set_attribute_valid(emm_ctx, EMM_CTXT_MEMBER_MS_NETWORK_CAPABILITY_IE);
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_3_2_4__5);
    emm_ctx_set_valid_current_drx_parameter(emm_ctx, &emm_ctx->_pending_drx_parameter);
    emm_ctx_clear_pending_current_drx_parameter(emm_ctx);
    //----------------------------------------
    /*
     * Set the GUTI.
     */
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_3_2_4__1b);
    if (!IS_EMM_CTXT_PRESENT_GUTI(emm_ctx)) {
      // Sure it is an unknown GUTI in this MME
      guti_t old_guti = emm_ctx->_old_guti;
      // todo: this is cool
      guti_t guti     = {.gummei.plmn = {0},
          .gummei.mme_gid = 0,
          .gummei.mme_code = 0,
          .m_tmsi = INVALID_M_TMSI};
      clear_guti(&guti);
      /** New GUTI is allocated when ATTACH_ACCEPT/TAU_ACCEPT is sent. */
      rc = mme_api_new_guti (&emm_ctx->_imsi, &old_guti, &guti, &emm_ctx->originating_tai, &emm_ctx->_tai_list); /**< This will increment/update the TAI_LIST. */
      if ( RETURNok != rc) {
        OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC- Error allocating GUTI @ TAU_ACCEPT for ue_id=" MME_UE_S1AP_ID_FMT ", \n", emm_ctx->ue_id);
        OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
      }
      emm_ctx_set_guti(emm_ctx, &guti); /**< Set the GUTI as present and continue. */
      emm_ctx_set_attribute_valid(emm_ctx, EMM_CTXT_MEMBER_TAI_LIST);

      /** Set the GUTI fields. */
      emm_sap.u.emm_as.u.data.eps_id.guti = &emm_ctx->_guti;


    }
    //----------------------------------------
    /**
     * Set the TAI_LIST valid with TAI_ACCEPT. todo: not checking what it was?
     */
    REQUIREMENT_3GPP_24_301(R10_5_5_3_2_4__1c);
    emm_sap.u.emm_as.u.data.tai_list.list_type = emm_ctx->_tai_list.list_type;
    emm_sap.u.emm_as.u.data.tai_list.n_tais    = emm_ctx->_tai_list.n_tais;
    for (i=0; i < emm_ctx->_tai_list.n_tais; i++) {
      memcpy(&emm_sap.u.emm_as.u.data.tai_list.tai[i], &emm_ctx->_tai_list.tai[i], sizeof(tai_t));
    }

    /** An old GUTI must always exist. */
    if (!IS_EMM_CTXT_VALID_GUTI(emm_ctx) &&
         IS_EMM_CTXT_PRESENT_GUTI(emm_ctx) &&
         IS_EMM_CTXT_PRESENT_OLD_GUTI(emm_ctx)) {
      /*
       * Implicit GUTI reallocation;
       * include the new assigned GUTI in the Tracking Area Update Accept message
       */
      OAILOG_INFO (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - Implicit GUTI reallocation, include the new assigned GUTI in the Tracking Area Update Accept message\n",
          emm_ctx->ue_id);
      emm_sap.u.emm_as.u.data.new_guti    = &emm_ctx->_guti;
      emm_sap.u.emm_as.u.data.eps_id.guti = &emm_ctx->_guti;
    } else {
      OAILOG_INFO (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - UE with IMSI " IMSI_64_FMT " has already a valid GUTI " GUTI_FMT ". "
          "Not including new GUTI in Tracking Area Update Accept message\n", emm_ctx->_imsi, GUTI_ARG(&emm_ctx->_guti));
      emm_sap.u.emm_as.u.data.new_guti  = NULL;
    }
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__14);
    emm_sap.u.emm_as.u.data.eps_network_feature_support = &_emm_data.conf.eps_network_feature_support;
    emm_sap.u.emm_as.u.data.eps_update_result = data->eps_update_type; /**< Set the UPDATE_RESULT irrelevant of data/establish. */
    emm_sap.u.emm_as.u.data.nas_msg = NULL;

    // TODO : Not setting these values..
//    emm_sap.u.emm_as.u.data.eps_bearer_context_status = NULL;
//    emm_sap.u.emm_as.u.data.location_area_identification = NULL;
//    emm_sap.u.emm_as.u.data.combined_tau_emm_cause = NULL;

    /*
     * Setup EPS NAS security data
     */
    emm_as_set_security_data (&emm_sap.u.emm_as.u.data.sctx, &emm_ctx->_security, false, true);
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - encryption = 0x%X ", emm_sap.u.emm_as.u.data.encryption);
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - integrity  = 0x%X ", emm_sap.u.emm_as.u.data.integrity);
    emm_sap.u.emm_as.u.data.encryption = emm_ctx->_security.selected_algorithms.encryption;
    emm_sap.u.emm_as.u.data.integrity = emm_ctx->_security.selected_algorithms.integrity;
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - encryption = 0x%X (0x%X)", emm_sap.u.emm_as.u.data.encryption, emm_ctx->_security.selected_algorithms.encryption);
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - integrity  = 0x%X (0x%X)", emm_sap.u.emm_as.u.data.integrity, emm_ctx->_security.selected_algorithms.integrity);
    
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_3_2_4__20);
    emm_sap.u.emm_as.u.data.eps_network_feature_support = &_emm_data.conf.eps_network_feature_support;
    /*
     * Setup EPS NAS security data
     */
    emm_as_set_security_data (&emm_sap.u.emm_as.u.data.sctx, &emm_ctx->_security, false, true);
    rc = emm_sap_send (&emm_sap); /**< This may be a DL_DATA_REQ or an ESTABLISH_CNF, initiating an S1AP connection. */

    if (rc != RETURNerror) {
      if (emm_sap.u.emm_as.u.establish.new_guti != NULL) { /**< A new GUTI was included. Start the timer to wait for TAU_COMPLETE. */
        if (emm_ctx->T3450.id != NAS_TIMER_INACTIVE_ID) {
          /*
           * Re-start T3450 timer
           */
            emm_ctx->T3450.id = nas_timer_restart (emm_ctx->T3450.id);
            MSC_LOG_EVENT (MSC_NAS_EMM_MME, "T3450 restarted UE " MME_UE_S1AP_ID_FMT " (TAU)", data->ue_id);
          } else {
            /*
             * Start T3450 timer
             */
            emm_ctx->T3450.id = nas_timer_start (emm_ctx->T3450.sec, _emm_tau_t3450_handler, data);
            MSC_LOG_EVENT (MSC_NAS_EMM_MME, "T3450 started UE " MME_UE_S1AP_ID_FMT " (TAU)", data->ue_id);
          }
        OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Timer T3450 (%d) expires in %ld seconds (TAU)", emm_ctx->T3450.id, emm_ctx->T3450.sec);
      }
    }
  } else {
    OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - emm_ctx NULL");
  }
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

/****************************************************************************
 **                                                                        **
 ** Name:    _emm_tracking_area_update_accept_retx()                              **
 **                                                                        **
 ** Description: Retransmit TRACKING AREA UPDATE ACCEPT message and restart timer T3450  **
 **                                                                        **
 ** Inputs:  data:      Tracking Area Update accept retransmission data                  **
 **      Others:    None                                                   **
 ** Outputs:     None                                                      **
 **      Return:    RETURNok, RETURNerror                                  **
 **      Others:    T3450                                                  **
 **                                                                        **
 ***************************************************************************/
static int
_emm_tracking_area_update_accept_retx (
  emm_data_context_t * emm_ctx,
  tau_accept_data_t * data)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_sap_t                               emm_sap = {0};
  int                                     i = 0;
  int                                     rc = RETURNerror;
  if (!emm_ctx) {
      OAILOG_WARNING (LOG_NAS_EMM, "emm_ctx NULL\n");
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
  if (!IS_EMM_CTXT_PRESENT_GUTI(emm_ctx)) { /**< It must be present or validated. */
    OAILOG_WARNING (LOG_NAS_EMM, " No GUTI present in emm_ctx. Abormal case. Skipping Retx of Attach Accept NULL\n");
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }
  /*
   * Notify EMM-AS SAP that Tracking Area Update Accept message has to be sent to the UE.
   * Retx of Tracking Area Update Accept needs to be done via DL NAS Transport S1AP message
   */
  emm_sap.primitive = EMMAS_DATA_REQ; /**< Send it as an DATA request (not initial). */
  emm_sap.u.emm_as.u.data.ue_id = emm_ctx->ue_id;
  emm_sap.u.emm_as.u.data.nas_info = EMM_AS_NAS_DATA_TAU;
  emm_sap.u.emm_as.u.data.tai_list.list_type = emm_ctx->_tai_list.list_type;
  emm_sap.u.emm_as.u.data.tai_list.n_tais    = emm_ctx->_tai_list.n_tais;
  for (i = 0; i < emm_ctx->_tai_list.n_tais; i++) {
    memcpy(&emm_sap.u.emm_as.u.data.tai_list.tai[i], &emm_ctx->_tai_list.tai[i], sizeof(tai_t));
  }
  /** If the GUTI is not validated, add the GUTI, else don't add the GUTI, not to enter COMMON state. */
  if(!IS_EMM_CTXT_VALID_GUTI(emm_ctx)){
    emm_sap.u.emm_as.u.data.eps_id.guti = &emm_ctx->_guti;
    OAILOG_DEBUG (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - Include the same GUTI " GUTI_FMT " in the Tracking Area Update Accept Retx message. \n", emm_ctx->ue_id, GUTI_ARG(&emm_ctx->_guti));
    emm_sap.u.emm_as.u.data.new_guti    = &emm_ctx->_guti;
  }else{
    OAILOG_DEBUG (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - Not including the validated GUTI " GUTI_FMT " in the Tracking Area Update Accept Retx message. \n", emm_ctx->ue_id, GUTI_ARG(&emm_ctx->_guti));
  }
  /** State won't be changed. */
  emm_sap.u.emm_as.u.data.eps_network_feature_support = &_emm_data.conf.eps_network_feature_support;
  /*
   * Setup EPS NAS security data
   */
  emm_as_set_security_data (&emm_sap.u.emm_as.u.data.sctx, &emm_ctx->_security, false, true);
  OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - encryption = 0x%X ", emm_sap.u.emm_as.u.data.encryption);
  OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - integrity  = 0x%X ", emm_sap.u.emm_as.u.data.integrity);
  emm_sap.u.emm_as.u.data.encryption = emm_ctx->_security.selected_algorithms.encryption;
  emm_sap.u.emm_as.u.data.integrity = emm_ctx->_security.selected_algorithms.integrity;
  OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - encryption = 0x%X (0x%X)", emm_sap.u.emm_as.u.data.encryption, emm_ctx->_security.selected_algorithms.encryption);
  OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - integrity  = 0x%X (0x%X)", emm_sap.u.emm_as.u.data.integrity, emm_ctx->_security.selected_algorithms.integrity);

  rc = emm_sap_send (&emm_sap);

  if (RETURNerror != rc) {
    OAILOG_INFO (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  -Sent Retx Tracking Area Update Accept message\n", emm_ctx->ue_id);
    /*
     * Re-start T3450 timer
     */
    emm_ctx->T3450.id = nas_timer_restart (emm_ctx->T3450.id);
    OAILOG_DEBUG (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  T3450 restarted\n", emm_ctx->ue_id);
    OAILOG_DEBUG (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "Timer T3450 (%d) expires in %ld seconds\n",
      emm_ctx->ue_id, emm_ctx->T3450.id, emm_ctx->T3450.sec);
  } else {
    OAILOG_WARNING (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - Send failed- Retx Tracking Area Update Accept message\n", emm_ctx->ue_id);
  }
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int
_emm_tracking_area_update_abort (
  void *args)
{
  int                                     rc = RETURNerror;
  emm_data_context_t                     *ctx = NULL;
  tau_accept_data_t                      *data;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  data = (tau_accept_data_t *) (args);

  if (data) {
    unsigned int                            ue_id = data->ue_id;

    OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - Abort the TAU procedure (ue_id=" MME_UE_S1AP_ID_FMT ")", ue_id);
    ctx = emm_data_context_get (&_emm_data, ue_id);

    if (ctx) {
      /*
       * Stop timer T3450
       */
      if (ctx->T3450.id != NAS_TIMER_INACTIVE_ID) {
        OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Stop timer T3450 (%d)", ctx->T3450.id);
        ctx->T3450.id = nas_timer_stop (ctx->T3450.id);
        MSC_LOG_EVENT (MSC_NAS_EMM_MME, "T3450 stopped UE " MME_UE_S1AP_ID_FMT " (TAU)", data->ue_id);
      }
    }

    /*
     * Release retransmission timer parameters
     */
    // no contained struct to free
    free_wrapper ((void**) &data);

    /*
     * Notify EMM that EPS tau procedure failed
     */
    emm_sap_t                               emm_sap = {0};

    emm_sap.primitive = EMMREG_TAU_REJ;
    emm_sap.u.emm_reg.ue_id = ue_id;
    emm_sap.u.emm_reg.ctx = ctx;
    rc = emm_sap_send (&emm_sap);
  }
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}
