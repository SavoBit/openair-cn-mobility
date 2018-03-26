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

  Source      emm_cn.c

  Version     0.1

  Date        2013/12/05

  Product     NAS stack

  Subsystem   EPS Core Network

  Author      Sebastien Roux, Lionel GAUTHIER

  Description

*****************************************************************************/

#include <string.h>


#include "log.h"
#include "commonDef.h"

#include "emm_cn.h"
#include "emm_sap.h"
#include "emm_proc.h"
#include "emm_cause.h"

#include "esm_send.h"
#include "esm_proc.h"
#include "esm_cause.h"
#include "assertions.h"
#include "emmData.h"
#include "esm_sap.h"
#include "EmmCommon.h"
#include "3gpp_requirements_24.301.h"

#include "mme_app_ue_context.h"


#include "../../esm/esm_pt.h"

extern int emm_cn_wrapper_attach_accept (emm_data_context_t * emm_ctx, void *data);

/** TAU related Context Request/Fail handling. */
static int _emm_cn_context_res (const emm_cn_context_res_t * msg);
static int _emm_cn_context_fail(const emm_cn_context_fail_t * msg);

static int _emm_cn_pdn_connectivity_fail (const emm_cn_pdn_fail_t * msg);

/*
   Internal data used for attach procedure
*/
typedef struct {
  unsigned int                            ue_id; /* UE identifier        */
#  define ATTACH_COUNTER_MAX  5
  unsigned int                            retransmission_count; /* Retransmission counter   */
  bstring                                 esm_msg;      /* ESM message to be sent within
                                                         * the Attach Accept message    */
} attach_data_t;

/*
   Internal data used for attach procedure
*/
typedef struct handover_data_s {
  unsigned int                            ue_id; /* UE identifier        */
//#define ATTACH_COUNTER_MAX  5
//  unsigned int                            retransmission_count; /* Retransmission counter   */
//  bstring                                 esm_msg;      /* ESM message to be sent within
//                                                         * the Attach Accept message    */
} handover_data_t;

/*
   String representation of EMMCN-SAP primitives
*/
static const char                      *_emm_cn_primitive_str[] = {
  "EMM_CN_AUTHENTICATION_PARAM_RES",
  "EMM_CN_AUTHENTICATION_PARAM_FAIL",
  "EMMCN_CONTEXT_RES",
  "EMMCN_CONTEXT_FAIL",
  "EMMCN_UPDATE_LOCATION_RES",
  "EMMCN_UPDATE_LOCATION_FAIL",
  "EMM_CN_DEREGISTER_UE",
  "EMM_CN_PDN_CONNECTIVITY_RES",
  "EMM_CN_PDN_CONNECTIVITY_FAIL",
  "EMM_CN_PDN_CONNECTIVITY_UPDATE_PENDING",
  "EMMCN_IMPLICIT_DETACH_UE",
  "EMMCN_SMC_PROC_FAIL",
};

//------------------------------------------------------------------------------
static int _emm_cn_authentication_res (const emm_cn_auth_res_t * msg)
{
  emm_data_context_t                     *emm_ctx = NULL;
  int                                     rc = RETURNerror;

  /*
   * We received security vector from HSS. Try to setup security with UE
   */
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_ctx = emm_data_context_get (&_emm_data, msg->ue_id);

  if (emm_ctx == NULL) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - " "Failed to find UE associated to id " MME_UE_S1AP_ID_FMT "...\n", msg->ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }

  /*
   * Copy provided vector to user context
   */
  for (int i = 0; i < msg->nb_vectors; i++) {
    memcpy (emm_ctx->_vector[i].kasme, msg->vector[i]->kasme, AUTH_KASME_SIZE);
    memcpy (emm_ctx->_vector[i].autn,  msg->vector[i]->autn, AUTH_AUTN_SIZE);
    memcpy (emm_ctx->_vector[i].rand, msg->vector[i]->rand, AUTH_RAND_SIZE);
    memcpy (emm_ctx->_vector[i].xres, msg->vector[i]->xres.data, msg->vector[i]->xres.size);
    emm_ctx->_vector[i].xres_size = msg->vector[i]->xres.size;
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Received Vector %u:\n", i);
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Received RAND ..: " RAND_FORMAT "\n", RAND_DISPLAY (emm_ctx->_vector[i].rand));
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Received AUTN ..: " AUTN_FORMAT "\n", AUTN_DISPLAY (emm_ctx->_vector[i].autn));
    OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - Received KASME .: " KASME_FORMAT " " KASME_FORMAT "\n",
        KASME_DISPLAY_1 (emm_ctx->_vector[i].kasme), KASME_DISPLAY_2 (emm_ctx->_vector[i].kasme));
    emm_ctx_set_attribute_present(emm_ctx, EMM_CTXT_MEMBER_AUTH_VECTOR0+i);
  }
  emm_ctx_set_attribute_present(emm_ctx, EMM_CTXT_MEMBER_AUTH_VECTORS);

  ksi_t eksi = 0;
  if (emm_ctx->_security.eksi !=  KSI_NO_KEY_AVAILABLE) {
    AssertFatal(0 !=  0, "emm_ctx->_security.eksi %d", emm_ctx->_security.eksi);
    REQUIREMENT_3GPP_24_301(R10_5_4_2_4__2);
    eksi = (emm_ctx->_security.eksi + 1) % (EKSI_MAX_VALUE + 1);
  }
  if (msg->nb_vectors > 0) {
    int vindex = 0;
    for (vindex = 0; vindex < MAX_EPS_AUTH_VECTORS; vindex++) {
      if (IS_EMM_CTXT_PRESENT_AUTH_VECTOR(emm_ctx, vindex)) {
        break;
      }
    }
    // eksi should always be 0
    AssertFatal(IS_EMM_CTXT_PRESENT_AUTH_VECTOR(emm_ctx, vindex), "TODO No valid vector, should not happen");
    emm_ctx_set_security_vector_index(emm_ctx, vindex);

    /*
     * 3GPP TS 24.401, Figure 5.3.2.1-1, point 5a
     * * * * No EMM context exists for the UE in the network; authentication
     * * * * and NAS security setup to activate integrity protection and NAS
     * * * * ciphering are mandatory.
     */
    rc = emm_proc_authentication (emm_ctx, emm_ctx->ue_id, eksi,
        emm_ctx->_vector[vindex].rand, emm_ctx->_vector[vindex].autn, emm_attach_security, NULL, NULL);

    if (rc != RETURNok) {
      /*
       * Failed to initiate the authentication procedure
       */
      OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - " "Failed to initiate authentication procedure\n");
      emm_ctx->emm_cause = EMM_CAUSE_ILLEGAL_UE;
    }
  } else {
    OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - " "Failed to initiate authentication procedure\n");
    emm_ctx->emm_cause = EMM_CAUSE_ILLEGAL_UE;
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int _emm_cn_authentication_fail (const emm_cn_auth_fail_t * msg)
{
  int                                     rc = RETURNerror;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  rc = emm_proc_attach_reject (msg->ue_id, msg->cause);
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

#include "EpsUpdateType.h"

//------------------------------------------------------------------------------
static
int _emm_cn_update_location_res(const emm_cn_update_loc_res_t * msg)
{
  emm_data_context_t                     *emm_ctx = NULL;
  int                                     rc = RETURNerror;
  /*
   * We received security vector from HSS. Try to setup security with UE
   */
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_ctx = emm_data_context_get (&_emm_data, msg->ue_id);
  if (emm_ctx == NULL) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - " "Failed to find UE associated to id " MME_UE_S1AP_ID_FMT "...\n", msg->ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }
  // todo: updating the subscription information in the EMM data context from the received ULA (like authentication)? --> multi APN // all handled in MME_APP?
  /**
   * Check the TAU status/flag.
   * Depending on the received TAU procedure (must exist, return an TAU accept back).
   */
  if(emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU)){
    /** TAU is in progress. UE should not be EMM_REGISTERED yet but must have SECURITY_CONTEXT (via S10 Context Response). */
    if(emm_ctx->_emm_fsm_status == EMM_DEREGISTERED && IS_EMM_CTXT_PRESENT_SECURITY(emm_ctx)){
      /** UE is deregistered. Check that TAU_ACCEPT is not sent yet and the security context exists.*/
      // todo: this check eventually is not needed..
      if(!(emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU_ACCEPT_SENT) || emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU_REJECT_SENT))){
        /** ULR received for UE in correct state. */
        OAILOG_INFO (LOG_NAS_EMM, "EMM-PROC  - " "Received ULA for UE id " MME_UE_S1AP_ID_FMT " in TAU procedure in correct state. Continuing with TAU_Accept. \n", msg->ue_id);
        /** Get the MME_APP context. */
        EpsUpdateType *epsUpdateType = mme_api_get_epsUpdateType(emm_ctx->ue_id);
        rc = emm_proc_tracking_area_update_accept(emm_ctx->ue_id, epsUpdateType);
        OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
      }else{
        OAILOG_INFO(LOG_MME_APP, "UE context for ue_id " MME_UE_S1AP_ID_FMT ",  is in TAU procedure: ULR NAS indication received but TAU_ACC, TAU_REJ already sent. \n", emm_ctx->ue_id);
        rc = emm_proc_tracking_area_update_reject(emm_ctx->ue_id, SYSTEM_FAILURE);
        OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
      }
    }else{
      OAILOG_INFO(LOG_MME_APP, "UE context for ue_id " MME_UE_S1AP_ID_FMT ", is in TAU procedure, but no security context set yet & not registered. \n", emm_ctx->ue_id);
      rc = emm_proc_tracking_area_update_reject(emm_ctx->ue_id, SYSTEM_FAILURE);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
  }else if (emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_ATTACH)){
    OAILOG_INFO(LOG_MME_APP, "UE with imsi " IMSI_64_FMT ", has received ULR in ATTACH Procedure. "
        "Triggering Session Establishment in SAE-GW.. \n", emm_ctx->_imsi64);
    rc =  mme_api_send_s11_create_session_req(emm_ctx->ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }else {
    DevMessage("UE context for ue_id " + emm_ctx->ue_id " if not in TAU procedure, should not get the UL message. \n");
    // todo: handle this.
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  }
}

//------------------------------------------------------------------------------
static int _emm_cn_update_location_fail (const emm_cn_update_loc_fail_t * msg)
{
  int                                     rc = RETURNerror;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  // todo: check if the cause fits..
  rc = emm_proc_tracking_area_update_reject(msg->ue_id, msg->cause);
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int _emm_cn_smc_fail (const emm_cn_smc_fail_t * msg)
{
  int                                     rc = RETURNerror;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  rc = emm_proc_attach_reject (msg->ue_id, msg->emm_cause);
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int _emm_cn_deregister_ue (const uint32_t ue_id)
{
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - " "TODO deregister UE " MME_UE_S1AP_ID_FMT ", following procedure is a test\n", ue_id);
  emm_proc_detach_request (ue_id, EMM_DETACH_TYPE_EPS /* ??? emm_proc_detach_type_t */ ,
                           0 /*switch_off */ , 0 /*native_ksi */ , 0 /*ksi */ ,
                           NULL /*guti */ , NULL /*imsi */ , NULL /*imei */ );
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int _emm_cn_implicit_detach_ue (const uint32_t ue_id)
{
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  OAILOG_DEBUG (LOG_NAS_EMM, "EMM-PROC Implicit Detach UE" MME_UE_S1AP_ID_FMT "\n", ue_id);
  emm_proc_detach_request (ue_id, EMM_DETACH_TYPE_EPS, 1 /*switch_off */ , 0 /*native_ksi */ , 0 /*ksi */ ,
                           NULL /*guti */ , NULL /*imsi */ , NULL /*imei */ );
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int _emm_cn_pdn_connectivity_res (emm_cn_pdn_res_t * msg_pP)
{
  int                                     rc = RETURNerror;
  struct emm_data_context_s              *emm_ctx_p = NULL;
  esm_proc_pdn_type_t                     esm_pdn_type = ESM_PDN_TYPE_IPV4;

  // nice --> getting stack object and initializing stack parameters
  ESM_msg                                 esm_msg = {.header = {0}};
  EpsQualityOfService                     qos = {0};
  bstring                                 rsp = NULL;
  bool                                    is_standalone = false;    // warning hardcoded
  bool                                    triggered_by_ue = true;  // warning hardcoded
  attach_data_t                          *data_p = NULL;
  int                                     esm_cause = ESM_CAUSE_SUCCESS;
  int                                     pid = 0;
  unsigned int                            new_ebi = 0;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_ctx_p = emm_data_context_get (&_emm_data, msg_pP->ue_id);

  if (emm_ctx_p == NULL) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMMCN-SAP  - " "Failed to find UE associated to id " MME_UE_S1AP_ID_FMT "...\n", msg_pP->ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }

  memset (&esm_msg, 0, sizeof (ESM_msg));

  switch (msg_pP->pdn_type) {
  case IPv4:
    OAILOG_INFO (LOG_NAS_EMM, "EMM  -  esm_pdn_type = ESM_PDN_TYPE_IPV4\n");
    esm_pdn_type = ESM_PDN_TYPE_IPV4;
    break;

  case IPv6:
    OAILOG_INFO (LOG_NAS_EMM, "EMM  -  esm_pdn_type = ESM_PDN_TYPE_IPV6\n");
    esm_pdn_type = ESM_PDN_TYPE_IPV6;
    break;

  case IPv4_AND_v6:
    OAILOG_INFO (LOG_NAS_EMM, "EMM  -  esm_pdn_type = ESM_PDN_TYPE_IPV4V6\n");
    esm_pdn_type = ESM_PDN_TYPE_IPV4V6;
    break;

  default:
    OAILOG_INFO (LOG_NAS_EMM, "EMM  -  esm_pdn_type = ESM_PDN_TYPE_IPV4 (forced to default)\n");
    esm_pdn_type = ESM_PDN_TYPE_IPV4;
  }

  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  qci       = %u \n", msg_pP->qci);
  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  qos.qci   = %u \n", msg_pP->qos.qci);
  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  qos.mbrUL = %u \n", msg_pP->qos.mbrUL);
  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  qos.mbrDL = %u \n", msg_pP->qos.mbrDL);
  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  qos.gbrUL = %u \n", msg_pP->qos.gbrUL);
  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  qos.gbrDL = %u \n", msg_pP->qos.gbrDL);
  qos.bitRatesPresent = 0;
  qos.bitRatesExtPresent = 0;
  //#pragma message "Some work to do here about qos"
  qos.qci = msg_pP->qci;
  qos.bitRates.maxBitRateForUL = 0;     //msg_pP->qos.mbrUL;
  qos.bitRates.maxBitRateForDL = 0;     //msg_pP->qos.mbrDL;
  qos.bitRates.guarBitRateForUL = 0;    //msg_pP->qos.gbrUL;
  qos.bitRates.guarBitRateForDL = 0;    //msg_pP->qos.gbrDL;
  qos.bitRatesExt.maxBitRateForUL = 0;
  qos.bitRatesExt.maxBitRateForDL = 0;
  qos.bitRatesExt.guarBitRateForUL = 0;
  qos.bitRatesExt.guarBitRateForDL = 0;


  /*************************************************************************/
  /*
   * CODE THAT WAS IN esm_recv.c/esm_recv_pdn_connectivity_request()
   */
  /*************************************************************************/
  /*
   * Execute the PDN connectivity procedure requested by the UE
   */
  pid = esm_proc_pdn_connectivity_request (emm_ctx_p, msg_pP->pti, msg_pP->request_type, msg_pP->apn, esm_pdn_type, msg_pP->pdn_addr, NULL, &esm_cause);
  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  APN = %s\n", (char *)bdata(msg_pP->apn));

  if (pid != RETURNerror) {
    /*
     * Create local default EPS bearer context
     */
    rc = esm_proc_default_eps_bearer_context (emm_ctx_p, pid, &new_ebi, &msg_pP->qos, &esm_cause);

    if (rc != RETURNerror) {
      esm_cause = ESM_CAUSE_SUCCESS;
    }
  } else {
    /** Returned error while setting up ESM PDN context.. */
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }

  /**************************************************************************/
  /*
   * END OF CODE THAT WAS IN esm_recv.c/esm_recv_pdn_connectivity_request()
   */
  /**************************************************************************/
  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  APN = %s\n", (char *)bdata(msg_pP->apn));
  /*************************************************************************/
  /*
   * CODE THAT WAS IN esm_sap.c/_esm_sap_recv()
   */
  /*************************************************************************/


  /**
   * UE/MS network capabilities, DRX parameters, can be set with MM EPS Context IE or with the TAU Request.
   * They will be set as present.
   * At handover/TAU case, they only will be validated with TAU_ACCEPT!
   * Allocate a new GUTI with TAU accept (present), validate with TAU_COMPLETE todo: what for cases without TAU_COMPLETE!
   * TAI_LIST VALID & PRESENT WITH TAU_ACCEPT!
   * todo: check ATTACH_ACCEPT further..
   * todo: Setup EPS NAS security data.
   * For HO/TAU procedure, where it is EMM_DEREGISTRATED, it will continue to stay in EMM_DEREGISTRATED state.
   */

  /**
   * No SAP message will be sent. SAP messages are actual message.
   * If there is no subscription context yet, trigger an ULR!
   * todo: some other way to differentiate may be used..
   * Else continue with an attach accept.
   */
  /**
   * Get the UE's EMM context if it exists
   * Checking if the UE has subscription information.
   */
  if(mme_api_is_subscription_known(emm_ctx_p->ue_id) != SUBSCRIPTION_KNOWN){
    /**
     * We assume that this is a handover/TAU procedure. Further values may be checked.
     * The whole ESM procedure is already completed. Setting the bearer status to ESM_EBR_ACTIVE.
     */
    rc =esm_ebr_set_status (emm_ctx_p, new_ebi, ESM_EBR_ACTIVE, true);
    if(rc != RETURNerror){
      /** If we are already in a TAU procedure, continue with the ULR. Else inform the MME_APP layer to continue with the handover procedure. */
      if(emm_ctx_is_specific_procedure(emm_ctx_p, EMM_CTXT_SPEC_PROC_TAU)){
        OAILOG_INFO (LOG_NAS_EMM, "For IMSI " IMSI_64_FMT ", subscription not pulled yet. Triggering S6A_ULR. \n", emm_ctx_p->_imsi64);
        OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC- THE UE with ue_id=" MME_UE_S1AP_ID_FMT ", does not have a subscription profile set. Requesting a new subscription profile. \n",
            emm_ctx_p->ue_id, EMM_CAUSE_IE_NOT_IMPLEMENTED);
        rc = mme_api_send_update_location_request(emm_ctx_p->ue_id);
        OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
      }else{
        /**
         * todo: send a confirmation message to MME_APP to continue with the handover (must send HANDOVER_REQUEST!).
         * todo: check the valid/present parameters there..
         */
      }
    }else{
      /** Perform TAU/HANDOVER Reject and implicit detach. */
      rc = _emm_cn_pdn_connectivity_fail (&((emm_cn_pdn_fail_t){ .ue_id = emm_ctx_p->ue_id, .pti = PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED, .cause = CAUSE_SYSTEM_FAILURE}));
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
  }
  OAILOG_INFO (LOG_NAS_EMM, "For IMSI " IMSI_64_FMT ", subscription already pulled from HSS. Continuing with Attach Accept. \n", emm_ctx_p->_imsi64);
  /** Normal Attach/PDN_Connectivity case. */
  rc = esm_send_activate_default_eps_bearer_context_request (msg_pP->pti, new_ebi,      //msg_pP->ebi,
                                                             &esm_msg.activate_default_eps_bearer_context_request,
                                                             msg_pP->apn, &msg_pP->pco,
                                                             esm_pdn_type, msg_pP->pdn_addr,
                                                             &qos, ESM_CAUSE_SUCCESS);
  clear_protocol_configuration_options(&msg_pP->pco);
  if (rc != RETURNerror) {
    /*
     * Encode the returned ESM response message
     */
    int                                     size = esm_msg_encode (&esm_msg, (uint8_t *) emm_ctx_p->emm_cn_sap_buffer,
                                                                   EMM_CN_SAP_BUFFER_SIZE);

    OAILOG_INFO (LOG_NAS_EMM, "ESM encoded MSG size %d\n", size);

    if (size > 0) {
      rsp = blk2bstr(emm_ctx_p->emm_cn_sap_buffer, size);
    }

    /*
     * Complete the relevant ESM procedure
     */
    rc = esm_proc_default_eps_bearer_context_request (is_standalone, emm_ctx_p, new_ebi,        //0, //ESM_EBI_UNASSIGNED, //msg->ebi,
                                                      &rsp, triggered_by_ue);

    if (rc != RETURNok) {
      /*
       * Return indication that ESM procedure failed
       */
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
  } else {
    OAILOG_INFO (LOG_NAS_EMM, "ESM send activate_default_eps_bearer_context_request failed\n");
  }

  /*************************************************************************/
  /*
   * END OF CODE THAT WAS IN esm_sap.c/_esm_sap_recv()
   */
  /*************************************************************************/
  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  APN = %s\n", (char *)bdata(msg_pP->apn));

  /** No pending handover, so NAS message (attach accept) or retransmission has to be sent.
   * Attach_Data contains the message and further information for retransmission handling (_emm_attach_t4350_handler // _emm_attach_accept_retrx).
   */
  data_p = (attach_data_t *) emm_proc_common_get_args (msg_pP->ue_id);
  /*
   * Setup the ESM message container
   */
  data_p->esm_msg = rsp;
  /*
   * Send attach accept message to the UE
   */
  rc = emm_cn_wrapper_attach_accept (emm_ctx_p, data_p);

  if (rc != RETURNerror) {
    if (IS_EMM_CTXT_PRESENT_OLD_GUTI(emm_ctx_p) &&
        (memcmp(&emm_ctx_p->_old_guti, &emm_ctx_p->_guti, sizeof(emm_ctx_p->_guti)))) {
      /*
       * Implicit GUTI reallocation;
       * * * * Notify EMM that common procedure has been initiated
       */
      emm_sap_t                               emm_sap = {0};

      emm_sap.primitive = EMMREG_COMMON_PROC_REQ;
      emm_sap.u.emm_reg.ue_id = msg_pP->ue_id;
      emm_sap.u.emm_reg.ctx  = emm_ctx_p;
      rc = emm_sap_send (&emm_sap);
    }
  }

  OAILOG_INFO (LOG_NAS_EMM, "EMM  -  APN = %s \n", (char *)bdata(msg_pP->apn));
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int _emm_cn_pdn_connectivity_fail (const emm_cn_pdn_fail_t * msg)
{
  int                                     rc = RETURNok;
  struct emm_data_context_s              *emm_ctx_p = NULL;
  attach_data_t                          *data_p = NULL;
  ESM_msg                                 esm_msg = {.header = {0}};
  int                                     esm_cause; 
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_ctx_p = emm_data_context_get (&_emm_data, msg->ue_id);
  if (emm_ctx_p == NULL) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMMCN-SAP  - " "Failed to find UE associated to id " MME_UE_S1AP_ID_FMT "...\n", msg->ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }
  memset (&esm_msg, 0, sizeof (ESM_msg));
  
  // Map S11 cause to ESM cause
  switch (msg->cause) {
    case CAUSE_CONTEXT_NOT_FOUND:
      esm_cause = ESM_CAUSE_REQUEST_REJECTED_BY_GW; 
      break;
    case CAUSE_INVALID_MESSAGE_FORMAT:
      esm_cause = ESM_CAUSE_REQUEST_REJECTED_BY_GW; 
      break;
    case CAUSE_SERVICE_NOT_SUPPORTED:                  
      esm_cause = ESM_CAUSE_SERVICE_OPTION_NOT_SUPPORTED;
      break;
    case CAUSE_SYSTEM_FAILURE:                        
      esm_cause = ESM_CAUSE_NETWORK_FAILURE; 
      break;
    case CAUSE_NO_RESOURCES_AVAILABLE:           
      esm_cause = ESM_CAUSE_INSUFFICIENT_RESOURCES; 
      break;
    case CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED:  
      esm_cause = ESM_CAUSE_INSUFFICIENT_RESOURCES;
      break;
    default: 
      esm_cause = ESM_CAUSE_REQUEST_REJECTED_BY_GW; 
      break;
  }

  /**
   * If there was an ATTACH procedure running, create/encode the Attach Reject message with the ESM reject.
   */
  if(emm_ctx_is_specific_procedure(emm_ctx_p, EMM_CTXT_SPEC_PROC_TAU)){
    EpsUpdateType *epsUpdateType = mme_api_get_epsUpdateType(emm_ctx_p->ue_id);
    /** Just send a TAU-Reject which also will implicitly remove the UE contexts. No ESM message needed to be encoded. */
    rc = emm_proc_tracking_area_update_reject(emm_ctx_p->ue_id, SYSTEM_FAILURE);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }else if (emm_ctx_is_specific_procedure(emm_ctx_p, EMM_CTXT_SPEC_PROC_ATTACH)){
    rc = esm_send_pdn_connectivity_reject (msg->pti, &esm_msg.pdn_connectivity_reject, esm_cause);
    /** Encode the returned ESM response message. */
    int size = esm_msg_encode (&esm_msg, (uint8_t *) emm_ctx_p->emm_cn_sap_buffer, EMM_CN_SAP_BUFFER_SIZE);
    OAILOG_INFO (LOG_NAS_EMM, "ESM encoded MSG size %d\n", size);
    if (size > 0) {
      data_p = (attach_data_t *) emm_proc_common_get_args (msg->ue_id);
      /** Setup the ESM message container. */
      data_p->esm_msg = blk2bstr(emm_ctx_p->emm_cn_sap_buffer, size);
      rc = emm_proc_attach_reject (msg->ue_id, EMM_CAUSE_ESM_FAILURE);
    }else{
      OAILOG_ERROR(LOG_NAS_EMM, "ESM message PDN_CONNECTIVITY_REJECT could not be encoded for attach reject.\n");
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
    }
  }else{
    OAILOG_ERROR(LOG_NAS_EMM, "No ATTACH or TAU procedure specified for the UE context with IMSI " IMSI_64_FMT " and "
        "mmeUeS1apId " MME_UE_S1AP_ID_FMT " with ESM PDN Connectivity Fail. \n", emm_ctx_p->_imsi64, emm_ctx_p->ue_id);
    // todo: this will be the handover procedure!!
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int _emm_cn_context_res (const emm_cn_context_res_t * msg)
{
  emm_data_context_t                     *emm_ctx = NULL;
  int                                     rc = RETURNerror;
  /**
   * We received security vector from source MME.
   * Directly using received security parameters.
   * If we received already security parameters like UE network capability, ignoring the parameters received from the source MME and using the UE parameters.
   */
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_ctx = emm_data_context_get (&_emm_data, msg->ue_id);
  if (emm_ctx == NULL) { /**< We assume that an MME_APP UE context also should not exist here. */
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - " "Failed to find UE associated to id " MME_UE_S1AP_ID_FMT "...\n", msg->ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }
  /**
   * Set the identity values (IMSI) valid and present.
   * Assuming IMSI is always returned with S10 Context Response and the IMSI hastable registration method validates the received IMSI.
   */
  /**
   * Set the identity values (IMSI) valid and present.
   * Assuming IMSI is always returned with S10 Context Response and the IMSI hastable registration method validates the received IMSI.
   */
  clear_imsi(&emm_ctx->_imsi);
  emm_ctx_set_valid_imsi(emm_ctx, &msg->_imsi, msg->imsi);
  rc = emm_data_context_upsert_imsi(&_emm_data, emm_ctx); /**< Register the IMSI in the hash table. */
  if (rc != RETURNok) {
    OAILOG_ERROR(LOG_NAS_EMM, "EMM-PROC  - " "Error inserting EMM_DATA_CONTEXT for mmeUeS1apId " MME_UE_S1AP_ID_FMT " "
        "for the RECEIVED IMSI " IMSI_64_FMT ". \n", emm_ctx->ue_id, msg->imsi);
    /** Sending TAU or Attach Reject back, which will purge the EMM/MME_APP UE contexts. */
    if(emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU)){
      rc = emm_proc_tracking_area_update_reject(emm_ctx->ue_id, SYSTEM_FAILURE);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
    }else if (emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_ATTACH)){
      rc = emm_proc_attach_reject(emm_ctx->ue_id, msg->cause);
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
    }
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  }

  /**
   * Update the security context & security vectors of the UE independent of TAU/Attach here (set fields valid/present).
   * Then inform the MME_APP that the context was successfully authenticated. Trigger a CSR.
   */
  emm_ctx_update_from_mm_eps_context(emm_ctx, &msg->mm_eps_context);
  OAILOG_INFO(LOG_NAS_EMM, "EMM-PROC  - " "Successfully updated the EMM context from the received MM_EPS_Context from the MME for UE with imsi: " IMSI_64_FMT ". \n", emm_ctx->_imsi64);

  /**
   * Currently, the PDN_CONNECTIVITY_REQUEST ESM IE is not processed by the ESM layer.
   * Later, with multi APN, process it and also the PDN_CONNECTION IE.
   * Currently, just send ITTI signal to build up session via the stored pending PDN information.
   */


  /**
   * Prepare a CREATE_SESSION_REQUEST message from the pending data.
   * NO (default) apn_configuration is present (or expected) since ULA is not sent yet to HSS.
   */
  rc =  mme_app_send_s11_create_session_req_from_handover_tau(emm_ctx->ue_id);
  /** Leave the UE in EMM_DEREGISTERED state until TAU_ACCEPT. */
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

//------------------------------------------------------------------------------
static int _emm_cn_context_fail (const emm_cn_context_fail_t * msg)
{
  int                                     rc = RETURNerror;
  emm_data_context_t                     *emm_ctx = NULL;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  /**
   * An UE could or could not exist. We need to check. If it exists, it needs to be purged.
   * Since no UE context is established yet, we don't have security/no bearers.0
   * If the message is received after the timeout, the MME_APP context also should not exist.
   * If the MME_APP context existed at that point in time, it will later be removed.
   * Just discard the message then.
   */
  emm_ctx = emm_data_context_get (&_emm_data, msg->ue_id);
  if (emm_ctx == NULL) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-PROC  - " "Failed to find UE associated to id " MME_UE_S1AP_ID_FMT "...\n", msg->ue_id);
    /**
     * In this case, don't wait for the timer to remove the rest! Assume no timers exist.
     * Purge the rest of the UE context (MME_APP etc.).
     */
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }

  /**
   * Check the TAU status/flag.
   * Depending on the received TAU procedure (must exist, return an TAU accept back).
   */
  if(emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU) || emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_ATTACH) ){
    /** TAU is in progress. UE should be registered (via S10 Context Response). */
    if(emm_ctx->_emm_fsm_status == EMM_DEREGISTERED && !IS_EMM_CTXT_PRESENT_SECURITY(emm_ctx)){
      /** UE is not registered. Context confirmation for UE with attach reqCheck that TAU_ACCEPT is not sent and the security context exists.*/
      if(!emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU_ACCEPT_SENT) && !emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU_REJECT_SENT)){
        /** Handle the context failure. */
        if(emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_TAU)){
          EpsUpdateType *epsUpdateType = mme_api_get_epsUpdateType(emm_ctx->ue_id);
          rc = emm_proc_tracking_area_update_reject(emm_ctx->ue_id, epsUpdateType);
          OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
        }else if (emm_ctx_is_specific_procedure(emm_ctx, EMM_CTXT_SPEC_PROC_ATTACH)){
          rc = emm_proc_attach_reject(emm_ctx->ue_id, msg->cause);
          OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
        }
      }
    }
  }
  OAILOG_ERROR(LOG_NAS_EMM, "EMM-PROC  - " "UE context failure received for ue_id " MME_UE_S1AP_ID_FMT " which is neither is in TAU nor Attach procedure."
      "Ignoring the UE context failure (NAS s10 context response timer should do the cleanup). \n", emm_ctx->ue_id);
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
}

//------------------------------------------------------------------------------
int emm_cn_send (const emm_cn_t * msg)
{
  int                                     rc = RETURNerror;
  emm_cn_primitive_t                      primitive = msg->primitive;

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  OAILOG_INFO (LOG_NAS_EMM, "EMMCN-SAP - Received primitive %s (%d)\n", _emm_cn_primitive_str[primitive - _EMMCN_START - 1], primitive);

  switch (primitive) {
  case _EMMCN_AUTHENTICATION_PARAM_RES:
    rc = _emm_cn_authentication_res (msg->u.auth_res);
    break;

  case _EMMCN_AUTHENTICATION_PARAM_FAIL:
    rc = _emm_cn_authentication_fail (msg->u.auth_fail);
    break;

  case _EMMCN_UPDATE_LOCATION_RES:
    rc = _emm_cn_update_location_res(msg->u.update_loc_res);
    break;

  case _EMMCN_UPDATE_LOCATION_FAIL:
    rc = _emm_cn_update_location_fail(msg->u.update_loc_fail);
    break;

  case EMMCN_DEREGISTER_UE:
    rc = _emm_cn_deregister_ue (msg->u.deregister.ue_id);
    break;

  // EMMCN messages for handling BEARER MODIFICATION
  case EMMCN_PDN_CONNECTIVITY_RES:
    rc = _emm_cn_pdn_connectivity_res (msg->u.emm_cn_pdn_res);
    break;

  case EMMCN_PDN_CONNECTIVITY_FAIL:
    rc = _emm_cn_pdn_connectivity_fail (msg->u.emm_cn_pdn_fail);
    break;

  case EMMCN_PDN_CONNECTIVITY_UPDATE_PENDING:
    rc = _emm_cn_pdn_connectivity_fail (msg->u.emm_cn_pdn_fail);
    break;

  case EMMCN_IMPLICIT_DETACH_UE:
    rc = _emm_cn_implicit_detach_ue (msg->u.emm_cn_implicit_detach.ue_id);
    break;
  case EMMCN_SMC_PROC_FAIL:
    rc = _emm_cn_smc_fail (msg->u.smc_fail);
    break;

  /** S10 Context Response information. */
  case EMMCN_CONTEXT_RES:
    rc = _emm_cn_context_res (msg->u.context_res);
    break;
  case EMMCN_CONTEXT_FAIL:
    rc = _emm_cn_context_fail (msg->u.context_fail);
    break;

  default:
    /*
     * Other primitives are forwarded to the Access Stratum
     */
    rc = RETURNerror;
    break;
  }

  if (rc != RETURNok) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMMCN-SAP - Failed to process primitive %s (%d)\n", _emm_cn_primitive_str[primitive - _EMMCN_START - 1], primitive);
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}
