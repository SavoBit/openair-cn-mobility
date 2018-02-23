/*
 * Handover.c
 *
 *  Created on: Oct 17, 2017
 * \author Dincer Beken
 * \company Blackned GmbH
 * \email: dbeken@blackned.de
 *
 * \author Andreas Eberlein
 * \company Blackned GmbH
 * \email: aeberlein@blackned.de
 *
 */


#include <string.h>

#include "gcc_diag.h"
#include "bstrlib.h"
#include "dynamic_memory_check.h"
#include "log.h"
#include "msc.h"
#include "obj_hashtable.h"
#include "nas_timer.h"

#include "conversions.h"
#include "3gpp_requirements_24.301.h"
#include "emm_proc.h"
#include "networkDef.h"
#include "emmData.h"
#include "emm_sap.h"
#include "esm_sap.h"
#include "emm_cause.h"
#include "NasSecurityAlgorithms.h"
#include "mme_api.h"
#include "mme_app_defs.h"
#include "mme_app_ue_context.h"
#include "mme_config.h"
#include "nas_itti_messaging.h"


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

static int
_emm_handover_update (
  emm_data_context_t * ctx,
  mme_ue_s1ap_id_t ue_id,
  imsi_t * imsi,
  imei_t * imei,
  const tai_t   * const originating_tai);

static int
_emm_handover_update_security(
  emm_data_context_t  *ctx,
  mme_ue_s1ap_id_t     ue_id,
  ksi_t                ksi,
  count_t              nas_ul_count,
  count_t              nas_dl_count,
  uint8_t              used_eaa,
  uint8_t              used_eia,
  uint8_t              ncc,
  uint8_t              k_asme[32],
  uint8_t              nh[32],
  const tai_t         *const handovered_tai_pP,
  const ue_network_capability_t *const ue_network_cap_pP);

static int
_emm_ho_forward_relocation_request(
    emm_cn_ho_forward_relocation_req_t * msg_pP);

int emm_cn_nas_ho_forward_relocation_request_failed(mme_ue_s1ap_id_t        ue_id){
  MessageDef *message_p = NULL;

  message_p = itti_alloc_new_message(TASK_NAS_MME, NAS_HO_FORWARD_RELOCATION_FAIL);
  memset(&message_p->ittiMsg.nas_ho_forward_relocation_fail, 0, sizeof(itti_nas_ho_forward_reloc_fail_t));

  itti_send_msg_to_task(TASK_MME_APP, INSTANCE_DEFAULT, message_p);
}

int
emm_cn_wrapper_ho_forward_relocation_request(emm_cn_ho_forward_relocation_req_t * msg_pP)
{
  return _emm_ho_forward_relocation_request( msg_pP);
}

static int
_emm_ho_forward_relocation_request(
    emm_cn_ho_forward_relocation_req_t * msg_pP)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_sap_t                               emm_sap = {0};
  int                                     i = 0;
  int                                     rc = RETURNerror;

  OAILOG_INFO(LOG_NAS_EMM, "EMMCN-SAP  - " " Creating new UE NAS context with  " MME_UE_S1AP_ID_FMT " from S10 Forward Relocation Request...\n", msg_pP->ue_id);

  /**
   * Create UE's EMM context
   */
  emm_data_context_t *emm_ctx_p = (emm_data_context_t *) calloc (1, sizeof (emm_data_context_t));
  if (!emm_ctx_p) {
    OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - Failed to create EMM context\n");
    /** Inform the MME_APP layer of the failed relocation in the NAS layer. */
    emm_cn_nas_ho_forward_relocation_request_failed(msg_pP->ue_id);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
  }

  emm_ctx_p->num_attach_request++;
  emm_ctx_p->_security.ncc = 0;
  emm_ctx_p->ue_id      = msg_pP->ue_id;
  OAILOG_NOTICE (LOG_NAS_EMM, "EMM-PROC  - Create EMM context ue_id = " MME_UE_S1AP_ID_FMT "\n", msg_pP->ue_id);
  emm_ctx_p->is_dynamic = true;
  bdestroy(emm_ctx_p->esm_msg);
//    emm_ctx_p->attach_type = type; todo: attach_type handover!
//    emm_ctx_p->additional_update_type = additional_update_type;
  emm_ctx_p->emm_cause = EMM_CAUSE_SUCCESS;
  emm_ctx_p->_emm_fsm_status = EMM_INVALID;
  emm_ctx_p->T3450.id = NAS_TIMER_INACTIVE_ID;
  emm_ctx_p->T3450.sec = T3450_DEFAULT_VALUE;
  emm_ctx_p->T3460.id = NAS_TIMER_INACTIVE_ID;
  emm_ctx_p->T3460.sec = T3460_DEFAULT_VALUE;
  emm_ctx_p->T3470.id = NAS_TIMER_INACTIVE_ID;
  emm_ctx_p->T3470.sec = T3470_DEFAULT_VALUE;
  emm_ctx_p->timer_s6a_auth_info_rsp.id = NAS_TIMER_INACTIVE_ID;
  emm_ctx_p->timer_s6a_auth_info_rsp.sec = TIMER_S6A_AUTH_INFO_RSP_DEFAULT_VALUE;
  emm_ctx_p->timer_s6a_auth_info_rsp_arg = NULL;
  emm_fsm_set_status (msg_pP->ue_id, emm_ctx_p, EMM_DEREGISTERED);

  emm_ctx_p->is_dynamic = false;
  /** Set IMSI. */
//  emm_ctx_p->_imsi64    = msg_pP->imsi;

  /** Clear the context. */
  //  todo: emm_ctx clear for handover?!
  emm_ctx_clear_guti(emm_ctx_p);
  emm_ctx_clear_old_guti(emm_ctx_p);
  emm_ctx_clear_imsi(emm_ctx_p);
  emm_ctx_clear_imei(emm_ctx_p);
  emm_ctx_clear_imeisv(emm_ctx_p);
  emm_ctx_clear_lvr_tai(emm_ctx_p);
  emm_ctx_clear_security(emm_ctx_p);
  emm_ctx_clear_non_current_security(emm_ctx_p);
  emm_ctx_clear_auth_vectors(emm_ctx_p);
  emm_ctx_clear_ms_nw_cap(emm_ctx_p);
  emm_ctx_clear_ue_nw_cap_ie(emm_ctx_p);
  emm_ctx_clear_current_drx_parameter(emm_ctx_p);
  emm_ctx_clear_pending_current_drx_parameter(emm_ctx_p);
  emm_ctx_clear_eps_bearer_context_status(emm_ctx_p);

  /** Set the rest of the security parameters. */
  /** todo: Initialize EMM timers. */
  if (RETURNok != emm_data_context_add (&_emm_data, emm_ctx_p)) {
    OAILOG_CRITICAL(LOG_NAS_EMM, "EMM-PROC  - Attach EMM Context for IMSI " IMSI_64_FMT " and MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT " could not be inserted in hashtables. \n",
        msg_pP->ue_id, msg_pP->imsi);
    /** Inform the MME_APP layer of the failed relocation in the NAS layer. */
    emm_cn_nas_ho_forward_relocation_request_failed(msg_pP->ue_id);
    /** Remove the current NAS/EMM UE context. */
    _clear_emm_ctxt(emm_ctx_p);
    OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
  }
  // todo: last_visited_registered_tai
  //  if (last_visited_registered_tai) {
  //    emm_ctx_set_valid_lvr_tai(new_emm_ctx, last_visited_registered_tai);
  //  } else {
  //    emm_ctx_clear_lvr_tai(new_emm_ctx);
  //  }
  /**
   * Update the EMM context with the current S1AP S10 handover procedure parameters.
   * GUTI will be setup @ TAU time --> UE will enter EMM_COMMON from EMM_REGISTERED.
   */
  // todo: misc at ue network capability --> ucs2//gea.
  /**
   * Update the EMM context with the current attach procedure parameters.
   * todo: assuming no GUTI/OLD-GUTI is present. Always allocating a new GUTI.
   */
  emm_ctx_update_from_mm_eps_context(emm_ctx_p, &msg_pP->mm_ue_eps_context);

  /**
   * No UE identification, authentication, security mode procedures will be performed.
   * NAS ESM context will not be updated.
   * The EMM state change will trigger an CSR in the MME_APP.
   * ULA is not sent/triggered. It will be done at Tc
   * todo: @Handover case, when is ULA exactly sent?
   */

  /** Set the state to registered, state change should trigger the CSR! */
  rc = emm_fsm_set_status (msg_pP->ue_id, emm_ctx_p, EMM_REGISTERED);
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}


/****************************************************************************
 **                                                                        **
 ** Name:    _emm_attach_update()                                      **
 **                                                                        **
 ** Description: Update the EMM context with the given attach procedure    **
 **      parameters.                                               **
 **                                                                        **
 ** Inputs:  ue_id:      UE lower layer identifier                  **
 **      type:      Type of the requested attach               **
 **      ksi:       Security ket sey identifier                **
 **      guti:      The GUTI provided by the UE                **
 **      imsi:      The IMSI provided by the UE                **
 **      imei:      The IMEI provided by the UE                **
 **      eea:       Supported EPS encryption algorithms        **
 **      originating_tai Originating TAI (from eNB TAI)        **
 **      eia:       Supported EPS integrity algorithms         **
 **      esm_msg_pP:   ESM message contained with the attach re-  **
 **             quest                                      **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     ctx:       EMM context of the UE in the network       **
 **      Return:    RETURNok, RETURNerror                      **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
static int
_emm_handover_update (
  emm_data_context_t * ctx,
  mme_ue_s1ap_id_t ue_id,
  imsi_t * imsi,
  imei_t * imei,
  const tai_t   * const originating_tai)
{

  OAILOG_FUNC_IN (LOG_NAS_EMM);
  /*
   * UE identifier
   */
  ctx->ue_id = ue_id;
  /*
   * Emergency bearer services indicator
   */
  ctx->is_emergency = false; // todo: setting attach_type and handover is always no emergency?

  if(originating_tai != NULL){
    ctx->originating_tai = *originating_tai;
  }
  ctx->is_guti_based_attach = false;

  /*
   * The IMSI if provided by the UE
   */
  if (imsi) {
    imsi64_t new_imsi64 = INVALID_IMSI64;
    IMSI_TO_IMSI64(imsi,new_imsi64);
    if (new_imsi64 != ctx->_imsi64) {
      emm_ctx_set_valid_imsi(ctx, imsi, new_imsi64);
      emm_data_context_add_imsi (&_emm_data, ctx);
    }
  }

  /*
   * The IMEI if provided by the UE
   */
  if (imei) {
    emm_ctx_set_valid_imei(ctx, imei);
  }

  /*
   * Attachment indicator
   */
  ctx->is_attached = false;
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNok);
}

static int
_emm_handover_update_security(
  emm_data_context_t  *ctx,
  mme_ue_s1ap_id_t     ue_id,
  ksi_t                ksi,
  count_t              nas_ul_count,
  count_t              nas_dl_count,
  uint8_t              used_eea,
  uint8_t              used_eia,
  uint8_t              ncc,
  uint8_t              k_asme[32],
  uint8_t              nh[32],
  const tai_t         *const handovered_tai_pP,
  const ue_network_capability_t *const ue_network_cap_pP)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  /* NCC */
  ctx->_security.ncc      = ncc;
  /* todo: NH  : difference to NH_conj, K_ASME */
  /* todo: NH  : difference to NH_conj, K_ASME */
  // todo: to set in the security context and in the vector?!
  memcpy(ctx->_security.nh_conj, nh, 32);
  /** KASME. */
  // todo: calculating knas_enc & knas_int.
  // todo: checking if the vector exists, and if not
  memcpy(ctx->_vector[0].kasme, k_asme, 32);

  /*
   * Security key set identifier
   */
  ctx->ue_ksi = ksi;
  // todo: eksi @ security capabilities..
  // todo: ksi --> security vector index?
  emm_ctx_set_security_vector_index(ctx, 0);

  /** NAS counts. */
  ctx->_security.ul_count = nas_ul_count;
  ctx->_security.dl_count = nas_dl_count;

  /** Set the UE Network Capabilities. */
  ctx->_security.selected_algorithms.encryption = used_eea;
  ctx->_security.selected_algorithms.integrity  = used_eia;

  /** Capabilities. */
  ctx->_security.capability.eps_encryption = ue_network_cap_pP->eea;
  ctx->_security.capability.eps_integrity  = ue_network_cap_pP->eia;
  if(ue_network_cap_pP->umts_present){
    ctx->_security.capability.umts_present = ue_network_cap_pP->umts_present;
    ctx->_security.capability.umts_encryption= ue_network_cap_pP->uea;
    ctx->_security.capability.umts_integrity = ue_network_cap_pP->uia;
  }
  // todo: why updating these ones, too? why two times necessary? (for replaying the capabilities?)
  ctx->eea  = ue_network_cap_pP->eea;
  ctx->eia  = ue_network_cap_pP->eia;
  ctx->ucs2 = ue_network_cap_pP->ucs2;
  ctx->uea  = ue_network_cap_pP->uea;
  ctx->uia  = ue_network_cap_pP->uia;
//  todo: ctx->gea  = ue_network_cap_pP->gea;
  ctx->umts_present = ue_network_cap_pP->umts_present;
//  todo: ctx->gprs_present = ue_network_cap_pP->gprs_present; MISC?

  // todo: GPRS pesence!
  if(ue_network_cap_pP->misc_present){
      ctx->_security.capability.umts_present = ue_network_cap_pP->misc_present;
      // todo: gprs stuff!
//      ctx->_security.capability.umts_encryption= ue_network_cap_pP->uea;
//      ctx->_security.capability.umts_integrity = ue_network_cap_pP->uia;
  }
  // todo: separate adding supported network capabilities?!?
  // todo: supported capabilities x2, both equal?
      // todo: ctx->_ue_network_capability_ie.
      // todo: ctx->_security.capability

  // todo: ue_network_capabilities

  /*
   * todo: how to get attach type at handover?! (EPS, IMSI, EMERGENCY)..
   * Emergency bearer services indicator
   */

  /** Derive the KNAS integrity and ciphering keys. */
  emm_ctx_set_security_type(ctx, SECURITY_CTX_TYPE_FULL_NATIVE);
  AssertFatal(EMM_SECURITY_VECTOR_INDEX_INVALID != ctx->_security.vector_index, "Vector index not initialized");
  AssertFatal(MAX_EPS_AUTH_VECTORS >  ctx->_security.vector_index, "Vector index outbound value %d/%d", ctx->_security.vector_index, MAX_EPS_AUTH_VECTORS);
  derive_key_nas (NAS_INT_ALG, ctx->_security.selected_algorithms.integrity,  ctx->_vector[ctx->_security.vector_index].kasme, ctx->_security.knas_int);
  derive_key_nas (NAS_ENC_ALG, ctx->_security.selected_algorithms.encryption, ctx->_vector[ctx->_security.vector_index].kasme, ctx->_security.knas_enc);

  /** Derive the NH-Keys. */

  /** Set the attribute as present and valid!. */
  // todo: how to handle this better?!
  emm_ctx_set_attribute_present(ctx, EMM_CTXT_MEMBER_SECURITY);
  emm_ctx_set_attribute_valid(ctx, EMM_CTXT_MEMBER_SECURITY);

  ctx->originating_tai = *handovered_tai_pP;
  OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNok);
}
