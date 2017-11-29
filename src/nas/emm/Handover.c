/*
 * Handover.c
 *
 *  Created on: Oct 17, 2017
 *      Author: admin
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

static int                              _emm_handover (
  emm_data_context_t * emm_ctx,
  handover_data_t * data);


int
emm_cn_wrapper_handover (
  emm_data_context_t * emm_ctx,
  void *data)
{
  return _emm_handover (emm_ctx, (handover_data_t *) data);
}

static int
_emm_handover(
  emm_data_context_t * emm_ctx,
  handover_data_t * data)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  emm_sap_t                               emm_sap = {0};
  int                                     i = 0;
  int                                     rc = RETURNerror;

  // todo: handovr rejection!
  // may be caused by timer not stopped when deleted context
  if (emm_ctx) {
    /*
     * Notify EMM-AS SAP that Attach Accept message together with an Activate
     * Default EPS Bearer Context Request message has to be sent to the UE
     */
    emm_sap.primitive = EMMAS_HO_BEARER_MODIFICATION_CNF;
    emm_sap.u.emm_as.u.establish.ue_id = emm_ctx->ue_id;
    emm_sap.u.emm_as.u.establish.nas_info = EMM_AS_NAS_INFO_HO;

    NO_REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__3);
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__4);
//    emm_ctx_set_attribute_valid(emm_ctx, EMM_CTXT_MEMBER_UE_NETWORK_CAPABILITY_IE);
//    emm_ctx_set_attribute_valid(emm_ctx, EMM_CTXT_MEMBER_MS_NETWORK_CAPABILITY_IE);
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__5);
//    emm_ctx_set_valid_current_drx_parameter(emm_ctx, &emm_ctx->_pending_drx_parameter);
//    emm_ctx_clear_pending_current_drx_parameter(emm_ctx);
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__9);
    // the set of emm_sap.u.emm_as.u.establish.new_guti is for including the GUTI in the attach accept message
    //ONLY ONE MME NOW NO S10
    // todo: if there are multiple MME via S10, what happens?
//    if (!IS_EMM_CTXT_PRESENT_GUTI(emm_ctx)) {
//      // Sure it is an unknown GUTI in this MME
//      guti_t old_guti = emm_ctx->_old_guti;
//      // todo: this is cool
//      guti_t guti     = {.gummei.plmn = {0},
//                         .gummei.mme_gid = 0,
//                         .gummei.mme_code = 0,
//                         .m_tmsi = INVALID_M_TMSI};
//      clear_guti(&guti);
//
//      rc = mme_api_new_guti (&emm_ctx->_imsi, &old_guti, &guti, &emm_ctx->originating_tai, &emm_ctx->_tai_list);
//      if ( RETURNok == rc) {
//        emm_ctx_set_guti(emm_ctx, &guti);
//        emm_ctx_set_attribute_valid(emm_ctx, EMM_CTXT_MEMBER_TAI_LIST);
//        //----------------------------------------
//        REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__6);
//        REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__10);
//        emm_sap.u.emm_as.u.establish.tai_list.list_type = emm_ctx->_tai_list.list_type;
//        emm_sap.u.emm_as.u.establish.tai_list.n_tais    = emm_ctx->_tai_list.n_tais;
//        for (i=0; i < emm_ctx->_tai_list.n_tais; i++) {
//          memcpy(&emm_sap.u.emm_as.u.establish.tai_list.tai[i], &emm_ctx->_tai_list.tai[i], sizeof(tai_t));
//        }
//      } else {
//        OAILOG_FUNC_RETURN (LOG_NAS_EMM, RETURNerror);
//      }
//    } else {
//      // Set the TAI attributes from the stored context for resends.
//      emm_sap.u.emm_as.u.establish.tai_list.list_type = emm_ctx->_tai_list.list_type;
//      emm_sap.u.emm_as.u.establish.tai_list.n_tais    = emm_ctx->_tai_list.n_tais;
//      for (i=0; i < emm_ctx->_tai_list.n_tais; i++) {
//        memcpy(&emm_sap.u.emm_as.u.establish.tai_list.tai[i], &emm_ctx->_tai_list.tai[i], sizeof(tai_t));
//      }
//    }

//    emm_sap.u.emm_as.u.establish.eps_id.guti = &emm_ctx->_guti;

//    if (!IS_EMM_CTXT_VALID_GUTI(emm_ctx) &&
//         IS_EMM_CTXT_PRESENT_GUTI(emm_ctx) &&
//         IS_EMM_CTXT_PRESENT_OLD_GUTI(emm_ctx)) {
//      /*
//       * Implicit GUTI reallocation;
//       * include the new assigned GUTI in the Attach Accept message
//       */
//      OAILOG_INFO (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - Implicit GUTI reallocation, include the new assigned GUTI in the Attach Accept message\n",
//          emm_ctx->ue_id);
//      emm_sap.u.emm_as.u.establish.new_guti    = &emm_ctx->_guti;
//    } else if (!IS_EMM_CTXT_VALID_GUTI(emm_ctx) &&
//        IS_EMM_CTXT_PRESENT_GUTI(emm_ctx)) {
//      /*
//       * include the new assigned GUTI in the Attach Accept message
//       */
//      OAILOG_INFO (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - Include the new assigned GUTI in the Attach Accept message\n", emm_ctx->ue_id);
//      emm_sap.u.emm_as.u.establish.new_guti    = &emm_ctx->_guti;
//    } else { // IS_EMM_CTXT_VALID_GUTI(emm_ctx) is true
//      emm_sap.u.emm_as.u.establish.new_guti  = NULL;
//    }
    //----------------------------------------
    REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__14);
//    emm_sap.u.emm_as.u.establish.eps_network_feature_support = &_emm_data.conf.eps_network_feature_support;

    /*
     * Delete any preexisting UE radio capabilities, pursuant to
     * GPP 24.310:5.5.1.2.4
     */
    ue_context_t *ue_context_p =
      mme_ue_context_exists_mme_ue_s1ap_id(&mme_app_desc.mme_ue_contexts,
                                           emm_ctx->ue_id);

    OAILOG_DEBUG (LOG_NAS_EMM,
                 "UE context already exists: %s\n",
                 ue_context_p ? "yes" : "no");
    if (ue_context_p) {
      // Note: this is safe from double-free errors because it sets to NULL
      // after freeing, which free treats as a no-op.
      free_wrapper((void**) &ue_context_p->ue_radio_capabilities);
      ue_context_p->ue_radio_cap_length = 0;  // Logically "deletes" info
    }
    /*
     * Setup EPS NAS security data
     */
    emm_as_set_security_data (&emm_sap.u.emm_as.u.establish.sctx, &emm_ctx->_security, false, true);
    emm_sap.u.emm_as.u.establish.encryption = emm_ctx->_security.selected_algorithms.encryption;
    emm_sap.u.emm_as.u.establish.integrity = emm_ctx->_security.selected_algorithms.integrity;
    OAILOG_DEBUG (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - encryption = 0x%X (0x%X)\n",
        emm_ctx->ue_id, emm_sap.u.emm_as.u.establish.encryption, emm_ctx->_security.selected_algorithms.encryption);
    OAILOG_DEBUG (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - integrity  = 0x%X (0x%X)\n",
        emm_ctx->ue_id, emm_sap.u.emm_as.u.establish.integrity, emm_ctx->_security.selected_algorithms.integrity);
    /*
     * Get the activate default EPS bearer context request message to
     * transfer within the ESM container of the attach accept message
     *
     * Any kind of piggybacked nas message!
     * todo: does data,
     */
//    emm_sap.u.emm_as.u.establish.nas_msg = data->esm_msg;
//    OAILOG_TRACE (LOG_NAS_EMM, "ue_id=" MME_UE_S1AP_ID_FMT " EMM-PROC  - nas_msg  src size = %d nas_msg  dst size = %d \n",
//        emm_ctx->ue_id, blength(data->esm_msg), blength(emm_sap.u.emm_as.u.establish.nas_msg));

    REQUIREMENT_3GPP_24_301(R10_5_5_1_2_4__2);
    rc = emm_sap_send (&emm_sap);

    if (RETURNerror != rc) {
      if (emm_ctx->T3450.id != NAS_TIMER_INACTIVE_ID) {
        /*
         * Re-start T3450 timer
         */
        emm_ctx->T3450.id = nas_timer_restart (emm_ctx->T3450.id);
        MSC_LOG_EVENT (MSC_NAS_EMM_MME, "T3450 restarted UE " MME_UE_S1AP_ID_FMT "", data->ue_id);
      } else {
        /*
         * Start T3450 timer
         */
//        emm_ctx->T3450.id = nas_timer_start (emm_ctx->T3450.sec, _emm_attach_t3450_handler, data);
//        MSC_LOG_EVENT (MSC_NAS_EMM_MME, "T3450 started UE " MME_UE_S1AP_ID_FMT " ", data->ue_id);
      }

      OAILOG_INFO (LOG_NAS_EMM, "UE " MME_UE_S1AP_ID_FMT "Timer T3450 (%d) expires in %ld seconds\n",
          emm_ctx->ue_id, emm_ctx->T3450.id, emm_ctx->T3450.sec);
    }
  } else {
    OAILOG_WARNING (LOG_NAS_EMM, "emm_ctx NULL\n");
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}
