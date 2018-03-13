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


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "assertions.h"
#include "hashtable.h"
#include "log.h"
#include "msc.h"
#include "conversions.h"
#include "intertask_interface.h"
#include "asn1_conversions.h"
#include "s1ap_common.h"
#include "s1ap_ies_defs.h"
#include "s1ap_mme_encoder.h"
#include "s1ap_mme_itti_messaging.h"
#include "s1ap_mme.h"
#include "dynamic_memory_check.h"
#include "mme_app_messages_types.h"
#include "mme_app_defs.h"

/* Every time a new UE is associated, increment this variable.
   But care if it wraps to increment also the mme_ue_s1ap_id_has_wrapped
   variable. Limit: UINT32_MAX (in stdint.h).
*/
//static mme_ue_s1ap_id_t                 mme_ue_s1ap_id = 0;
//static bool                             mme_ue_s1ap_id_has_wrapped = false;

extern const char                      *s1ap_direction2String[];
extern hash_table_ts_t g_s1ap_mme_id2assoc_id_coll; // contains sctp association id, key is mme_ue_s1ap_id;

static int s1ap_mme_process_new_initial_ue_message(
      const sctp_assoc_id_t assoc_id,
      const sctp_stream_id_t stream,
      bstring                 nas,
      const tai_t             const* tai,
      const ecgi_t            const* cgi,
      const long              rrc_cause,
      const as_stmsi_t const* opt_s_tmsi,
      csg_id_t                *csg_id,
      const gummei_t          const* gummei,

      ue_description_t                       *ue_ref,
      enb_description_t                      *eNB_ref,
      enb_ue_s1ap_id_t                        enb_ue_s1ap_id
){
  uint32_t                                enb_id;
//  as_stmsi_t                              s_tmsi = {.mme_code = 0, .m_tmsi = INVALID_M_TMSI};

  OAILOG_DEBUG (LOG_S1AP, "INITIAL UE Message: No S-TMSI received from eNodeB. Creating new S1AP UE description. \n");
  /*
    * This UE eNB Id has currently no known s1 association.
    * * * * Create new UE context by associating new mme_ue_s1ap_id.
    * * * * Update eNB UE list.
    * * * * Forward message to NAS.
    */
   if ((ue_ref = s1ap_new_ue (assoc_id, enb_ue_s1ap_id)) == NULL) {
     // If we failed to allocate a new UE return -1
     OAILOG_ERROR (LOG_S1AP, "S1AP:Initial UE Message- Failed to allocate S1AP UE Context, eNBUeS1APId:" ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
     OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
   }

   ue_ref->s1_ue_state = S1AP_UE_WAITING_CSR;

   ue_ref->enb_ue_s1ap_id = enb_ue_s1ap_id;
   // Will be allocated by NAS
   ue_ref->mme_ue_s1ap_id = INVALID_MME_UE_S1AP_ID;

   OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ NEW INITIAL UE MESSAGE %x \n", ue_ref);
   OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ NEW INITIAL UE MESSAGE %p \n", ue_ref);
   OAILOG_DEBUG(LOG_S1AP, "SET ENB_UE_S1AP_ID (0)   @ NEW INITIAL UE MESSAGE  %d \n", ue_ref->enb_ue_s1ap_id);

   ue_ref->s1ap_ue_context_rel_timer.id  = S1AP_TIMER_INACTIVE_ID;
   ue_ref->s1ap_ue_context_rel_timer.sec = S1AP_UE_CONTEXT_REL_COMP_TIMER;

   // On which stream we received the message
   ue_ref->sctp_stream_recv = stream;
   ue_ref->sctp_stream_send = ue_ref->enb->next_sctp_stream;

   /*
    * Increment the sctp stream for the eNB association.
    * If the next sctp stream is >= instream negociated between eNB and MME, wrap to first stream.
    * TODO: search for the first available stream instead.
    */

   /*
    * TODO task#15456359.
    * Below logic seems to be incorrect , revisit it.
    */
   ue_ref->enb->next_sctp_stream += 1;
   if (ue_ref->enb->next_sctp_stream >= ue_ref->enb->instreams) {
     ue_ref->enb->next_sctp_stream = 1;
   }
   s1ap_dump_enb (ue_ref->enb);

   enb_id = ue_ref->enb->enb_id;

  /*
   * We received the first NAS transport message: initial UE message.
   * * * * Send a NAS ESTAeNBBLISH IND to NAS layer
   */
  #if ORIGINAL_CODE
      s1ap_mme_itti_nas_establish_ind (ue_ref->mme_ue_s1ap_id, initialUEMessage_p->nas_pdu.buf, initialUEMessage_p->nas_pdu.size,
          initialUEMessage_p->rrC_Establishment_Cause, tai_tac);
  #else
  #if ITTI_LITE
      itf_mme_app_ll_initial_ue_message(assoc_id,
          ue_ref->enb_ue_s1ap_id,
          ue_ref->mme_ue_s1ap_id,
          initialUEMessage_p->nas_pdu.buf,
          initialUEMessage_p->nas_pdu.size,
          initialUEMessage_p->rrC_Establishment_Cause,
          &tai, &cgi, &s_tmsi, &gummei);
  #else
      s1ap_mme_itti_mme_app_initial_ue_message (assoc_id,
          enb_id,
          enb_ue_s1ap_id,
          INVALID_MME_UE_S1AP_ID,
          nas,
          tai,
          cgi,
          rrc_cause,
          opt_s_tmsi,
          csg_id,
          gummei,
          NULL, // CELL ACCESS MODE
          NULL, // GW Transport Layer Address
          NULL  //Relay Node Indicator
          );
  #endif
  #endif
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
int
s1ap_mme_handle_initial_ue_message (
  const sctp_assoc_id_t assoc_id,
  const sctp_stream_id_t stream,
  struct s1ap_message_s *message)
{
  S1ap_InitialUEMessageIEs_t             *initialUEMessage_p = NULL;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *eNB_ref = NULL;
  enb_ue_s1ap_id_t                        enb_ue_s1ap_id = 0;

  OAILOG_FUNC_IN (LOG_S1AP);
  initialUEMessage_p = &message->msg.s1ap_InitialUEMessageIEs;

  OAILOG_INFO (LOG_S1AP, "Received S1AP INITIAL_UE_MESSAGE eNB_UE_S1AP_ID " ENB_UE_S1AP_ID_FMT "\n", (enb_ue_s1ap_id_t)initialUEMessage_p->eNB_UE_S1AP_ID);

  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME, MSC_S1AP_ENB, NULL, 0, "0 initialUEMessage/%s assoc_id %u stream %u " ENB_UE_S1AP_ID_FMT " ",
          s1ap_direction2String[message->direction], assoc_id, stream, (enb_ue_s1ap_id_t)initialUEMessage_p->eNB_UE_S1AP_ID);

  if ((eNB_ref = s1ap_is_enb_assoc_id_in_list (assoc_id)) == NULL) {
    OAILOG_ERROR (LOG_S1AP, "Unknown eNB on assoc_id %d\n", assoc_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  // eNB UE S1AP ID is limited to 24 bits
  enb_ue_s1ap_id = (enb_ue_s1ap_id_t) (initialUEMessage_p->eNB_UE_S1AP_ID & 0x00ffffff);
  OAILOG_INFO (LOG_S1AP, "New Initial UE message received with eNB UE S1AP ID: " ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
  ue_ref = s1ap_is_ue_enb_id_in_list (eNB_ref, enb_ue_s1ap_id);
  tai_t                                   tai = {.plmn = {0}, .tac = INVALID_TAC_0000};
  ecgi_t                                  ecgi = {.plmn = {0}, .cell_identity = {0}};
  csg_id_t                                csg_id = 0;
  gummei_t                                gummei = {.plmn = {0}, .mme_code = 0, .mme_gid = 0}; // initialized after

  // Not changing the state!
  // TAI mandatory IE
  OCTET_STRING_TO_TAC (&initialUEMessage_p->tai.tAC, tai.tac);
  DevAssert (initialUEMessage_p->tai.pLMNidentity.size == 3);
  TBCD_TO_PLMN_T(&initialUEMessage_p->tai.pLMNidentity, &tai.plmn);

  // CGI mandatory IE
  DevAssert (initialUEMessage_p->eutran_cgi.pLMNidentity.size == 3);
  TBCD_TO_PLMN_T(&initialUEMessage_p->eutran_cgi.pLMNidentity, &ecgi.plmn);
  BIT_STRING_TO_CELL_IDENTITY (&initialUEMessage_p->eutran_cgi.cell_ID, ecgi.cell_identity);

  if (initialUEMessage_p->presenceMask & S1AP_INITIALUEMESSAGEIES_CSG_ID_PRESENT) {
    csg_id = BIT_STRING_to_uint32(&initialUEMessage_p->csG_Id);
  }

  memset(&gummei, 0, sizeof(gummei));
  if (initialUEMessage_p->presenceMask & S1AP_INITIALUEMESSAGEIES_GUMMEI_ID_PRESENT) {
    //TODO OCTET_STRING_TO_PLMN(&initialUEMessage_p->gummei_id.pLMN_Identity, gummei.plmn);
    OCTET_STRING_TO_MME_GID(&initialUEMessage_p->gummei_id.mME_Group_ID, gummei.mme_gid);
    OCTET_STRING_TO_MME_CODE(&initialUEMessage_p->gummei_id.mME_Code, gummei.mme_code);
  }
  if (ue_ref == NULL) {
    as_stmsi_t                              s_tmsi = {.mme_code = 0, .m_tmsi = INVALID_M_TMSI};

    AssertFatal((initialUEMessage_p->nas_pdu.size < 1000), "Bad length for NAS message %lu", initialUEMessage_p->nas_pdu.size);
    bstring nas = blk2bstr(initialUEMessage_p->nas_pdu.buf, initialUEMessage_p->nas_pdu.size);
    /**
     * Assuming that the original NAS message will be deallocated.
     * Always create an eNB reference here. In the MME_APP we will check the S-TMSI.
     */
    return s1ap_mme_process_new_initial_ue_message(assoc_id, stream,
        nas,
        &tai, &ecgi,
        initialUEMessage_p->rrC_Establishment_Cause,
        (initialUEMessage_p->presenceMask & S1AP_INITIALUEMESSAGEIES_S_TMSI_PRESENT) ? &s_tmsi:NULL,
        (initialUEMessage_p->presenceMask & S1AP_INITIALUEMESSAGEIES_CSG_ID_PRESENT) ? &csg_id:NULL,
        (initialUEMessage_p->presenceMask & S1AP_INITIALUEMESSAGEIES_GUMMEI_ID_PRESENT) ? &gummei:NULL,
        ue_ref, eNB_ref, enb_ue_s1ap_id);
} else {
  OAILOG_ERROR (LOG_S1AP, "S1AP:Initial UE Message- Duplicate ENB_UE_S1AP_ID. Ignoring the message, eNBUeS1APId:" ENB_UE_S1AP_ID_FMT "\n", enb_ue_s1ap_id);
}
}

//------------------------------------------------------------------------------
int
s1ap_mme_handle_uplink_nas_transport (
  const sctp_assoc_id_t assoc_id,
  __attribute__((unused)) const sctp_stream_id_t stream,
  struct s1ap_message_s *message)
{
  S1ap_UplinkNASTransportIEs_t           *uplinkNASTransport_p = NULL;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *enb_ref = NULL;
  tai_t                                   tai = {.plmn = {0}, .tac = INVALID_TAC_0000};
  ecgi_t                                  ecgi = {.plmn = {0}, .cell_identity = {0}};

  OAILOG_FUNC_IN (LOG_S1AP);
  uplinkNASTransport_p = &message->msg.s1ap_UplinkNASTransportIEs;

  if (INVALID_MME_UE_S1AP_ID == uplinkNASTransport_p->mme_ue_s1ap_id) {
    OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT message MME_UE_S1AP_ID unknown\n");

    enb_ref = s1ap_is_enb_assoc_id_in_list (assoc_id);

    if (!(ue_ref = s1ap_is_ue_enb_id_in_list ( enb_ref, (enb_ue_s1ap_id_t)uplinkNASTransport_p->eNB_UE_S1AP_ID))) {
      OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT No UE is attached to this enb_ue_s1ap_id: " ENB_UE_S1AP_ID_FMT "\n",
          (enb_ue_s1ap_id_t)uplinkNASTransport_p->eNB_UE_S1AP_ID);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
  } else {
    OAILOG_INFO (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT message MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT "\n",
        (mme_ue_s1ap_id_t)uplinkNASTransport_p->mme_ue_s1ap_id);

    if (!(ue_ref = s1ap_is_ue_mme_id_in_list (uplinkNASTransport_p->mme_ue_s1ap_id))) {
      OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT No UE is attached to this mme_ue_s1ap_id: " MME_UE_S1AP_ID_FMT "\n",
          (mme_ue_s1ap_id_t)uplinkNASTransport_p->mme_ue_s1ap_id);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
  }

  if (S1AP_UE_CONNECTED != ue_ref->s1_ue_state) {
    OAILOG_WARNING (LOG_S1AP, "Received S1AP UPLINK_NAS_TRANSPORT while UE in state != S1AP_UE_CONNECTED\n");
    MSC_LOG_RX_DISCARDED_MESSAGE (MSC_S1AP_MME,
                        MSC_S1AP_ENB,
                        NULL, 0,
                        "0 uplinkNASTransport/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas len %u",
                        s1ap_direction2String[message->direction],
                        (mme_ue_s1ap_id_t)uplinkNASTransport_p->mme_ue_s1ap_id,
                        (enb_ue_s1ap_id_t)uplinkNASTransport_p->eNB_UE_S1AP_ID,
                        uplinkNASTransport_p->nas_pdu.size);

    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  // TAI mandatory IE
  OCTET_STRING_TO_TAC (&uplinkNASTransport_p->tai.tAC, tai.tac);
  DevAssert (uplinkNASTransport_p->tai.pLMNidentity.size == 3);
  TBCD_TO_PLMN_T(&uplinkNASTransport_p->tai.pLMNidentity, &tai.plmn);

  // CGI mandatory IE
  DevAssert (uplinkNASTransport_p->eutran_cgi.pLMNidentity.size == 3);
  TBCD_TO_PLMN_T(&uplinkNASTransport_p->eutran_cgi.pLMNidentity, &ecgi.plmn);
  BIT_STRING_TO_CELL_IDENTITY (&uplinkNASTransport_p->eutran_cgi.cell_ID, ecgi.cell_identity);

  // TODO optional GW Transport Layer Address


  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 uplinkNASTransport/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas len %u",
                      s1ap_direction2String[message->direction],
                      (mme_ue_s1ap_id_t)uplinkNASTransport_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)uplinkNASTransport_p->eNB_UE_S1AP_ID,
                      uplinkNASTransport_p->nas_pdu.size);

  bstring b = blk2bstr(uplinkNASTransport_p->nas_pdu.buf, uplinkNASTransport_p->nas_pdu.size);
  s1ap_mme_itti_nas_uplink_ind (uplinkNASTransport_p->mme_ue_s1ap_id,
                                &b,
                                &tai,
                                &ecgi);
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}


//------------------------------------------------------------------------------
int
s1ap_mme_handle_nas_non_delivery (
    __attribute__((unused)) sctp_assoc_id_t assoc_id,
  sctp_stream_id_t stream,
  struct s1ap_message_s *message)
{
  S1ap_NASNonDeliveryIndication_IEs_t    *nasNonDeliveryIndication_p = NULL;
  ue_description_t                       *ue_ref = NULL;

  OAILOG_FUNC_IN (LOG_S1AP);
  /*
   * UE associated signalling on stream == 0 is not valid.
   */
  if (stream == 0) {
    OAILOG_NOTICE (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION message on invalid sctp stream 0\n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  nasNonDeliveryIndication_p = &message->msg.s1ap_NASNonDeliveryIndication_IEs;

  OAILOG_NOTICE (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION message MME_UE_S1AP_ID " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT "\n",
      (mme_ue_s1ap_id_t)nasNonDeliveryIndication_p->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)nasNonDeliveryIndication_p->eNB_UE_S1AP_ID);

  MSC_LOG_RX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 NASNonDeliveryIndication/%s mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " cause %u nas len %u",
                      s1ap_direction2String[message->direction],
                      (mme_ue_s1ap_id_t)nasNonDeliveryIndication_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)nasNonDeliveryIndication_p->eNB_UE_S1AP_ID,
                      nasNonDeliveryIndication_p->cause,
                      nasNonDeliveryIndication_p->nas_pdu.size);

  if ((ue_ref = s1ap_is_ue_mme_id_in_list (nasNonDeliveryIndication_p->mme_ue_s1ap_id))
      == NULL) {
    OAILOG_DEBUG (LOG_S1AP, "No UE is attached to this mme UE s1ap id: " MME_UE_S1AP_ID_FMT "\n", (mme_ue_s1ap_id_t)nasNonDeliveryIndication_p->mme_ue_s1ap_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  if (ue_ref->s1_ue_state != S1AP_UE_CONNECTED) {
    OAILOG_DEBUG (LOG_S1AP, "Received S1AP NAS_NON_DELIVERY_INDICATION while UE in state != S1AP_UE_CONNECTED\n");
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  //TODO: forward NAS PDU to NAS
  s1ap_mme_itti_nas_non_delivery_ind (nasNonDeliveryIndication_p->mme_ue_s1ap_id,
                                      nasNonDeliveryIndication_p->nas_pdu.buf,
                                      nasNonDeliveryIndication_p->nas_pdu.size,
                                      &nasNonDeliveryIndication_p->cause);
  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
int
s1ap_generate_downlink_nas_transport (
  const enb_ue_s1ap_id_t enb_ue_s1ap_id,
  const mme_ue_s1ap_id_t ue_id,
  STOLEN_REF bstring *payload)
{
  ue_description_t                       *ue_ref = NULL;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  void                                   *id = NULL;

  OAILOG_FUNC_IN (LOG_S1AP);

  // Try to retrieve SCTP assoication id using mme_ue_s1ap_id
  if (HASH_TABLE_OK ==  hashtable_ts_get (&g_s1ap_mme_id2assoc_id_coll, (const hash_key_t)ue_id, (void **)&id)) {
    sctp_assoc_id_t sctp_assoc_id = (sctp_assoc_id_t)(uintptr_t)id;
    enb_description_t  *enb_ref = s1ap_is_enb_assoc_id_in_list (sctp_assoc_id);
    if (enb_ref) {
      ue_ref = s1ap_is_ue_enb_id_in_list (enb_ref,enb_ue_s1ap_id);
    } else {
      OAILOG_ERROR (LOG_S1AP, "No eNB for SCTP association id %d \n", sctp_assoc_id);
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }
  }
  // TODO remove soon:
  if (!ue_ref) {
    ue_ref = s1ap_is_ue_mme_id_in_list (ue_id);
  }
  // finally!
  if (!ue_ref) {
    /*
     * If the UE-associated logical S1-connection is not established,
     * * * * the MME shall allocate a unique MME UE S1AP ID to be used for the UE.
     */
    OAILOG_WARNING (LOG_S1AP, "Unknown UE MME ID " MME_UE_S1AP_ID_FMT ", This case is not handled right now\n", ue_id);
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  } else {
    /*
     * We have fount the UE in the list.
     * * * * Create new IE list message and encode it.
     */
    S1ap_DownlinkNASTransportIEs_t         *downlinkNasTransport = NULL;
    s1ap_message                            message = {0};

    message.procedureCode = S1ap_ProcedureCode_id_downlinkNASTransport;
    message.direction = S1AP_PDU_PR_initiatingMessage;
    ue_ref->s1_ue_state = S1AP_UE_CONNECTED;
    downlinkNasTransport = &message.msg.s1ap_DownlinkNASTransportIEs;
    /*
     * Setting UE informations with the ones fount in ue_ref
     */
    downlinkNasTransport->mme_ue_s1ap_id = ue_ref->mme_ue_s1ap_id;
    downlinkNasTransport->eNB_UE_S1AP_ID = ue_ref->enb_ue_s1ap_id;
    /*eNB
     * Fill in the NAS pdu
     */
    OCTET_STRING_fromBuf (&downlinkNasTransport->nas_pdu, (char *)bdata(*payload), blength(*payload));
    bdestroy(*payload);
    *payload = NULL;

    if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
      // TODO: handle something
      OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
    }

    OAILOG_NOTICE (LOG_S1AP, "Send S1AP DOWNLINK_NAS_TRANSPORT message ue_id = " MME_UE_S1AP_ID_FMT " MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
                ue_id, (mme_ue_s1ap_id_t)downlinkNasTransport->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)downlinkNasTransport->eNB_UE_S1AP_ID);
    MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                        MSC_S1AP_ENB,
                        NULL, 0,
                        "0 downlinkNASTransport/initiatingMessage ue_id " MME_UE_S1AP_ID_FMT " mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id" ENB_UE_S1AP_ID_FMT " nas length %u",
                        ue_id, (mme_ue_s1ap_id_t)downlinkNasTransport->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)downlinkNasTransport->eNB_UE_S1AP_ID, length);
    bstring b = blk2bstr(buffer_p, length);
    free(buffer_p);
    s1ap_mme_itti_send_sctp_request (&b , ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  }

  OAILOG_FUNC_RETURN (LOG_S1AP, RETURNok);
}

//------------------------------------------------------------------------------
void
s1ap_handle_conn_est_cnf (
  const itti_mme_app_connection_establishment_cnf_t * const conn_est_cnf_pP)
{
  /*
   * We received create session response from S-GW on S11 interface abstraction.
   * At least one bearer has been established. We can now send s1ap initial context setup request
   * message to eNB.
   */
  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;

  ue_description_t                       *ue_ref1 = NULL;
  ue_description_t                       *ue_ref2 = NULL;

  S1ap_InitialContextSetupRequestIEs_t   *initialContextSetupRequest_p = NULL;
  S1ap_E_RABToBeSetupItemCtxtSUReq_t      e_RABToBeSetup = {0}; // yes, alloc on stack
  S1ap_NAS_PDU_t                          nas_pdu = {0}; // yes, alloc on stack
  s1ap_message                            message = {0}; // yes, alloc on stack

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (conn_est_cnf_pP != NULL);
  
  ue_ref = s1ap_is_ue_mme_id_in_list (conn_est_cnf_pP->nas_conn_est_cnf.ue_id);
  if (!ue_ref) {
    OAILOG_WARNING (LOG_S1AP, "This mme ue s1ap id (" MME_UE_S1AP_ID_FMT ") is not attached to any UE context. New connection establishment is %d.\n",
        conn_est_cnf_pP->nas_conn_est_cnf.ue_id, conn_est_cnf_pP->create_new_ue_reference);
    if(conn_est_cnf_pP->create_new_ue_reference){
      OAILOG_INFO( LOG_S1AP, "Creating a new ue reference for mme ue s1ap id (" MME_UE_S1AP_ID_FMT ").\n",conn_est_cnf_pP->nas_conn_est_cnf.ue_id);


    }else{
      OAILOG_ERROR (LOG_S1AP, "Not creating a new ue reference for mme ue s1ap id (" MME_UE_S1AP_ID_FMT ").\n",conn_est_cnf_pP->nas_conn_est_cnf.ue_id);
      // There are some race conditions were NAS T3450 timer is stopped and removed at same time
      OAILOG_FUNC_OUT (LOG_S1AP);
    }
  }

  ue_ref1 = s1ap_is_ue_enb_id_in_list(ue_ref->enb, 1);
  ue_ref2 = s1ap_is_ue_enb_id_in_list(ue_ref->enb, 2);

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
  message.procedureCode = S1ap_ProcedureCode_id_InitialContextSetup;
  message.direction = S1AP_PDU_PR_initiatingMessage;
  initialContextSetupRequest_p = &message.msg.s1ap_InitialContextSetupRequestIEs;
  initialContextSetupRequest_p->mme_ue_s1ap_id = (unsigned long)ue_ref->mme_ue_s1ap_id;
  initialContextSetupRequest_p->eNB_UE_S1AP_ID = (unsigned long)ue_ref->enb_ue_s1ap_id;

  OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ CONNECTION ESTABLISHMENT %x \n", ue_ref);
  OAILOG_DEBUG(LOG_S1AP, "UE_DESCRIPTION REFERENCE @ CONNECTION ESTABLISHMENT %p \n", ue_ref);
  OAILOG_DEBUG(LOG_S1AP, "SET ENB_UE_S1AP_ID (0)  @ CONNECTION ESTABLISHMENT %d \n", (unsigned long)ue_ref->enb_ue_s1ap_id);
  OAILOG_DEBUG(LOG_S1AP, "SET ENB_UE_S1AP_ID  @ CONNECTION ESTABLISHMENT %d \n", initialContextSetupRequest_p->eNB_UE_S1AP_ID);

  /*
   * Only add capability information if it's not empty.
   */
  if (conn_est_cnf_pP->ue_radio_cap_length) {
    OAILOG_DEBUG (LOG_S1AP, "UE radio capability found, adding to message\n");
    initialContextSetupRequest_p->presenceMask |=
      S1AP_INITIALCONTEXTSETUPREQUESTIES_UERADIOCAPABILITY_PRESENT;
    OCTET_STRING_fromBuf(&initialContextSetupRequest_p->ueRadioCapability,
                        (const char*) conn_est_cnf_pP->ue_radio_capabilities,
                         conn_est_cnf_pP->ue_radio_cap_length);
    free_wrapper((void**) &(conn_est_cnf_pP->ue_radio_capabilities));
  }

  /*
   * uEaggregateMaximumBitrateDL and uEaggregateMaximumBitrateUL expressed in term of bits/sec
   */
  asn_uint642INTEGER (&initialContextSetupRequest_p->uEaggregateMaximumBitrate.uEaggregateMaximumBitRateDL, conn_est_cnf_pP->ambr.br_dl);
  asn_uint642INTEGER (&initialContextSetupRequest_p->uEaggregateMaximumBitrate.uEaggregateMaximumBitRateUL, conn_est_cnf_pP->ambr.br_ul);
  e_RABToBeSetup.e_RAB_ID = conn_est_cnf_pP->eps_bearer_id;     //5;
  e_RABToBeSetup.e_RABlevelQoSParameters.qCI = conn_est_cnf_pP->bearer_qos_qci;

  if (conn_est_cnf_pP->nas_conn_est_cnf.nas_msg != NULL) {
    // NAS PDU is optional in rab_setup
    nas_pdu.size = conn_est_cnf_pP->nas_conn_est_cnf.nas_msg->slen;
    nas_pdu.buf  = conn_est_cnf_pP->nas_conn_est_cnf.nas_msg->data;
    e_RABToBeSetup.nAS_PDU = &nas_pdu;
  }
#  if ORIGINAL_S1AP_CODE
  e_RABToBeSetup.e_RABlevelQoSParameters.allocationRetentionPriority.priorityLevel = S1ap_PriorityLevel_lowest;
  e_RABToBeSetup.e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionCapability = S1ap_Pre_emptionCapability_shall_not_trigger_pre_emption;
  e_RABToBeSetup.e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionVulnerability = S1ap_Pre_emptionVulnerability_not_pre_emptable;
#  else
  e_RABToBeSetup.e_RABlevelQoSParameters.allocationRetentionPriority.priorityLevel = conn_est_cnf_pP->bearer_qos_prio_level;
  e_RABToBeSetup.e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionCapability = conn_est_cnf_pP->bearer_qos_pre_emp_capability;
  e_RABToBeSetup.e_RABlevelQoSParameters.allocationRetentionPriority.pre_emptionVulnerability = conn_est_cnf_pP->bearer_qos_pre_emp_vulnerability;
#  endif
  /*
   * Set the GTP-TEID. This is the S1-U S-GW TEID
   */
  INT32_TO_OCTET_STRING (conn_est_cnf_pP->bearer_s1u_sgw_fteid.teid, &e_RABToBeSetup.gTP_TEID);

  /*
   * S-GW IP address(es) for user-plane
   */
  if (conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv4) {
    e_RABToBeSetup.transportLayerAddress.buf = calloc (4, sizeof (uint8_t));
    /*
     * Only IPv4 supported
     */
    memcpy (e_RABToBeSetup.transportLayerAddress.buf, &conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv4_address, 4);
    offset += 4;
    e_RABToBeSetup.transportLayerAddress.size = 4;
    e_RABToBeSetup.transportLayerAddress.bits_unused = 0;
  }

  if (conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv6) {
    if (offset == 0) {
      /*
       * Both IPv4 and IPv6 provided
       */
      /*
       * TODO: check memory allocation
       */
      e_RABToBeSetup.transportLayerAddress.buf = calloc (16, sizeof (uint8_t));
    } else {
      /*
       * Only IPv6 supported
       */
      /*
       * TODO: check memory allocation
       */
      e_RABToBeSetup.transportLayerAddress.buf = realloc (e_RABToBeSetup.transportLayerAddress.buf, (16 + offset) * sizeof (uint8_t));
    }

    memcpy (&e_RABToBeSetup.transportLayerAddress.buf[offset], conn_est_cnf_pP->bearer_s1u_sgw_fteid.ipv6_address, 16);
    e_RABToBeSetup.transportLayerAddress.size = 16 + offset;
    e_RABToBeSetup.transportLayerAddress.bits_unused = 0;
  }

  ASN_SEQUENCE_ADD (&initialContextSetupRequest_p->e_RABToBeSetupListCtxtSUReq, &e_RABToBeSetup);
  initialContextSetupRequest_p->ueSecurityCapabilities.encryptionAlgorithms.buf = (uint8_t *) & conn_est_cnf_pP->security_capabilities_encryption_algorithms;
  initialContextSetupRequest_p->ueSecurityCapabilities.encryptionAlgorithms.size = 2;
  initialContextSetupRequest_p->ueSecurityCapabilities.encryptionAlgorithms.bits_unused = 0;
  initialContextSetupRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.buf = (uint8_t *) & conn_est_cnf_pP->security_capabilities_integrity_algorithms;
  initialContextSetupRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.size = 2;
  initialContextSetupRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.bits_unused = 0;
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", conn_est_cnf_pP->security_capabilities_encryption_algorithms);
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n", conn_est_cnf_pP->security_capabilities_integrity_algorithms);

  // todo: why not adding kenb to ueDescription?
  if (conn_est_cnf_pP->kenb) {
    initialContextSetupRequest_p->securityKey.buf = calloc (32, sizeof(uint8_t));
    memcpy (initialContextSetupRequest_p->securityKey.buf, conn_est_cnf_pP->kenb, 32);
    initialContextSetupRequest_p->securityKey.size = 32;
  } else {
    OAILOG_DEBUG (LOG_S1AP, "No kenb\n");
    initialContextSetupRequest_p->securityKey.buf = NULL;
    initialContextSetupRequest_p->securityKey.size = 0;
  }

  initialContextSetupRequest_p->securityKey.bits_unused = 0;

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    // TODO: handle something
    DevMessage ("Failed to encode initial context setup request message\n");
  }

  if (conn_est_cnf_pP->nas_conn_est_cnf.nas_msg != NULL) {
    bdestroy (conn_est_cnf_pP->nas_conn_est_cnf.nas_msg);
  }
  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_INITIAL_CONTEXT_SETUP_REQUEST message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)initialContextSetupRequest_p->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)initialContextSetupRequest_p->eNB_UE_S1AP_ID);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 InitialContextSetup/initiatingMessage mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT " nas length %u",
                      (mme_ue_s1ap_id_t)initialContextSetupRequest_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)initialContextSetupRequest_p->eNB_UE_S1AP_ID, nas_pdu.size);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  // todo: like in S1_SETUP_RESPONSE, we add a sequence, in one of them we manually deallocate, in another we don't
  OAILOG_FUNC_OUT (LOG_S1AP);
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
  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  S1ap_PathSwitchRequestAcknowledgeIEs_t *pathSwitchRequestAcknowledge_p = NULL;

  S1ap_E_RABToBeSwitchedULItem_t          e_RABToBeSwitchedUl = {0}; // yes, alloc on stack
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

  /*
   * Set the GTP-TEID. This is the S1-U S-GW TEID
   */
  e_RABToBeSwitchedUl.e_RAB_ID = 5; // todo: get ebi
  INT32_TO_OCTET_STRING (path_switch_req_ack_pP->bearer_s1u_sgw_fteid.teid, &e_RABToBeSwitchedUl.gTP_TEID);

  /*
   * S-GW IP address(es) for user-plane
   */
  if (path_switch_req_ack_pP->bearer_s1u_sgw_fteid.ipv4) {
    e_RABToBeSwitchedUl.transportLayerAddress.buf = calloc (4, sizeof (uint8_t));
    /*
     * Only IPv4 supported
     */
    memcpy (e_RABToBeSwitchedUl.transportLayerAddress.buf, &path_switch_req_ack_pP->bearer_s1u_sgw_fteid.ipv4_address, 4);
    offset += 4;
    e_RABToBeSwitchedUl.transportLayerAddress.size = 4;
    e_RABToBeSwitchedUl.transportLayerAddress.bits_unused = 0;
  }

  if (path_switch_req_ack_pP->bearer_s1u_sgw_fteid.ipv6) {
    if (offset == 0) {
      /*
       * Both IPv4 and IPv6 provided
       */
      /*
       * TODO: check memory allocation
       */
      e_RABToBeSwitchedUl.transportLayerAddress.buf = calloc (16, sizeof (uint8_t));
    } else {
      /*
       * Only IPv6 supported
       */
      /*
       * TODO: check memory allocation
       */
      e_RABToBeSwitchedUl.transportLayerAddress.buf = realloc (e_RABToBeSwitchedUl.transportLayerAddress.buf, (16 + offset) * sizeof (uint8_t));
    }

    memcpy (&e_RABToBeSwitchedUl.transportLayerAddress.buf[offset], path_switch_req_ack_pP->bearer_s1u_sgw_fteid.ipv6_address, 16);
    e_RABToBeSwitchedUl.transportLayerAddress.size = 16 + offset;
    e_RABToBeSwitchedUl.transportLayerAddress.bits_unused = 0;
  }
//  pathSwitchRequestAcknowledge_p->presenceMask |=
//       S1AP_PATHSWITCHREQUESTACKNOWLEDGEIES_E_RABTOBESWITCHEDULLIST_PRESENT;

//  ASN_SEQUENCE_ADD (&initialContextSetupRequest_p->e_RABToBeSetupListCtxtSUReq, &e_RABToBeSetup);
  ASN_SEQUENCE_ADD (&pathSwitchRequestAcknowledge_p->e_RABToBeSwitchedULList, &e_RABToBeSwitchedUl);

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

int s1ap_handle_handover_preparation_failure (
    const itti_s1ap_handover_preparation_failure_t *handover_prep_failure_pP)
{
  DevAssert(handover_prep_failure_pP);
  return s1ap_handover_preparation_failure (handover_prep_failure_pP->assoc_id, handover_prep_failure_pP->mme_ue_s1ap_id, handover_prep_failure_pP->enb_ue_s1ap_id, handover_prep_failure_pP->cause);
}

int s1ap_handover_preparation_failure (
    const sctp_assoc_id_t assoc_id,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id,
    const S1ap_Cause_PR cause_type)
{
  int                                     enc_rval = 0;
  S1ap_HandoverPreparationFailureIEs_t   *handoverPreparationFailure_p = NULL;
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

  handoverPreparationFailure_p = &message.msg.s1ap_HandoverPreparationFailureIEs;
  s1ap_mme_set_cause(&handoverPreparationFailure_p->cause, cause_type, 4);
  handoverPreparationFailure_p->eNB_UE_S1AP_ID = enb_ue_s1ap_id;
  handoverPreparationFailure_p->mme_ue_s1ap_id = mme_ue_s1ap_id;

  message.procedureCode = S1ap_ProcedureCode_id_HandoverPreparation;
  message.direction = S1AP_PDU_PR_unsuccessfulOutcome;
  enc_rval = s1ap_mme_encode_pdu (&message, &buffer, &length);

  // Failed to encode
  if (enc_rval < 0) {
    DevMessage ("Failed to encode handover preparation failure message\n");
  }

  bstring b = blk2bstr(buffer, length);
  free(buffer);
  rc = s1ap_mme_itti_send_sctp_request (&b, assoc_id, 0, INVALID_MME_UE_S1AP_ID);
  /**
   * No need to free it, since it is stacked and nothing is allocated.
   * S1AP UE Reference will stay as it is. If removed, it needs to be removed with a separate NAS_IMPLICIT_DETACH.
   */
  OAILOG_FUNC_RETURN (LOG_S1AP, rc);
}


int s1ap_handle_path_switch_request_failure (
    const itti_s1ap_path_switch_request_failure_t *path_switch_request_failure_pP)
{
  DevAssert(path_switch_request_failure_pP);
  return s1ap_path_switch_request_failure (path_switch_request_failure_pP->assoc_id, path_switch_request_failure_pP->mme_ue_s1ap_id, path_switch_request_failure_pP->enb_ue_s1ap_id, path_switch_request_failure_pP->cause);
}

int s1ap_path_switch_request_failure (
    const sctp_assoc_id_t assoc_id,
    const mme_ue_s1ap_id_t mme_ue_s1ap_id,
    const enb_ue_s1ap_id_t enb_ue_s1ap_id,
    const S1ap_Cause_PR cause_type)
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
  s1ap_mme_set_cause(&pathSwitchRequestFailure_p->cause, cause_type, 4);
  pathSwitchRequestFailure_p->eNB_UE_S1AP_ID = enb_ue_s1ap_id;
  pathSwitchRequestFailure_p->mme_ue_s1ap_id = mme_ue_s1ap_id;

  message.procedureCode = S1ap_ProcedureCode_id_PathSwitchRequest;
  message.direction = S1AP_PDU_PR_unsuccessfulOutcome;
  enc_rval = s1ap_mme_encode_pdu (&message, &buffer, &length);

  // Failed to encode
  if (enc_rval < 0) {
    DevMessage ("Failed to encode path switch request failure message\n");
  }

  bstring b = blk2bstr(buffer, length);
  free(buffer);
  rc = s1ap_mme_itti_send_sctp_request (&b, assoc_id, 0, INVALID_MME_UE_S1AP_ID);
  /**
   * No need to free it, since it is stacked and nothing is allocated.
   * S1AP UE Reference will stay as it is. If removed, it needs to be removed with a separate NAS_IMPLICIT_DETACH.
   */
  OAILOG_FUNC_RETURN (LOG_S1AP, rc);
}


void
s1ap_handle_handover_request (
  const itti_s1ap_handover_request_t * const handover_request_pP)
{
  /*
   * We received as a consequence of S1AP handover a bearer modification response (CSR or MBR) from S-GW on S11 interface abstraction.
   * We initiate an S1AP handover in the target cell.
   * 1- We will not create a UE_REFERENCE at this step, since we don't have the eNB-ID, yet to set in the UE map of the eNB.
   * We will create it with HANDOVER_REQUEST_ACKNOWLEDGE (success) and set it in the eNB map.
   *
   * 2- We won't set the MME_UE_S1AP_ID's SCTP_ASSOC, yet. We will do it in HANDOVER_NOTIFY, since after then only UE-CONTEXT-RELEASE-COMMAND will be sent to the source eNB.
   * The UE-Context-Release-Command where the MME_UE_S1AP_ID is already overwritten and the UE-Context-Realease-COMPLETE message will be handled where the mme_ue_s1ap_id to sctp_assoc
   * association is already removed.
   */
  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *target_enb_ref = NULL;
  S1ap_HandoverRequestIEs_t              *handoverRequest_p = NULL;

  S1ap_E_RABToBeSetupItemHOReq_t          e_RABToBeSetupHO = {0}; // yes, alloc on stack
  s1ap_message                            message = {0}; // yes, alloc on stack
  MessageDef                             *message_p = NULL;

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (handover_request_pP != NULL);

  /**
   * Search based on the MME_UE_S1AP_ID, since it's the only one we have currently.
   */
  ue_ref = s1ap_is_ue_mme_id_in_list (handover_request_pP->ue_id);
  if (ue_ref) {
    OAILOG_ERROR (LOG_S1AP, "Currently only inter-mme s1ap handover is implemented. UE_CONTEXT for mme ue s1ap id (" MME_UE_S1AP_ID_FMT ") is already existing \n",
        handover_request_pP->ue_id);
    /**
     * Send Handover Failure back (manually) to the MME.
     * This will trigger an implicit detach if the UE is not REGISTERED yet (single MME S1AP HO), or will just send a HO-PREP-FAILURE to the MME (if the cause is not S1AP-SYSTEM-FAILURE).
     */
    message_p = itti_alloc_new_message (TASK_S1AP, S1AP_HANDOVER_FAILURE);
    AssertFatal (message_p != NULL, "itti_alloc_new_message Failed");
    itti_s1ap_handover_failure_t *handover_failure_p = &message_p->ittiMsg.s1ap_handover_failure;
    memset ((void *)&message_p->ittiMsg.s1ap_handover_failure, 0, sizeof (itti_s1ap_handover_failure_t));
    /** Fill the S1AP Handover Failure elements per hand. */
    handover_failure_p->mme_ue_s1ap_id = handoverRequest_p->mme_ue_s1ap_id;
    handover_failure_p->enb_ue_s1ap_id = ue_ref->enb_ue_s1ap_id; /**< Set it from the invalid context. */
    handover_failure_p->assoc_id       = ue_ref->enb->sctp_assoc_id; /**< Set it from the invalid context. */
    /**
     * Set it to S1AP_SYSTEM_FAILURE for the invalid context. Not waiting for RELEASE-COMPLETE from target-eNB.
     * It may remove the sctp association to the correct MME_UE_S1AP_ID, too. For that, to continue with the handover fail case,
     * to reach the source-ENB, the MME_APP has to re-notify the MME_UE_S1AP_ID/SCTP association.
     */
    handover_failure_p->cause          = S1AP_SYSTEM_FAILURE;
    MSC_LOG_TX_MESSAGE (MSC_S1AP_MME, MSC_MMEAPP_MME, NULL, 0, "0 Sending manually S1AP_HANDOVER_FAILURE for mme_ue_s1ap_id  " MME_UE_S1AP_ID_FMT " ", handover_request_pP->ue_id);
    itti_send_msg_to_task (TASK_MME_APP, INSTANCE_DEFAULT, message_p);
    itti_s1ap_ue_context_release_command_t *ue_context_release_cmd_p = &((itti_s1ap_ue_context_release_command_t){ .mme_ue_s1ap_id = handover_request_pP->ue_id, .enb_ue_s1ap_id = ue_ref->enb_ue_s1ap_id, .cause = S1AP_SYSTEM_FAILURE});
    /** Remove the UE-Reference implicitly. Don't need to wait for the UE_CONTEXT_REMOVAL_COMMAND_COMPLETE. */
    s1ap_handle_ue_context_release_command(ue_context_release_cmd_p); /**< Send a removal message and remove the context also directly. */
    // There are some race conditions were NAS T3450 timer is stopped and removed at same time
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /** Create a new UE_Refence to the new eNodeB. */
    // todo: we also may create a stacked new one and remove it after the message is sent. Create the permanent one when HandoverRequestAcknowledge is received..
  /** Check that there exists an enb reference to the target-enb. */
  target_enb_ref = s1ap_is_enb_id_in_list(handover_request_pP->macro_enb_id);
  if(!target_enb_ref){
    OAILOG_ERROR (LOG_S1AP, "No target-enb could be found for enb-id %u. Handover Failed. \n",
            handover_request_pP->macro_enb_id);
    /**
     * Send Handover Failure back (manually) to the MME.
     * This will trigger an implicit detach if the UE is not REGISTERED yet (single MME S1AP HO), or will just send a HO-PREP-FAILURE to the MME (if the cause is not S1AP-SYSTEM-FAILURE).
     */
    message_p = itti_alloc_new_message (TASK_S1AP, S1AP_HANDOVER_FAILURE);
    AssertFatal (message_p != NULL, "itti_alloc_new_message Failed");
    itti_s1ap_handover_failure_t *handover_failure_p = &message_p->ittiMsg.s1ap_handover_failure;
    memset ((void *)&message_p->ittiMsg.s1ap_handover_failure, 0, sizeof (itti_s1ap_handover_failure_t));
    /** Fill the S1AP Handover Failure elements per hand. */
    handover_failure_p->mme_ue_s1ap_id = handoverRequest_p->mme_ue_s1ap_id;
//    handover_failure_p->enb_ue_s1ap_id = ue_ref->enb_ue_s1ap_id; /**< Set it from the invalid context. */
//    handover_failure_p->assoc_id       = ue_ref->enb->sctp_assoc_id; /**< Set it from the invalid context. */
    /**
     * Set it to S1AP_SYSTEM_FAILURE for the invalid context. Not waiting for RELEASE-COMPLETE from target-eNB.
     * It may remove the sctp association to the correct MME_UE_S1AP_ID, too. For that, to continue with the handover fail case,
     * to reach the source-ENB, the MME_APP has to re-notify the MME_UE_S1AP_ID/SCTP association.
     */
    handover_failure_p->cause          = S1AP_SYSTEM_FAILURE;
    MSC_LOG_TX_MESSAGE (MSC_S1AP_MME, MSC_MMEAPP_MME, NULL, 0, "0 Sending manually S1AP_HANDOVER_FAILURE for mme_ue_s1ap_id  " MME_UE_S1AP_ID_FMT " ", handover_request_pP->ue_id);
    itti_send_msg_to_task (TASK_MME_APP, INSTANCE_DEFAULT, message_p);
    itti_s1ap_ue_context_release_command_t *ue_context_release_cmd_p = &((itti_s1ap_ue_context_release_command_t){ .mme_ue_s1ap_id = handover_request_pP->ue_id, .enb_ue_s1ap_id = INVALID_ENB_UE_S1AP_ID_KEY, .cause = S1AP_SYSTEM_FAILURE});
    /** Remove the UE-Reference implicitly. Don't need to wait for the UE_CONTEXT_REMOVAL_COMMAND_COMPLETE. */
    s1ap_handle_ue_context_release_command(ue_context_release_cmd_p); /**< Send a removal message and remove the context also directly. */
    // There are some race conditions were NAS T3450 timer is stopped and removed at same time
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /**
   * UE Reference will only be created with a valid ENB_UE_S1AP_ID!
   * We don't wan't to save 2 the UE reference twice in the hashmap, but only with a valid ENB_ID key.
   * That's why create the UE Reference only with Handover Request Acknowledge.
   * No timer will be created for Handover Request (not defined in the specification and no UE-Reference to the target-ENB exists yet.
   *
   * Target eNB could be found. Create a new ue_reference.
   * This UE eNB Id has currently no known s1 association.
   * * * * Create new UE context by associating new mme_ue_s1ap_id.
   * * * * Update eNB UE list.
   *
   * todo: what to provide as enb_id?
   */

  /*
   * Start the outcome response timer.
   *
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
  message.procedureCode = S1ap_ProcedureCode_id_HandoverResourceAllocation;
  message.direction = S1AP_PDU_PR_initiatingMessage;
  handoverRequest_p = &message.msg.s1ap_HandoverRequestIEs;
  handoverRequest_p->mme_ue_s1ap_id = (unsigned long)handover_request_pP->ue_id;

  /* Set the GTP-TEID. This is the S1-U S-GW TEID. */
  // todo: support this with multibearer!
  bearer_context_t * bearer_ctxt_p = handover_request_pP->bearer_ctx_to_be_setup_list.bearer_ctx[0];
  e_RABToBeSetupHO.e_RAB_ID = bearer_ctxt_p->ebi;

  /** Set QoS parameters of the bearer. */
  e_RABToBeSetupHO.e_RABlevelQosParameters.qCI                                                  = bearer_ctxt_p->qci;
  e_RABToBeSetupHO.e_RABlevelQosParameters.allocationRetentionPriority.priorityLevel            = bearer_ctxt_p->prio_level;
  e_RABToBeSetupHO.e_RABlevelQosParameters.allocationRetentionPriority.pre_emptionCapability    = bearer_ctxt_p->pre_emp_capability;
  e_RABToBeSetupHO.e_RABlevelQosParameters.allocationRetentionPriority.pre_emptionVulnerability = bearer_ctxt_p->pre_emp_vulnerability;

  INT32_TO_OCTET_STRING (bearer_ctxt_p->s_gw_teid, &e_RABToBeSetupHO.gTP_TEID);

  /*
   * S-GW IP address(es) for user-plane
   */
  if(bearer_ctxt_p->s_gw_address.address.ipv4_address) {
    e_RABToBeSetupHO.transportLayerAddress.buf = calloc(4, sizeof(uint8_t));
    /*
     * ONLY IPV4 SUPPORTED
     */
    memcpy(e_RABToBeSetupHO.transportLayerAddress.buf, &bearer_ctxt_p->s_gw_address.address.ipv4_address, 4);
    offset += 4; /**< Later for IPV4V6 addresses. */
    e_RABToBeSetupHO.transportLayerAddress.size = 4;
    e_RABToBeSetupHO.transportLayerAddress.bits_unused = 0;
  }
  // TODO: S1AP PDU..
  /** Set the bearer as an ASN list element. */
  S1ap_IE_t                               s1ap_ie_ext;
  ssize_t                                 encoded;
  S1AP_PDU_t                              pdu;

  memset (&s1ap_ie_ext, 0, sizeof (S1ap_IE_t));
  s1ap_ie_ext.id = S1ap_ProtocolIE_ID_id_Data_Forwarding_Not_Possible;
  s1ap_ie_ext.criticality = S1ap_Criticality_ignore;
  s1ap_ie_ext.value.buf = NULL;
  s1ap_ie_ext.value.size = 0;
  ASN_SEQUENCE_ADD (e_RABToBeSetupHO.iE_Extensions, &pdu);
  /** Adding stacked value. */

  if (bearer_ctxt_p->s_gw_address.pdn_type == IPv6 ||bearer_ctxt_p->s_gw_address.pdn_type == IPv4_AND_v6) {
    if (bearer_ctxt_p->s_gw_address.pdn_type == IPv6) {
      /*
       * Only IPv6 supported
       */
      /*
       * TODO: check memory allocation
       */
      e_RABToBeSetupHO.transportLayerAddress.buf = calloc (16, sizeof (uint8_t));
    } else {
      /*
       * Both IPv4 and IPv6 provided
       */
      /*
       * TODO: check memory allocation
       */
      e_RABToBeSetupHO.transportLayerAddress.buf = realloc (e_RABToBeSetupHO.transportLayerAddress.buf, (16 + offset) * sizeof (uint8_t));
    }

    memcpy (&e_RABToBeSetupHO.transportLayerAddress.buf[offset], bearer_ctxt_p->s_gw_address.address.ipv6_address, 16);
    e_RABToBeSetupHO.transportLayerAddress.size = 16 + offset;
    e_RABToBeSetupHO.transportLayerAddress.bits_unused = 0;
  }

  /** Add the E-RAB bearer to the message. */
  ASN_SEQUENCE_ADD (&handoverRequest_p->e_RABToBeSetupListHOReq, &e_RABToBeSetupHO);

  /** Set the security context. */
  handoverRequest_p->securityContext.nextHopChainingCount = handover_request_pP->ncc;
  handoverRequest_p->securityContext.nextHopParameter.buf  = calloc (32, sizeof(uint8_t));
  memcpy (handoverRequest_p->securityContext.nextHopParameter.buf, handover_request_pP->nh, 32);
  handoverRequest_p->securityContext.nextHopParameter.size = 32;
  handoverRequest_p->securityContext.nextHopParameter.bits_unused = 0;

  /** Add the security capabilities. */
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", handover_request_pP->security_capabilities_encryption_algorithms);
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n" , handover_request_pP->security_capabilities_integrity_algorithms);

  handoverRequest_p->ueSecurityCapabilities.encryptionAlgorithms.buf                  = (uint8_t *) & handover_request_pP->security_capabilities_encryption_algorithms;
  handoverRequest_p->ueSecurityCapabilities.encryptionAlgorithms.size                 = 2;
  handoverRequest_p->ueSecurityCapabilities.encryptionAlgorithms.bits_unused          = 0;
  handoverRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.buf         = (uint8_t *) & handover_request_pP->security_capabilities_integrity_algorithms;
  handoverRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.size        = 2;
  handoverRequest_p->ueSecurityCapabilities.integrityProtectionAlgorithms.bits_unused = 0;
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_encryption_algorithms 0x%04X\n", handover_request_pP->security_capabilities_encryption_algorithms);
  OAILOG_DEBUG (LOG_S1AP, "security_capabilities_integrity_algorithms 0x%04X\n", handover_request_pP->security_capabilities_integrity_algorithms);

  /** Set Handover Type. */
  handoverRequest_p->handoverType = S1ap_HandoverType_intralte;

  /** Set Id-Cause. */
  handoverRequest_p->cause.present = S1ap_Cause_PR_radioNetwork;
  handoverRequest_p->cause.choice.radioNetwork = S1ap_CauseRadioNetwork_handover_desirable_for_radio_reason;

  /*
   * uEaggregateMaximumBitrateDL and uEaggregateMaximumBitrateUL expressed in term of bits/sec
   */
  asn_uint642INTEGER (&handoverRequest_p->uEaggregateMaximumBitrate.uEaggregateMaximumBitRateDL, handover_request_pP->ambr.br_dl);
  asn_uint642INTEGER (&handoverRequest_p->uEaggregateMaximumBitrate.uEaggregateMaximumBitRateUL, handover_request_pP->ambr.br_ul);

  /*
   * E-UTRAN Target-ToSource Transparent Container.
   */
  OCTET_STRING_fromBuf(&handoverRequest_p->source_ToTarget_TransparentContainer,
      handover_request_pP->source_to_target_eutran_container->data, blength(handover_request_pP->source_to_target_eutran_container));
  /** Destroy the bstring manually. */
  bdestroy(handover_request_pP->source_to_target_eutran_container);
    handoverRequest_p->source_ToTarget_TransparentContainer.size = blength(handover_request_pP->source_to_target_eutran_container);

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_S1AP, "Failed to encode handover command \n");
    /** We rely on the handover_notify timeout to remove the UE context. */
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  // todo: s1ap_generate_initiating_message will remove the things?

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_HANDOVER_REQUEST message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)handoverRequest_p->mme_ue_s1ap_id);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      0,
                      NULL, 0,
                      "0 HandoverRequest/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)handoverRequest_p->mme_ue_s1ap_id);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  // todo: the next_sctp_stream is the one without incrementation?
  s1ap_mme_itti_send_sctp_request (&b, target_enb_ref->sctp_assoc_id, target_enb_ref->next_sctp_stream, handover_request_pP->ue_id);

  /**
   * Leave the state in as it is.
   * Not creating a UE-Reference towards the target-ENB.
   */
  OAILOG_FUNC_OUT (LOG_S1AP);
}

/**
 * Informing the source eNodeB about the successfully established handover.
 * Send the handover command to the source enb via the old s1ap ue_reference.
 * Keeping the old s1ap ue_reference for enb/MME status transfer.
 */
void
s1ap_handle_handover_command (
  const itti_s1ap_handover_command_t * const handover_command_pP)
{

  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *target_enb_ref = NULL;
  S1ap_HandoverCommandIEs_t              *handoverCommand_p = NULL;

  s1ap_message                            message = {0}; // yes, alloc on stack

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (handover_command_pP != NULL);

  /**
   * This should still refer to the old UE_REFERENCE structure.
   * The new UE_REFERENCE structure, though exists in the enb map, not registered as a SCTP associated.
   */
  ue_ref = s1ap_is_ue_mme_id_in_list (handover_command_pP->mme_ue_s1ap_id);
  if (!ue_ref) {
    /**
     * The source UE-Reference should exist.
     * It is an error, if its not existing.
     * We rely on the timer that if no HANDOVER_NOTIFY is received in time, we will remove the UE context implicitly and the target-enb UE_REFERENCE.
     */
    OAILOG_ERROR (LOG_S1AP, " NO UE_CONTEXT could be found to send handover command for UE mme ue s1ap id (" MME_UE_S1AP_ID_FMT ") to the source eNB with eNBId %d. \n",
        handover_command_pP->mme_ue_s1ap_id, handover_command_pP->enb_id);
    OAILOG_FUNC_OUT (LOG_S1AP);
  }
  /**
   * No timer needs to be started here.
   * The only timer is in the source-eNB..
   */
  // todo: PSR if the state is handover, else just complete the message!
  message.procedureCode = S1ap_ProcedureCode_id_HandoverPreparation;
  message.direction = S1AP_PDU_PR_successfulOutcome;
  handoverCommand_p = &message.msg.s1ap_HandoverCommandIEs;
  /** Set the enb_ue_s1ap id and the mme_ue_s1ap_id. */
  handoverCommand_p->mme_ue_s1ap_id = (unsigned long)ue_ref->mme_ue_s1ap_id;
  handoverCommand_p->eNB_UE_S1AP_ID = (unsigned long)ue_ref->enb_ue_s1ap_id;
  /** Set the handover type. */
  handoverCommand_p->handoverType = S1ap_HandoverType_intralte;
  /*
   * E-UTRAN Target-ToSource Transparent Container.
   * todo: Lionel: ask if correct:
   * The octet string will be freed inside: .
   *  s1ap_generate_successfull_outcome (
       * We can safely free list of IE from sptr
      ASN_STRUCT_FREE_CONTENTS_ONLY (*td, sptr);
   */
  OCTET_STRING_fromBuf(&handoverCommand_p->target_ToSource_TransparentContainer,
      handover_command_pP->eutran_target_to_source_container->data, blength(handover_command_pP->eutran_target_to_source_container));

  /** Destroy the bstring. */
  bdestroy(handover_command_pP->eutran_target_to_source_container);

  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    DevMessage("Failed to encode handover command \n");
  }
 OAILOG_NOTICE (LOG_S1AP, "Send S1AP_HANDOVER_COMMAND message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)handoverCommand_p->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)handoverCommand_p->eNB_UE_S1AP_ID);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 HandoverCommand/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)handoverCommand_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)handoverCommand_p->eNB_UE_S1AP_ID);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  /** Not changing the ECM state of the source eNB UE-Reference. */
  OAILOG_FUNC_OUT (LOG_S1AP);
}

//------------------------------------------------------------------------------
void
s1ap_handle_mme_status_transfer( const itti_s1ap_status_transfer_t * const s1ap_status_transfer_pP){

  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *target_enb_ref = NULL;
  S1ap_MMEStatusTransferIEs_t            *mmeStatusTransfer_p = NULL;

  s1ap_message                            message = {0}; // yes, alloc on stack

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (s1ap_status_transfer_pP != NULL);

  /**
   * Find the UE-Reference based on the enb_ue_s1ap_id.
   * We did not register the mme_ue_s1ap_id, yet.
   */
  ue_ref = s1ap_is_enb_ue_s1ap_id_in_list_per_enb(s1ap_status_transfer_pP->enb_id, s1ap_status_transfer_pP->enb_ue_s1ap_id);
  if (!ue_ref) {
    /** Set the source_assoc_id!! */
    OAILOG_ERROR (LOG_S1AP, " NO UE_CONTEXT could be found to send MME Status Transfer UE with enb ue s1ap id (" ENB_UE_S1AP_ID_FMT "). "
        "UE contexts are assumed to be cleaned up via timer. \n",
        s1ap_status_transfer_pP->enb_ue_s1ap_id);
    OAILOG_FUNC_OUT (LOG_S1AP);
  }
  /** Create the MME S1AP Statut Transfer message. */
  message.procedureCode = S1ap_ProcedureCode_id_MMEStatusTransfer;
  message.direction = S1AP_PDU_PR_initiatingMessage;
  mmeStatusTransfer_p = &message.msg.s1ap_MMEStatusTransferIEs;

  /** Set the enb_ue_s1ap id and the mme_ue_s1ap_id. */
  mmeStatusTransfer_p->mme_ue_s1ap_id = (unsigned long)ue_ref->mme_ue_s1ap_id;
  mmeStatusTransfer_p->eNB_UE_S1AP_ID = (unsigned long)ue_ref->enb_ue_s1ap_id;

  /*
   * E-UTRAN Status-Transfer Source Transparent Container.
   */
  // Add a new element.
  S1ap_IE_t                               status_container;
  ssize_t                                 encoded;

  memset (&status_container, 0, sizeof (S1ap_IE_t));
  status_container.id = S1ap_ProtocolIE_ID_id_Bearers_SubjectToStatusTransfer_Item;
  status_container.criticality = S1ap_Criticality_ignore;

  /*
   * E-UTRAN Target-ToSource Transparent Container.
   */

  /**
   * todo: lionel:
   * Here, do we need to allocate an OCTET String container because of the purge of the message in the encode?
   * Or can we use this?
   * What is exactly purged in the encoder? The list (without the contents)? the contents of the list? contents & list?
   */
  status_container.value.buf  = s1ap_status_transfer_pP->bearerStatusTransferList_buffer->data + 6;
  status_container.value.size = blength(s1ap_status_transfer_pP->bearerStatusTransferList_buffer) - 6; // s1ap_status_transfer_pP->bearerStatusTransferList_buffer->slen;

  /** Adding stacked value. */
  ASN_SEQUENCE_ADD (&mmeStatusTransfer_p->eNB_StatusTransfer_TransparentContainer.bearers_SubjectToStatusTransferList, &status_container);

  /** Encoding without allocating? */
  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_S1AP, "Failed to encode MME status transfer. \n");
    /** We rely on the handover_notify timeout to remove the UE context. */
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }
  // todo: do we need this destroy?
  bdestroy(s1ap_status_transfer_pP->bearerStatusTransferList_buffer);
  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_MME_STATUS_TRANSFER message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " eNB_UE_S1AP_ID = " ENB_UE_S1AP_ID_FMT "\n",
              (mme_ue_s1ap_id_t)mmeStatusTransfer_p->mme_ue_s1ap_id, (enb_ue_s1ap_id_t)mmeStatusTransfer_p->eNB_UE_S1AP_ID);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 MmeStatusTransfer/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT " enb_ue_s1ap_id " ENB_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)mmeStatusTransfer_p->mme_ue_s1ap_id,
                      (enb_ue_s1ap_id_t)mmeStatusTransfer_p->eNB_UE_S1AP_ID);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
}

//------------------------------------------------------------------------------
void
s1ap_handle_paging( const itti_s1ap_paging_t * const s1ap_paging_pP){

  uint                                    offset = 0;
  uint8_t                                *buffer_p = NULL;
  uint32_t                                length = 0;
  ue_description_t                       *ue_ref = NULL;
  enb_description_t                      *target_enb_ref = NULL;
  S1ap_PagingIEs_t                       *paging_p = NULL;

  s1ap_message                            message = {0}; // yes, alloc on stack

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (s1ap_paging_pP != NULL);

  ue_ref = s1ap_is_ue_mme_id_in_list (s1ap_paging_pP->mme_ue_s1ap_id);
  if (!ue_ref) {
    /** Set the source_assoc_id!! */
    /** todo: for intra-mme handover, this will deliver the old s1ap id. */
    OAILOG_ERROR (LOG_S1AP, " NO UE_CONTEXT could be found to send MME Status Transfer for UE mme ue s1ap id (" MME_UE_S1AP_ID_FMT "). \n",
        s1ap_paging_pP->mme_ue_s1ap_id);
    // todo: save the enb_association to the old enodeb temporarily in the newly created context?
    // There are some race conditions were NAS T3450 timer is stopped and removed at same time
    // todo: send the reject message back.. clear all the contexts..
    OAILOG_FUNC_OUT (LOG_S1AP);
  }

  /** No need to find the source_enb.. Assuming that the source_enb association is still present. */
  /** Check the UE state is in S1AP_UE_HANDOVER_S1AP. */
  // todo: creating a new UE_REFERENCE.. or getting one?

//  if(ue_ref->s1_ue_state != S1AP_UE_){
//    OAILOG_ERROR (LOG_S1AP, " UE context is not in S1AP_UE_CONNECTED state but in %d for UE mme ue s1ap id (" MME_UE_S1AP_ID_FMT "). \n",
//            ue_ref->s1_ue_state, s1ap_status_transfer_pP->mme_ue_s1ap_id);
//    // todo: save the enb_association to the old enodeb temporarily in the newly created context?
//    // There are some race conditions were NAS T3450 timer is stopped and removed at same time
//    // todo: send the reject message back.. clear all the contexts..
//    OAILOG_FUNC_OUT (LOG_S1AP);
//  }

  message.procedureCode = S1ap_ProcedureCode_id_Paging;
  message.direction = S1AP_PDU_PR_initiatingMessage;
  paging_p = &message.msg.s1ap_PagingIEs;

  /** Encode and set the UE Identity Index Value. */
//  paging_p->ueIdentityIndexValue.= (unsigned long)ue_ref->mme_ue_s1ap_id; // todo: encode!
  INT32_TO_BIT_STRING(s1ap_paging_pP->ue_identity_index, &paging_p->ueIdentityIndexValue);
//  paging_p->ueIdentityIndexValue.buf = (uint8_t *) & s1ap_paging_pP->ue_identity_index.;
//  paging_p->ueIdentityIndexValue.size = 5;
//  paging_p->ueIdentityIndexValue.bits_unused = 0;

  /** Encode the CN Domain. */
  paging_p->cnDomain = S1ap_CNDomain_ps;

  /** Set the UE Paging Identity . */
  paging_p->uePagingID.present = S1ap_UEPagingID_PR_s_TMSI;
  INT16_TO_OCTET_STRING(s1ap_paging_pP->tmsi, &paging_p->uePagingID.choice.s_TMSI.m_TMSI);
  // todo: chose the right gummei or get it from the request!
  INT8_TO_OCTET_STRING(mme_config.gummei.gummei[0].mme_code, &paging_p->uePagingID.choice.s_TMSI.mMEC);

  /** Set the TAI-List. */
  S1ap_TAIItemIEs_t tai_item = {0}; // yes, alloc on stack
  INT16_TO_OCTET_STRING(s1ap_paging_pP->tai.tac, &tai_item.taiItem.tAI.tAC);
  /** Set the PLMN. */
  uint8_t                                 plmn[3] = { 0x00, 0x00, 0x00 };     //{ 0x02, 0xF8, 0x29 };
  PLMN_T_TO_TBCD (s1ap_paging_pP->tai.plmn,
                    plmn,
                    find_mnc_length (
                        s1ap_paging_pP->tai.plmn.mcc_digit1, s1ap_paging_pP->tai.plmn.mcc_digit2, s1ap_paging_pP->tai.plmn.mcc_digit3,
                        s1ap_paging_pP->tai.plmn.mnc_digit1, s1ap_paging_pP->tai.plmn.mnc_digit2, s1ap_paging_pP->tai.plmn.mnc_digit3)
  );
  OCTET_STRING_fromBuf(&tai_item.taiItem.tAI.pLMNidentity, plmn, 3);;
  /** Set the TAI. */
  ASN_SEQUENCE_ADD (&paging_p->taiList, &tai_item);

  /** Encoding without allocating? */
  if (s1ap_mme_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_S1AP, "Failed to encode S1AP paging \n");
    // todo: in this case we will ignore this. no UE contex modification should occure
    OAILOG_FUNC_RETURN (LOG_S1AP, RETURNerror);
  }

  OAILOG_NOTICE (LOG_S1AP, "Send S1AP_PAGING message MME_UE_S1AP_ID = " MME_UE_S1AP_ID_FMT " \n",
              (mme_ue_s1ap_id_t)s1ap_paging_pP->mme_ue_s1ap_id);
  MSC_LOG_TX_MESSAGE (MSC_S1AP_MME,
                      MSC_S1AP_ENB,
                      NULL, 0,
                      "0 S1AP Paging/successfullOutcome mme_ue_s1ap_id " MME_UE_S1AP_ID_FMT,
                      (mme_ue_s1ap_id_t)s1ap_paging_pP->mme_ue_s1ap_id);
  bstring b = blk2bstr(buffer_p, length);
  free(buffer_p);
  s1ap_mme_itti_send_sctp_request (&b, ue_ref->enb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->mme_ue_s1ap_id);
  /** todo: leaving the UE in S1AP_UE_HANDOVER_STATE? */
  //  ue_ref->s1_ue_state = S1AP_UE_CONNECTED;
  OAILOG_FUNC_OUT (LOG_S1AP);
}

//------------------------------------------------------------------------------
void
s1ap_handle_mme_ue_id_notification (
  const itti_mme_app_s1ap_mme_ue_id_notification_t * const notification_p)
{

  OAILOG_FUNC_IN (LOG_S1AP);
  DevAssert (notification_p != NULL);
  s1ap_notified_new_ue_mme_s1ap_id_association (
                          notification_p->sctp_assoc_id, notification_p->enb_ue_s1ap_id, notification_p->mme_ue_s1ap_id);
  OAILOG_FUNC_OUT (LOG_S1AP);
}
