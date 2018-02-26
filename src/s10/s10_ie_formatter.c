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
#include <inttypes.h>

#include "dynamic_memory_check.h"
#include "common_defs.h"
#include "log.h"
#include "assertions.h"
#include "conversions.h"
#include "intertask_interface.h"
#include "NwGtpv2c.h"
#include "NwGtpv2cIe.h"
#include "NwGtpv2cMsg.h"
#include "NwGtpv2cMsgParser.h"
#include "s10_common.h"
#include "s10_ie_formatter.h"

#define MM_UE_CONTEXT_MAX_LENGTH 100
#define MIN_MM_UE_EPS_CONTEXT_SIZE                  80 // todo: what is the minimum length?

NwRcT
s10_imsi_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  Imsi_t                                 *imsi;
  uint8_t                                 i;
  uint8_t                                 mask = 0x0F;
  uint8_t                                 imsi_length = 2 * ieLength;

  DevAssert (arg );
  imsi = (Imsi_t *) arg;

  for (i = 0; i < ieLength * 2; i++) {
    if (mask == 0x0F) {
      imsi->digit[i] = (ieValue[i / 2] & (mask));
    } else {
      imsi->digit[i] = (ieValue[i / 2] & (mask)) >> 4;
    }

    imsi->digit[i] += '0';
    mask = ~mask;
  }

  if (imsi->digit[imsi_length - 1] == (0x0f + '0')) {
    imsi->digit[imsi_length - 1] = 0;
    imsi_length--;
  }

  imsi->length = imsi_length;
  OAILOG_DEBUG (LOG_S10, "\t- IMSI length %d\n", imsi->length);
  OAILOG_DEBUG (LOG_S10, "\t-      value  %*s\n", imsi->length, imsi->digit);
  return NW_OK;
}

int
s10_imsi_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const Imsi_t * imsi)
{
  uint8_t                                *temp = NULL;
  uint8_t                                 imsi_length,
                                          i;
  NwRcT                                   rc;

  DevAssert (msg );
  DevAssert (imsi );
  /*
   * In case of odd/even imsi
   */
  imsi_length = imsi->length % 2 == 0 ? imsi->length / 2 : imsi->length / 2 + 1;
  temp = calloc (imsi_length, sizeof (uint8_t));
  if (imsi->length % 2) {
    temp[(imsi->length) / 2] |= 0xF0;
  }
  DevAssert (temp );

  for (i = 0; i < imsi->length; i++) {
    temp[i / 2] |= ((imsi->digit[i] - '0') & 0x0F) << (i % 2 ? 4 : 0);
  }

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_IMSI, imsi_length, 0, temp);
  DevAssert (NW_OK == rc);
  free_wrapper ((void**) &temp);
  return RETURNok;
}

int
s10_guti_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const guti_t * guti)
{
  uint8_t                                 guti_length,
                                          i;
  NwRcT                                   rc;

  DevAssert (msg );
  DevAssert (guti );

  /** Set the first part which is equal to setting the serving network. */
  uint8_t                                 guti_b[3 + 2 + 1 + 4];
  memset((void*)guti_b, 0, sizeof(guti_b));

  uint8_t * pGutiBuf = guti_b;

  /** Convert the MNC/MCC. */
  PLMN_T_TO_TBCD (guti->gummei.plmn,
      pGutiBuf,
      mme_config_find_mnc_length (guti->gummei.plmn.mcc_digit1, guti->gummei.plmn.mcc_digit2, guti->gummei.plmn.mcc_digit3,
          guti->gummei.plmn.mnc_digit1, guti->gummei.plmn.mnc_digit2, guti->gummei.plmn.mnc_digit3)
  );
  pGutiBuf+=3;

//  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_SERVING_NETWORK, 3, 0, value);
//  DevAssert (NW_OK == rc);

  /** Set the MME group Id. */
  *((uint16_t *) (pGutiBuf)) = htons(guti->gummei.mme_gid);
  pGutiBuf+=2;

  /** Set the MME code. */
  *pGutiBuf = guti->gummei.mme_code;
  pGutiBuf++;

  /** Set the M-TMSI. */
  *((uint32_t *) (pGutiBuf)) = htonl(guti->m_tmsi);
  pGutiBuf+=4;

  /** Reset the pointer. */
  pGutiBuf = guti_b;

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_GUTI, sizeof(guti_b), 0, pGutiBuf);
  DevAssert (NW_OK == rc);

  return RETURNok;
}

NwRcT
s10_guti_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  guti_t                *guti = (guti_t*) arg;

  DevAssert (guti );

  /** Convert to TBCD and add to GUTI. */
  guti->gummei.plmn.mcc_digit2 = (ieValue[0] & 0xf0) >> 4;
  guti->gummei.plmn.mcc_digit1 = (ieValue[0]  & 0x0f);
  guti->gummei.plmn.mnc_digit3 = (ieValue[1]  & 0xf0) >> 4;
  guti->gummei.plmn.mcc_digit3 = (ieValue[1]  & 0x0f);
  guti->gummei.plmn.mnc_digit2 = (ieValue[2] & 0xf0) >> 4;
  guti->gummei.plmn.mnc_digit1 = (ieValue[2]  & 0x0f);

  /** Set the MME Group Id. */
  guti->gummei.mme_gid = (*((uint16_t*)(ieValue[3])));

  /** Set the MME Code . */
  guti->gummei.mme_code = ieValue[5];

  /** Set the M-TMSI. */
  guti->m_tmsi =  (*((uint32_t*)(ieValue[6])));

  return NW_OK;
}

NwRcT
s10_msisdn_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  Msisdn_t                               *msisdn;
  uint8_t                                 i;
  uint8_t                                 mask = 0x0F;
  uint8_t                                 msisdn_length = 2 * ieLength;

  DevAssert (arg );
  msisdn = (Msisdn_t *) arg;

  for (i = 0; i < ieLength * 2; i++) {
    if (mask == 0x0F) {
      msisdn->digit[i] = (ieValue[i / 2] & (mask));
    } else {
      msisdn->digit[i] = (ieValue[i / 2] & (mask)) >> 4;
    }

    msisdn->digit[i] += '0';
    mask = ~mask;
  }

  if (msisdn->digit[msisdn_length - 1] == (0x0f + '0')) {
    msisdn->digit[msisdn_length - 1] = 0;
    msisdn_length--;
  }

  msisdn->length = msisdn_length;
  OAILOG_DEBUG (LOG_S10, "\t- MSISDN length %d\n", msisdn->length);
  OAILOG_DEBUG (LOG_S10, "\t-        value  %*s\n", msisdn->length, (char *)msisdn->digit);
  return NW_OK;
}

NwRcT
s10_mei_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  Mei_t                                  *mei = (Mei_t *) arg;

  DevAssert (mei );
  return NW_OK;
}

NwRcT
s10_node_type_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  node_type_t                             *node_type = (node_type_t *) arg;

  DevAssert (node_type );

  if (*ieValue == 0) {
    *node_type = NODE_TYPE_MME;
  } else if (*ieValue == 1) {
    *node_type = NODE_TYPE_SGSN;
  } else {
    OAILOG_ERROR (LOG_S10, "Received unknown value for Node Type: %u\n", *ieValue);
    return NW_GTPV2C_IE_INCORRECT;
  }

  OAILOG_DEBUG (LOG_S10, "\t- Node type %u\n", *node_type);
  return NW_OK;
}

int
s10_node_type_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const node_type_t * node_type)
{
  NwRcT                                   rc;
  uint8_t                                 value;

  DevAssert (node_type );
  DevAssert (msg );

  switch (*node_type) {
  case NODE_TYPE_MME:
    value = 0;
    break;

  case NODE_TYPE_SGSN:
    value = 1;
    break;

  default:
    OAILOG_ERROR (LOG_S10, "Invalid Node type received: %d\n", *node_type);
    return RETURNerror;
  }

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_NODE_TYPE, 1, 0, (uint8_t *) & value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

int
s10_f_cause_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const F_Cause_t * f_cause)
{
  NwRcT                                   rc;
  uint8_t                                 fc_type;

  DevAssert (f_cause);
  DevAssert (msg );

  switch (f_cause->fcause_s1ap_type) {
  case FCAUSE_S1AP_RNL:
    fc_type = 0x00;
    break;

  case FCAUSE_S1AP_TL:
    fc_type = 0x01;
    break;

  case FCAUSE_S1AP_NAS:
    fc_type = 0x02;
    break;

  case FCAUSE_S1AP_Protocol:
    fc_type = 0x03;
    break;

  case FCAUSE_S1AP_Misc:
    fc_type = 0x04;
    break;

  default:
    OAILOG_ERROR (LOG_S10, "Invalid F_Cause type received: %d\n", f_cause->fcause_type);
    return RETURNerror;
  }

  // todo: separate element or f_cause?
  rc = nwGtpv2cMsgAddIeFCause(*msg, NW_GTPV2C_IE_INSTANCE_ZERO, fc_type, f_cause->fcause_value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

int
s10_target_identification_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const target_identification_t * target_identification)
{
  NwRcT                                  rc;
  uint8_t                                target_id[3];
  uint16_t                               macro_enb_id;
  uint16_t                               tac;

  DevAssert (msg );
  DevAssert (target_identification );
  /*
   * MCC Decimal | MCC Hundreds
   */
  target_id[0] = ((target_identification->mcc[1] & 0x0F) << 4) | (target_identification->mcc[0] & 0x0F);
  target_id[1] = target_identification->mcc[2] & 0x0F;

  if ((target_identification->mnc[0] & 0xF) == 0xF) {
    /*
     * Only two digits
     */
    target_id[1] |= 0xF0;
    target_id[2] = ((target_identification->mnc[2] & 0x0F) << 4) | (target_identification->mnc[1] & 0x0F);
  } else {
    target_id[1] |= (target_identification->mnc[2] & 0x0F) << 4;
    target_id[2] = ((target_identification->mnc[1] & 0x0F) << 4) | (target_identification->mnc[0] & 0x0F);
  }

  /** Set The Macro eNodeB Id. */
  macro_enb_id = target_identification->target_id.macro_enb_id.enb_id;
  tac          = target_identification->target_id.macro_enb_id.tac;

  /** Build an array for the TargetIe payload. */

  uint8_t targetIeBuf[9];
  uint8_t *pTargetIeBuf= targetIeBuf;

  memset(pTargetIeBuf, 0, 9);
  /** Target Type. */
  *pTargetIeBuf = target_identification->target_type;
  pTargetIeBuf++;
  /** Set the plmn. */
  memcpy(pTargetIeBuf, target_id, 3);
  pTargetIeBuf+=3;
  /** Macro Enb Id. */
  // Skip 1 place --> todo: copy 20 bits
  pTargetIeBuf++;
  *((uint16_t *) (pTargetIeBuf)) = htons(macro_enb_id);
  pTargetIeBuf+=2;
  /** TAC. */
  *((uint16_t *) (pTargetIeBuf)) = htons(target_identification->target_id.macro_enb_id.tac);
  // todo: extended f-cause?!
  /** Reset the pointer. */
  pTargetIeBuf= targetIeBuf;

  rc = nwGtpv2cMsgAddIe(*msg, NW_GTPV2C_IE_TARGET_IDENTIFICATION, 9, NW_GTPV2C_IE_INSTANCE_ZERO, pTargetIeBuf);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_pdn_connection_ie_set ( NwGtpv2cMsgHandleT * msg, const mme_ue_eps_pdn_connections_t * pdn_connections){
  NwRcT                                   rc;
  uint8_t                                 i;

  DevAssert (msg );
  DevAssert (pdn_connections );
  DevAssert (0 <= pdn_connections->num_pdn_connections);
  DevAssert(MSG_FORWARD_RELOCATION_REQUEST_MAX_PDN_CONNECTIONS >= pdn_connections->num_pdn_connections);

  /*
   * Start section for grouped IE: PDN connection
   */
  rc = nwGtpv2cMsgGroupedIeStart (*msg, NW_GTPV2C_IE_PDN_CONNECTION, NW_GTPV2C_IE_INSTANCE_ZERO);
  DevAssert (NW_OK == rc);

  for (i = 0; i < pdn_connections->num_pdn_connections; i++) {
    /** APN IE Set. */
    s10_apn_ie_set (msg, pdn_connections->pdn_connection[i].apn);

    /** IP Address Set. */
    s10_ip_address_ie_set(msg, &(pdn_connections->pdn_connection[i].ip_address));

    /** EBI Set. */
    s10_ebi_ie_set (msg, pdn_connections->pdn_connection[i].linked_eps_bearer_id);

    /** Set the S5/S8 FTEID. */
    rc = nwGtpv2cMsgAddIeFteid (*msg, NW_GTPV2C_IE_INSTANCE_ZERO,
             S5_S8_PGW_GTP_C,
             pdn_connections->pdn_connection[i].pgw_address_for_cp.teid,
             pdn_connections->pdn_connection[i].pgw_address_for_cp.ipv4 ? ntohl(pdn_connections->pdn_connection[i].pgw_address_for_cp.ipv4_address) : 0,
             pdn_connections->pdn_connection[i].pgw_address_for_cp.ipv6 ? (uint8_t *) pdn_connections->pdn_connection[i].pgw_address_for_cp.ipv6_address : NULL);
    DevAssert (NW_OK == rc);

    /** Set APN Restriction IE. */
    s10_apn_restriction_ie_set(msg, 0x00);
    /** Set AMBR IE. */
    s10_ambr_ie_set(msg, &(pdn_connections->pdn_connection[i].apn_ambr));

    /** Set the PDN connection (another concatenated grouped IE). */
    s10_bearer_context_to_create_ie_set(msg, &(pdn_connections->pdn_connection[i].bearer_context));
  }

  /*
   * End section for grouped IE: PDN connection
   */
  rc = nwGtpv2cMsgGroupedIeEnd (*msg);
  DevAssert (NW_OK == rc);

  return RETURNok;
}

NwRcT
s10_pdn_connection_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  mme_ue_eps_pdn_connections_t         *pdn_connections = (mme_ue_eps_pdn_connections_t *) arg;
  uint8_t                               current_pdn_connection = pdn_connections->num_pdn_connections;
  DevAssert (pdn_connections );
  DevAssert (0 <= current_pdn_connection);
  DevAssert (MSG_FORWARD_RELOCATION_REQUEST_MAX_PDN_CONNECTIONS >= current_pdn_connection + 1);
  pdn_connection_t                       *pdn_connection = &pdn_connections->pdn_connection[current_pdn_connection];
  uint8_t                                 read = 0;
  NwRcT                                   rc;

//  memset (&pdn_connection, 0, sizeof (pdn_connection_t));

  while (ieLength > read) {
    NwGtpv2cIeTlvT                         *ie_p;

    ie_p = (NwGtpv2cIeTlvT *) & ieValue[read];

    switch (ie_p->t) {
      case NW_GTPV2C_IE_EBI:
        rc = s10_ebi_ie_get (ie_p->t, ntohs (ie_p->l), ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &pdn_connection->linked_eps_bearer_id);
        DevAssert (NW_OK == rc);
        break;

      case NW_GTPV2C_IE_BEARER_CONTEXT:
        // todo: handle grouped IE
//        rc = s10_bearer_context_to_be_created_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &pdn_connection->bearer_context);
//        DevAssert (NW_OK == rc);
        break;

      case NW_GTPV2C_IE_APN:
        rc = s10_apn_ie_get (ie_p->t, ntohs (ie_p->l), ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &pdn_connection->apn);
        DevAssert (NW_OK == rc);
        break;

      case NW_GTPV2C_IE_APN_RESTRICTION:
        rc = s10_apn_restriction_ie_get(ie_p->t, ntohs (ie_p->l), ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &pdn_connection->apn_restriction);
        DevAssert (NW_OK == rc);
        break;

      /**
       * IP Address
       */
      case NW_GTPV2C_IE_IP_ADDRESS:
        rc = s10_ip_address_ie_get (ie_p->t, ntohs (ie_p->l), ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &pdn_connection->ip_address);
        DevAssert (NW_OK == rc);
        break;

      /**
       * AMBR IE.
       */
      case NW_GTPV2C_IE_AMBR:
        rc = s10_ambr_ie_get(ie_p->t, ntohs (ie_p->l), ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &pdn_connection->apn_ambr);
        DevAssert (NW_OK == rc);
        break;

      case NW_GTPV2C_IE_FTEID:
        switch (ie_p->i) {
          case 0:
            rc = s10_fteid_ie_get (ie_p->t, ntohs (ie_p->l), ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &pdn_connection->pgw_address_for_cp);
            break;
          default:
            OAILOG_ERROR (LOG_S10, "Received unexpected IE %u instance %u\n", ie_p->t, ie_p->i);
            return NW_GTPV2C_IE_INCORRECT;
        }
        DevAssert (NW_OK == rc);
        break;

      default:
        OAILOG_ERROR (LOG_S10, "Received unexpected IE %u\n", ie_p->t);
        return NW_GTPV2C_IE_INCORRECT;
    }

    read += (ntohs (ie_p->l) + sizeof (NwGtpv2cIeTlvT));
  }
  pdn_connections->num_pdn_connections += 1;
  return NW_OK;
}

NwRcT
s10_ue_mm_eps_context_ie_set ( NwGtpv2cMsgHandleT * msg, const mm_context_eps_t * ue_eps_mm_context){
  NwRcT                                   rc;
  uint8_t                                 value[MM_UE_CONTEXT_MAX_LENGTH];

  DevAssert (msg );
  DevAssert (ue_eps_mm_context );
  memset(value, 0, MM_UE_CONTEXT_MAX_LENGTH);
  int mm_ue_ctx_length = 0;

  /*
   * This is not a grouped IE.
   */
  value[mm_ue_ctx_length] = (ue_eps_mm_context->sec_mode << 5) | (0x1 << 4) | (0x0 << 3) | (ue_eps_mm_context->ksi);
  mm_ue_ctx_length++;
  value[mm_ue_ctx_length] = 0x0;
  mm_ue_ctx_length++;
  value[mm_ue_ctx_length] = (0x0 << 7) | (ue_eps_mm_context->nas_int_alg << 4) | (ue_eps_mm_context->nas_cipher_alg);
  mm_ue_ctx_length++;

  /**
   * NAS Uplink & Downlink Count.
   * Skip the spare region.
   */
  memcpy (&value[mm_ue_ctx_length], (((uint8_t*)&ue_eps_mm_context->nas_dl_count) +1) , 3);
  mm_ue_ctx_length+=3;
  memcpy (&value[mm_ue_ctx_length], (((uint8_t*)&ue_eps_mm_context->nas_ul_count) + 1), 3);
  mm_ue_ctx_length+=3;

  /**
   * K_ASME.
   */
  memcpy (&value[mm_ue_ctx_length], &ue_eps_mm_context->k_asme, 32);
  mm_ue_ctx_length+=32;
  /**
   * Next Hop.
   */
  memcpy (&value[mm_ue_ctx_length], &ue_eps_mm_context->nh, 32);
  mm_ue_ctx_length+=32;
  /**
   * NCC.
   */
  value[mm_ue_ctx_length] |= ue_eps_mm_context->ncc;
  mm_ue_ctx_length++;
  /**
   * UE Network Capability.
   */
  value[mm_ue_ctx_length] = ue_eps_mm_context->ue_nc_length;
  mm_ue_ctx_length++;
  value[mm_ue_ctx_length] = ue_eps_mm_context->ue_nc.eea;
  mm_ue_ctx_length++;
  value[mm_ue_ctx_length] = ue_eps_mm_context->ue_nc.eia;
  mm_ue_ctx_length++;
  if(ue_eps_mm_context->ue_nc.umts_present){
    value[mm_ue_ctx_length] = ue_eps_mm_context->ue_nc.eea;
    mm_ue_ctx_length++;
    value[mm_ue_ctx_length] = ue_eps_mm_context->ue_nc.eia;
    mm_ue_ctx_length++;
  }
  if(ue_eps_mm_context->ue_nc.misc_present){
    // todo: add misc gprs?value[mm_ue_ctx_length] = ue_eps_mm_context->ue_nc.
    // mm_ue_ctx_length++;
  }
  /** Length of MEIMS Network Capability. */ // todo: not setting these fields currently..
  value[mm_ue_ctx_length] = ue_eps_mm_context->ms_nc_length;
  mm_ue_ctx_length++;
  /** Length of MEI. */
  value[mm_ue_ctx_length] = ue_eps_mm_context->mei_length;
  mm_ue_ctx_length++;
  /** Access Restriction Data. */
  value[mm_ue_ctx_length] = ue_eps_mm_context->access_restriction_flags;
  mm_ue_ctx_length++;
  /** Access Restriction Data. */
  value[mm_ue_ctx_length] = ue_eps_mm_context->vdp_lenth;
  mm_ue_ctx_length++;

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_MM_EPS_CONTEXT, mm_ue_ctx_length, 0, value);
  DevAssert (NW_OK == rc);

  return RETURNok;
}

NwRcT
s10_mm_ue_context_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  mm_context_eps_t                       *mm_ue_context = (mm_context_eps_t *) arg;

  DevAssert (mm_ue_context );

  bool nh_present                 = false;
  bool drx_present                = false;
  bool osci_present               = false;
  bool ue_ambr_used_present       = false;
  bool ue_ambr_subscribed_present = false;

  // todo: check the minimum length!
  uint8_t * p_ieValue = ieValue;

  if ( MIN_MM_UE_EPS_CONTEXT_SIZE <= ieLength) {
    /** Get the flags. */
    mm_ue_context->sec_mode = (*p_ieValue >> 5) & 0x07;
    nh_present = ((*p_ieValue >> 4) & 0x01) && 0x01;
    drx_present = ((*p_ieValue >> 3) & 0x01) && 0x01;
    mm_ue_context->ksi = *p_ieValue & 0x07;
    p_ieValue++;
    /**  Number of Quintuplets and Quadruplets. */
    mm_ue_context->num_quit = (*p_ieValue >> 5) & 0x07;
    mm_ue_context->num_quad = (*p_ieValue >> 2) & 0x07;
    ue_ambr_used_present = ((*p_ieValue >> 1) & 0x01) && 0x01;
    osci_present = (*p_ieValue & 0x01) && 0x01;
    p_ieValue++;

    /** Used NAS Integrity and Encrpytion Algorithm. */
    ue_ambr_subscribed_present    = ((*p_ieValue >> 7) & 0x01) && 0x01;
    mm_ue_context->nas_int_alg    = (*p_ieValue >> 4) & 0x07;
    mm_ue_context->nas_cipher_alg = (*p_ieValue) & 0x0F;
    p_ieValue++;
    /** NAS Count. */
    mm_ue_context->nas_dl_count.overflow  = (*((uint16_t*)(p_ieValue))); // todo: only getting the last part or all of it?
    p_ieValue = ((uint16_t *)p_ieValue) + 1; /**< Move by 2. */
    mm_ue_context->nas_dl_count.seq_num = (*p_ieValue); // todo: only getting the last part or all of it?
    p_ieValue++;

    mm_ue_context->nas_ul_count.overflow  = (*((uint16_t*)(p_ieValue)));
    p_ieValue = ((uint16_t *)p_ieValue) + 1; /**< Move by 2. */
    mm_ue_context->nas_ul_count.seq_num = (*p_ieValue);
    p_ieValue++;

    /** Get the K_ASME. */
    memset(mm_ue_context->k_asme, 0, 32);
    memcpy(mm_ue_context->k_asme, p_ieValue, 32);
    p_ieValue+=32;

    /** Check for Quandruplets and Quintuplets. */
    if(mm_ue_context->num_quit > 0){
      // todo: not implemented currently.
      p_ieValue+=mm_ue_context->num_quit;
    }
    if(mm_ue_context->num_quad > 0){
      // todo: not implemented currently.
      p_ieValue+=mm_ue_context->num_quad;
    }
    if(drx_present){
      // todo: get drx
      p_ieValue = ((uint16_t *)p_ieValue) + 1; /**< Move by 2. */
    }

    /** Get the Next Hop value. */
    if(nh_present){
      memset(mm_ue_context->nh, 0, 32);
      memcpy(mm_ue_context->nh, p_ieValue, 32);
      p_ieValue+=32;
    }

    /** Get the Next Hop Chainging Counter. */
    mm_ue_context->ncc = *p_ieValue & 0x07;
    p_ieValue++;

    /** Get the Subscribed UE_AMBR. */
    if(ue_ambr_subscribed_present){
      mm_ue_context->ul_subscribed_ue_ambr = (*((uint32_t*)(p_ieValue)));
      p_ieValue = ((uint32_t *)p_ieValue) + 1; /**< Move by 4. */
      mm_ue_context->dl_subscribed_ue_ambr = (*((uint32_t*)(p_ieValue)));
      p_ieValue = ((uint32_t *)p_ieValue) + 1; /**< Move by 4. */
    }

    /** Get the Used UE_AMBR. */
    if(ue_ambr_used_present){
      mm_ue_context->ul_used_ue_ambr = (*((uint32_t*)(p_ieValue)));
      p_ieValue = ((uint32_t *)p_ieValue) + 1; /**< Move by 4. */
      mm_ue_context->dl_used_ue_ambr = (*((uint32_t*)(p_ieValue)));
      p_ieValue = ((uint32_t *)p_ieValue) + 1; /**< Move by 4. */
    }

    /** Get the UE Network Capability. */
    mm_ue_context->ue_nc_length = *p_ieValue;
    p_ieValue++;
       // todo: get another pointer and increment p_ieValue by length.
      /** Get E-UTRAN Network Capability. */
      mm_ue_context->ue_nc.eea   = *p_ieValue;
      p_ieValue++;
      mm_ue_context->ue_nc.eia   = *p_ieValue;
      p_ieValue++;
      if(mm_ue_context->ue_nc_length> 2 ){
        /** Get UMTS Network Capability. */
        mm_ue_context->ue_nc.uea = *p_ieValue;
        p_ieValue++;
        mm_ue_context->ue_nc.uia = *p_ieValue;
        p_ieValue++;
        /** Get MISC/GPRS. */
        if(mm_ue_context->ue_nc_length > 4 ){
          mm_ue_context->ue_nc.misc_present = true;
          // todo: ..
          p_ieValue++;
        }
      }

    /** Get the MS Network Capability. */
    mm_ue_context->ms_nc_length = *p_ieValue;
    // todo: get the value
    p_ieValue+=mm_ue_context->ms_nc_length;

    /** MEI. */
    mm_ue_context->mei_length = *p_ieValue;
    // todo: get the value
    p_ieValue+=mm_ue_context->mei_length;

    /** Access Restriction Data. */
    mm_ue_context->access_restriction_flags = *p_ieValue;
    p_ieValue++;

    /** Voice Domain Preferences. */
    mm_ue_context->vdp_lenth = *p_ieValue;
    p_ieValue +=mm_ue_context->vdp_lenth;

    // todo: other stuff: need to forward the pointer to the end??

    // todo: checking the size?
    return NW_OK;
  } else {
    return NW_GTPV2C_IE_INCORRECT;
  }
}

/**
 * Complete Request Message IE Getter.
 */
NwRcT
s10_complete_request_message_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  Complete_Request_Message_t                       *request= (Complete_Request_Message_t*) arg;
  DevAssert (request);
  // todo: check the minimum length!
  uint8_t * p_ieValue = ieValue;

  request->request_type = *p_ieValue;
  p_ieValue++;

  // todo: checking the length and copying it from there?
  request->request_value = blk2bstr((void*)p_ieValue, ieLength -1); /**< Todo: Check if this works. Will it stay after ITTI message is sent, also in the destination ?*/
  return NW_OK;
}


/**
 * F_Container IE Getter.
 * Allocated a new bstring in the heap and copies the container in it.
 */
NwRcT
s10_f_container_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  F_Container_t                       *f_container= (F_Container_t*) arg;
  DevAssert (f_container );
  // todo: check the minimum length!
  uint8_t * p_ieValue = ieValue;

  f_container->container_type = *p_ieValue & 0x0F;
  p_ieValue++;
  /** Allocating a new bstring. It will stay until it is manually deallocated. */
  f_container->container_value = blk2bstr((void*)p_ieValue, ieLength -1); /**< Will it stay after ITTI message is sent, also in the destination ?*/
  return NW_OK;
}

NwRcT
s10_pdn_type_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,

  void *arg)
{
  pdn_type_t                             *pdn_type = (pdn_type_t *) arg;

  DevAssert (pdn_type );

  if (*ieValue == 1) {
    /*
     * Only IPv4
     */
    *pdn_type = IPv4;
  } else if (*ieValue == 2) {
    /*
     * Only IPv6
     */
    *pdn_type = IPv6;
  } else if (*ieValue == 3) {
    /*
     * IPv4 and/or IPv6
     */
    *pdn_type = IPv4_AND_v6;
  } else {
    OAILOG_ERROR (LOG_S10, "Received unknown value for PDN Type: %u\n", *ieValue);
    return NW_GTPV2C_IE_INCORRECT;
  }

  OAILOG_DEBUG (LOG_S10, "\t- PDN type %u\n", *pdn_type);
  return NW_OK;
}

int
s10_pdn_type_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const pdn_type_t * pdn_type)
{
  NwRcT                                   rc;
  uint8_t                                 value;

  DevAssert (pdn_type );
  DevAssert (msg );

  switch (*pdn_type) {
  case IPv4:
    value = 1;
    break;

  case IPv6:
    value = 2;
    break;

  case IPv4_AND_v6:
  case IPv4_OR_v6:
    value = 3;
    break;

  default:
    OAILOG_ERROR (LOG_S10, "Invalid PDN type received: %d\n", *pdn_type);
    return RETURNerror;
  }

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_PDN_TYPE, 1, 0, (uint8_t *) & value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_rat_type_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  rat_type_t                             *rat_type = (rat_type_t *) arg;

  DevAssert (rat_type );

  switch (*ieValue) {
  case 1:
    *rat_type = RAT_UTRAN;
    break;

  case 2:
    *rat_type = RAT_GERAN;
    break;

  case 3:
    *rat_type = RAT_WLAN;
    break;

  case 4:
    *rat_type = RAT_GAN;
    break;

  case 5:
    *rat_type = RAT_HSPA_EVOLUTION;
    break;

  case 6:
    *rat_type = RAT_EUTRAN;
    break;

  default:
    OAILOG_ERROR (LOG_S10, "Can't map GTP RAT type %u to EPC definition\n" "\tCheck TS.29.274 #8.17 for possible values\n", *ieValue);
    return NW_GTPV2C_IE_INCORRECT;
  }

  OAILOG_DEBUG (LOG_S10, "\t- RAT type (%d): %d\n", *ieValue, *rat_type);
  return NW_OK;
}

int
s10_rat_type_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const rat_type_t * rat_type)
{
  NwRcT                                   rc;
  uint8_t                                 value;

  DevAssert (rat_type );
  DevAssert (msg );

  switch (*rat_type) {
  case RAT_UTRAN:
    value = 1;
    break;

  case RAT_GERAN:
    value = 2;
    break;

  case RAT_WLAN:
    value = 3;
    break;

  case RAT_GAN:
    value = 4;
    break;

  case RAT_HSPA_EVOLUTION:
    value = 5;
    break;

  case RAT_EUTRAN:
    value = 6;
    break;

  default:
    OAILOG_ERROR (LOG_S10, "Can't map RAT type %d to GTP RAT type\n" "\tCheck TS.29.274 #8.17 for possible values\n", *rat_type);
    return RETURNerror;
  }

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_RAT_TYPE, 1, 0, (uint8_t *) & value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

int
s10_ebi_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const unsigned ebi)
{
  NwRcT                                   rc;
  uint8_t                                 value = 0;

  value = ebi & 0x0F;
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_EBI, 1, 0, &value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_ebi_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  uint8_t                                *ebi = (uint8_t *) arg;

  DevAssert (ebi );
  *ebi = ieValue[0] & 0x0F;
  OAILOG_DEBUG (LOG_S10, "\t- EBI %u\n", *ebi);
  return NW_OK;
}

NwRcT
s10_ebi_ie_get_list (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  ebi_list_t                             *ebi_list = (ebi_list_t*)arg;
  DevAssert (ebi_list);
  DevAssert (RELEASE_ACCESS_BEARER_MAX_BEARERS > ebi_list->num_ebi);
  uint8_t                                *ebi = (uint8_t *)&ebi_list->ebis[ebi_list->num_ebi];

  DevAssert (ebi );
  *ebi = ieValue[0] & 0x0F;
  OAILOG_DEBUG (LOG_S10, "\t- EBI %u\n", *ebi);
  ebi_list->num_ebi += 1;
  return NW_OK;
}


NwRcT
s10_cause_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  SGWCause_t                             *cause = (SGWCause_t *) arg;

  DevAssert (cause );
  *cause = ieValue[0];
  OAILOG_DEBUG (LOG_S10, "\t- Cause %u\n", *cause);
  return NW_OK;
}

int
s10_cause_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const gtp_cause_t * cause)
{
  NwRcT                                   rc;
  uint8_t                                 value[6];

  DevAssert (msg );
  DevAssert (cause );
  value[0] = cause->cause_value;
  value[1] = ((cause->pce & 0x1) << 2) | ((cause->bce & 0x1) << 1) | (cause->cs & 0x1);

  if (cause->offending_ie_type ) {
    value[2] = cause->offending_ie_type;
    value[3] = (cause->offending_ie_length & 0xFF00) >> 8;
    value[4] = cause->offending_ie_length & 0x00FF;
    value[5] = cause->offending_ie_instance & 0x0F;
    rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_CAUSE, 6, 0, value);
  } else {
    rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_CAUSE, 2, 0, value);
  }

  DevAssert (NW_OK == rc);
  return rc == NW_OK ? 0 : -1;
}

int
s10_bearer_context_to_create_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const bearer_context_to_be_created_t * bearer_context)
{
  NwRcT                                   rc;

  DevAssert (msg );
  DevAssert (bearer_context);
  /*
   * Start section for grouped IE: bearer context to create
   */
  rc = nwGtpv2cMsgGroupedIeStart (*msg, NW_GTPV2C_IE_BEARER_CONTEXT, NW_GTPV2C_IE_INSTANCE_ZERO);
  DevAssert (NW_OK == rc);
  /** Set the EBI. */
  s10_ebi_ie_set (msg, bearer_context->eps_bearer_id);
  /** Set the Bearer Level QoS. */
  s10_bearer_qos_ie_set(msg, &bearer_context->bearer_level_qos);
  /** Set the S1U-SGW FTEID. */
  rc = nwGtpv2cMsgAddIeFteid (*msg, NW_GTPV2C_IE_INSTANCE_ZERO,
      bearer_context->s1u_sgw_fteid.interface_type,
      bearer_context->s1u_sgw_fteid.teid, bearer_context->s1u_sgw_fteid.ipv4 ? htonl (bearer_context->s1u_sgw_fteid.ipv4_address) : 0,
          bearer_context->s1u_sgw_fteid.ipv6 ? (uint8_t *) bearer_context->s1u_sgw_fteid.ipv6_address : NULL);
  DevAssert (NW_OK == rc);
  /*
   * End section for grouped IE: bearer context to create
   */
  rc = nwGtpv2cMsgGroupedIeEnd (*msg);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_bearer_context_to_be_created_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  bearer_contexts_to_be_created_t         *bearer_contexts = (bearer_contexts_to_be_created_t *) arg;
  DevAssert (bearer_contexts );
  DevAssert (0 <= bearer_contexts->num_bearer_context);
  DevAssert (MSG_FORWARD_RELOCATION_REQUEST_MAX_BEARER_CONTEXTS >= bearer_contexts->num_bearer_context);
  bearer_context_to_be_created_t          *bearer_context  = &bearer_contexts->bearer_contexts[bearer_contexts->num_bearer_context];
  uint8_t                                 read = 0;
  NwRcT                                   rc;

  while (ieLength > read) {
    NwGtpv2cIeTlvT                         *ie_p;

    ie_p = (NwGtpv2cIeTlvT *) & ieValue[read];

    switch (ie_p->t) {
    case NW_GTPV2C_IE_EBI:
      rc = s10_ebi_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->eps_bearer_id);
      DevAssert (NW_OK == rc);
      break;

    case NW_GTPV2C_IE_BEARER_LEVEL_QOS:
      rc = s10_bearer_qos_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->bearer_level_qos);
      break;

    case NW_GTPV2C_IE_BEARER_TFT:
      OAILOG_ERROR (LOG_S10, "Received IE %u to implement\n", ie_p->t);
      return NW_GTPV2C_IE_INCORRECT;
      break;

    case NW_GTPV2C_IE_FTEID:
      switch (ie_p->i) {
        case 0:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s1u_enb_fteid);
          break;
        case 1:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s4u_sgsn_fteid);
          break;
        case 2:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s5_s8_u_sgw_fteid);
          break;
        case 3:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s5_s8_u_pgw_fteid);
          break;
        case 4:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s12_rnc_fteid);
          break;
        case 5:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s2b_u_epdg_fteid);
          break;
        default:
          OAILOG_ERROR (LOG_S10, "Received unexpected IE %u instance %u\n", ie_p->t, ie_p->i);
          return NW_GTPV2C_IE_INCORRECT;

      }
      DevAssert (NW_OK == rc);
      break;

    default:
      OAILOG_ERROR (LOG_S10, "Received unexpected IE %u\n", ie_p->t);
      return NW_GTPV2C_IE_INCORRECT;
    }

    read += (ntohs (ie_p->l) + sizeof (NwGtpv2cIeTlvT));
  }
  bearer_contexts->num_bearer_context += 1;
  return NW_OK;
}

int
s10_list_of_setup_bearers_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const bearer_context_setup_t * bearer_context)
{
  NwRcT                                   rc;

  DevAssert (msg );
  DevAssert (bearer_context );
  /*
   * Start section for grouped IE: bearer context to create
   */
  rc = nwGtpv2cMsgGroupedIeStart (*msg, NW_GTPV2C_IE_BEARER_CONTEXT, NW_GTPV2C_IE_INSTANCE_ZERO);
  DevAssert (NW_OK == rc);
  s10_ebi_ie_set (msg, bearer_context->eps_bearer_id);
//  s10_bearer_qos_ie_set(msg, &bearer_context->bearer_level_qos);
  /*
   * End section for grouped IE: bearer context to create
   */
  rc = nwGtpv2cMsgGroupedIeEnd (*msg);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

int
s10_bearer_context_to_be_modified_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const bearer_context_to_be_modified_t * bearer_context)
{
  NwRcT                                   rc;

  DevAssert (msg );
  DevAssert (bearer_context );
  /*
   * Start section for grouped IE: bearer context to create
   */
  rc = nwGtpv2cMsgGroupedIeStart (*msg, NW_GTPV2C_IE_BEARER_CONTEXT, NW_GTPV2C_IE_INSTANCE_ZERO);
  DevAssert (NW_OK == rc);
  s10_ebi_ie_set (msg, bearer_context->eps_bearer_id);
  s10_fteid_ie_set(msg, &bearer_context->s1_eNB_fteid);
  /*
   * End section for grouped IE: bearer context to create
   */
  rc = nwGtpv2cMsgGroupedIeEnd (*msg);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_bearer_context_to_be_modified_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  bearer_contexts_to_be_modified_t       *bearer_contexts = (bearer_contexts_to_be_modified_t *) arg;
  DevAssert (bearer_contexts);
  DevAssert (0 <= bearer_contexts->num_bearer_context);
  DevAssert (MSG_MODIFY_BEARER_REQUEST_MAX_BEARER_CONTEXTS >= bearer_contexts->num_bearer_context);
  bearer_context_to_be_modified_t        *bearer_context = &bearer_contexts->bearer_contexts[bearer_contexts->num_bearer_context];
  uint8_t                                 read = 0;
  NwRcT                                   rc;

  DevAssert (bearer_context);

  while (ieLength > read) {
    NwGtpv2cIeTlvT                         *ie_p;

    ie_p = (NwGtpv2cIeTlvT *) & ieValue[read];

    FTeid_t fteid;
    switch (ie_p->t) {
      case NW_GTPV2C_IE_EBI:
        rc = s10_ebi_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->eps_bearer_id);
        DevAssert (NW_OK == rc);
        break;

      case NW_GTPV2C_IE_FTEID:
        rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &fteid);
        switch (fteid.interface_type) {
          case S1_U_ENODEB_GTP_U:
            rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s1_eNB_fteid);
            break;
          case S1_U_SGW_GTP_U:
            rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s1u_sgw_fteid);
            break;
          default:
            OAILOG_WARNING (LOG_S10, "Received unexpected F-TEID type %d\n", fteid.interface_type);
            break;
        }
        DevAssert (NW_OK == rc);
        break;

      case NW_GTPV2C_IE_CAUSE:
        break;

      default:
        OAILOG_ERROR (LOG_S10, "Received unexpected IE %u\n", ie_p->t);
        return NW_GTPV2C_IE_INCORRECT;
    }

    read += (ntohs (ie_p->l) + sizeof (NwGtpv2cIeTlvT));
  }
  bearer_contexts->num_bearer_context += 1;
  return NW_OK;
}

NwRcT
s10_bearer_context_created_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  bearer_contexts_created_t              *bearer_contexts = (bearer_contexts_created_t *) arg;
  DevAssert (bearer_contexts);
  DevAssert (0 <= bearer_contexts->num_bearer_context);
  DevAssert (MSG_CREATE_SESSION_REQUEST_MAX_BEARER_CONTEXTS >= bearer_contexts->num_bearer_context);
  bearer_context_created_t               *bearer_context = &bearer_contexts->bearer_contexts[bearer_contexts->num_bearer_context];
  uint8_t                                 read = 0;
  NwRcT                                   rc;

  while (ieLength > read) {
    NwGtpv2cIeTlvT                         *ie_p;

    ie_p = (NwGtpv2cIeTlvT *) & ieValue[read];

    switch (ie_p->t) {
    case NW_GTPV2C_IE_EBI:
      rc = s10_ebi_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->eps_bearer_id);
      DevAssert (NW_OK == rc);
      break;

    case NW_GTPV2C_IE_FTEID:
      switch (ie_p->i) {
        case 0:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s1u_sgw_fteid);
          break;
        case 1:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s4u_sgw_fteid);
          break;
        case 2:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s5_s8_u_pgw_fteid);
          break;
        case 3:
          rc = s10_fteid_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->s12_sgw_fteid);
          break;
        default:
          OAILOG_ERROR (LOG_S10, "Received unexpected IE %u instance %u\n", ie_p->t, ie_p->i);
          return NW_GTPV2C_IE_INCORRECT;

      }
      DevAssert (NW_OK == rc);
      break;

    case NW_GTPV2C_IE_CAUSE:
      rc = s10_cause_ie_get (ie_p->t, ie_p->l, ie_p->i, &ieValue[read + sizeof (NwGtpv2cIeTlvT)], &bearer_context->cause);
      break;

    default:
      OAILOG_ERROR (LOG_S10, "Received unexpected IE %u\n", ie_p->t);
      return NW_GTPV2C_IE_INCORRECT;
    }

    read += (ntohs (ie_p->l) + sizeof (NwGtpv2cIeTlvT));
  }
  bearer_contexts->num_bearer_context += 1;
  return NW_OK;
}

int
s10_bearer_context_created_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const bearer_context_setup_t * bearer)
{
  NwRcT                                   rc;

  DevAssert (msg );
  DevAssert (bearer);
  /*
   * Start section for grouped IE: bearer context created
   */
  rc = nwGtpv2cMsgGroupedIeStart (*msg, NW_GTPV2C_IE_BEARER_CONTEXT, NW_GTPV2C_IE_INSTANCE_ZERO);
  DevAssert (NW_OK == rc);
  s10_ebi_ie_set (msg, bearer->eps_bearer_id);
  /** No need to set the TEIDs now.. maybe with indirect tunneling. */
//  rc = nwGtpv2cMsgAddIeFteid (*msg, NW_GTPV2C_IE_INSTANCE_ZERO,
//                              bearer->s1u_sgw_fteid.interface_type,
//                              bearer->s1u_sgw_fteid.teid, bearer->s1u_sgw_fteid.ipv4 ? htonl (bearer->s1u_sgw_fteid.ipv4_address) : 0,
//                              bearer->s1u_sgw_fteid.ipv6 ? (uint8_t *) bearer->s1u_sgw_fteid.ipv6_address : NULL);
//  DevAssert (NW_OK == rc);
  /*
   * End section for grouped IE: bearer context created
   */
  rc = nwGtpv2cMsgGroupedIeEnd (*msg);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

/* This IE shall be included in the E-UTRAN initial attach,
   PDP Context Activation and UE Requested PDN connectivity procedures.
   This IE denotes the most stringent restriction as required
   by any already active bearer context. If there are no already active bearer
   contexts, this value is set to the least restrictive type.
*/
int
s10_apn_restriction_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const uint8_t apn_restriction)
{
  NwRcT                                   rc;

  DevAssert (msg );
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_APN_RESTRICTION, 1, 0, (uint8_t *) & apn_restriction);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

int s10_ambr_ie_set(NwGtpv2cMsgHandleT * msg, ambr_t * ambr){

  NwRcT                                   rc;
  uint8_t                                 value[3];

  DevAssert (msg );
  DevAssert (ambr );
  /*
   * MCC Decimal | MCC Hundreds
   */

  uint8_t                                 ambr_br[16];
  uint8_t                                 *p_ambr;
  p_ambr = ambr_br;

  memset(ambr_br, 0, 16);

  INT64_TO_BUFFER(ambr->br_ul, p_ambr);
  p_ambr+=8;

  INT64_TO_BUFFER(ambr->br_dl, p_ambr);
  // todo: byte order?

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_AMBR, 16, 0, p_ambr);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_serving_network_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  ServingNetwork_t                       *serving_net = (ServingNetwork_t *) arg;

  DevAssert (serving_net );
  serving_net->mcc[1] = (ieValue[0] & 0xF0) >> 4;
  serving_net->mcc[0] = (ieValue[0] & 0x0F);
  serving_net->mcc[2] = (ieValue[1] & 0x0F);

  if ((ieValue[1] & 0xF0) == 0xF0) {
    /*
     * Two digits MNC
     */
    serving_net->mnc[0] = 0;
    serving_net->mnc[1] = (ieValue[2] & 0x0F);
    serving_net->mnc[2] = (ieValue[2] & 0xF0) >> 4;
  } else {
    serving_net->mnc[0] = (ieValue[2] & 0x0F);
    serving_net->mnc[1] = (ieValue[2] & 0xF0) >> 4;
    serving_net->mnc[2] = (ieValue[1] & 0xF0) >> 4;
  }

  OAILOG_DEBUG (LOG_S10, "\t- Serving network %d.%d\n", serving_net->mcc[0] * 100 + serving_net->mcc[1] * 10 + serving_net->mcc[2], serving_net->mnc[0] * 100 + serving_net->mnc[1] * 10 + serving_net->mnc[2]);
  return NW_OK;
}

int
s10_serving_network_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const ServingNetwork_t * serving_network)
{
  NwRcT                                   rc;
  uint8_t                                 value[3];

  DevAssert (msg );
  DevAssert (serving_network );
  /*
   * MCC Decimal | MCC Hundreds
   */
  value[0] = ((serving_network->mcc[1] & 0x0F) << 4) | (serving_network->mcc[0] & 0x0F);
  value[1] = serving_network->mcc[2] & 0x0F;

  if ((serving_network->mnc[0] & 0xF) == 0xF) {
    /*
     * Only two digits
     */
    value[1] |= 0xF0;
    value[2] = ((serving_network->mnc[2] & 0x0F) << 4) | (serving_network->mnc[1] & 0x0F);
  } else {
    value[1] |= (serving_network->mnc[2] & 0x0F) << 4;
    value[2] = ((serving_network->mnc[1] & 0x0F) << 4) | (serving_network->mnc[0] & 0x0F);
  }

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_SERVING_NETWORK, 3, 0, value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

int
s10_fteid_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const FTeid_t * fteid)
{
  NwRcT                                   rc;
  uint8_t                                 value[25];

  DevAssert (msg );
  DevAssert (fteid );
  /*
   * MCC Decimal | MCC Hundreds
   */
  value[0] = (fteid->ipv4 << 7) | (fteid->ipv6 << 6) | (fteid->interface_type & 0x3F);
  value[1] = (fteid->teid >> 24 );
  value[2] = (fteid->teid >> 16 ) & 0xFF;
  value[3] = (fteid->teid >>  8 ) & 0xFF;
  value[4] = (fteid->teid >>  0 ) & 0xFF;

  int offset = 5;
  if (fteid->ipv4 == 1) {
    memcpy (&value[offset], &fteid->ipv4_address, 4);
    offset += 4;
  }
  if (fteid->ipv6 == 1) {
    /*
     * IPv6 present: copy the 16 bytes
     */
    memcpy (&value[offset], &fteid->ipv6_address[0], 16);
    offset += 16;
  }

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_FTEID, offset, 0, value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}


NwRcT
s10_fteid_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  uint8_t                                 offset = 0;
  FTeid_t                                *fteid = (FTeid_t *) arg;

  DevAssert (fteid );
  fteid->ipv4 = (ieValue[0] & 0x80) >> 7;
  fteid->ipv6 = (ieValue[0] & 0x40) >> 6;
  fteid->interface_type = ieValue[0] & 0x1F;
  OAILOG_DEBUG (LOG_S10, "\t- F-TEID type %d\n", fteid->interface_type);
  /*
   * Copy the TEID or GRE key
   */
  fteid->teid = ntoh_int32_buf (&ieValue[1]);
  OAILOG_DEBUG (LOG_S10, "\t- TEID/GRE    %08x\n", fteid->teid);

  if (fteid->ipv4 == 1) {
    /*
     * IPv4 present: copy the 4 bytes
     */
    memcpy (&fteid->ipv4_address, &ieValue[5], 4);
    offset = 4;
    OAILOG_DEBUG (LOG_S10, "\t- IPv4 addr   " IPV4_ADDR "\n", IPV4_ADDR_FORMAT (fteid->ipv4_address));
  }

  if (fteid->ipv6 == 1) {
    char                                    ipv6_ascii[40];

    /*
     * IPv6 present: copy the 16 bytes
     * * * * WARNING: if Ipv4 is present, 4 bytes of offset should be applied
     */
    memcpy (fteid->ipv6_address, &ieValue[5 + offset], 16);
    inet_ntop (AF_INET6, fteid->ipv6_address, ipv6_ascii, 40);
    OAILOG_DEBUG (LOG_S10, "\t- IPv6 addr   %s\n", ipv6_ascii);
  }

  return NW_OK;
}

NwRcT
s10_pco_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  uint8_t                                 offset = 0;
  protocol_configuration_options_t       *pco = (protocol_configuration_options_t *) arg;

  DevAssert (pco );
  offset = decode_protocol_configuration_options (pco, ieValue, ieLength);
  if ((0 < offset) && (PCO_MAX_LENGTH >= offset))
    return NW_OK;
  else
    return NW_GTPV2C_IE_INCORRECT;
}

int
s10_pco_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const protocol_configuration_options_t * pco)
{
  uint8_t                                 temp[PCO_MAX_LENGTH];
  uint8_t                                 offset = 0;
  NwRcT                                   rc = NW_OK;

  DevAssert (pco );
  offset = encode_protocol_configuration_options(pco, temp, PCO_MAX_LENGTH);
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_PCO, offset, 0, temp);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_paa_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  uint8_t                                 offset = 0;
  PAA_t                                  *paa = (PAA_t *) arg;

  DevAssert (paa );
  paa->pdn_type = ieValue[0] & 0x07;
  OAILOG_DEBUG (LOG_S10, "\t- PAA type  %d\n", paa->pdn_type);

  if (paa->pdn_type & 0x2) {
    char                                    ipv6_ascii[40];

    /*
     * IPv6 present: copy the 16 bytes
     * * * * WARNING: if both ipv4 and ipv6 are present,
     * * * *          17 bytes of offset should be applied for ipv4
     * * * * NOTE: an ipv6 prefix length is prepend
     * * * * NOTE: in Rel.8 the prefix length has a default value of /64
     */
    paa->ipv6_prefix_length = ieValue[1];
    memcpy (paa->ipv6_address, &ieValue[2], 16);
    inet_ntop (AF_INET6, paa->ipv6_address, ipv6_ascii, 40);
    OAILOG_DEBUG (LOG_S10, "\t- IPv6 addr %s/%u\n", ipv6_ascii, paa->ipv6_prefix_length);
  }

  if (paa->pdn_type == 3) {
    offset = 17;
  }

  if (paa->pdn_type & 0x1) {
    memcpy (paa->ipv4_address, &ieValue[1 + offset], 4);
    OAILOG_DEBUG (LOG_S10, "\t- IPv4 addr " IPV4_ADDR "\n", paa->ipv4_address[0], paa->ipv4_address[1], paa->ipv4_address[2], paa->ipv4_address[3]);
  }

  paa->pdn_type -= 1;
  return NW_OK;
}

int
s10_paa_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const PAA_t * paa)
{
  /*
   * ipv4 address = 4 + ipv6 address = 16 + ipv6 prefix length = 1
   * * * * + pdn_type = 1
   * * * * = maximum of 22 bytes
   */
  uint8_t                                 temp[22];
  uint8_t                                 pdn_type;
  uint8_t                                 offset = 0;
  NwRcT                                   rc;

  DevAssert (paa );
  pdn_type = paa->pdn_type + 1;
  temp[offset] = pdn_type;
  offset++;

  if (pdn_type & 0x2) {
    /*
     * If ipv6 or ipv4v6 present
     */
    temp[1] = paa->ipv6_prefix_length;
    memcpy (&temp[2], paa->ipv6_address, 16);
    offset += 17;
  }

  if (pdn_type & 0x1) {
    memcpy (&temp[offset], paa->ipv4_address, 4);
    offset += 4;
  }

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_PAA, offset, 0, temp);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

/* The encoding of the APN shall follow the Name Syntax defined in RFC 2181,
   RFC 1035 and RFC 1123. The APN consists of one or more labels. Each label
   is coded as a one octet length field followed by that number of octets
   coded as 8 bit ASCII characters. Following RFC 1035 the labels shall consist
   only of the alphabetic characters (A-Z and a-z), digits (0-9)
   and the hyphen (-).
*/
NwRcT
s10_apn_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  uint8_t                                 read = 1;
  uint8_t                                 word_length;
  char                                   *apn = (char *)arg;

  DevAssert (apn );
  DevCheck (ieLength <= APN_MAX_LENGTH, ieLength, APN_MAX_LENGTH, 0);
  word_length = ieValue[0];

  while (read < ieLength) {
    if (word_length > 0) {
      apn[read - 1] = ieValue[read];
      word_length--;
    } else {
      /*
       * This is not an alphanumeric character
       */
      word_length = ieValue[read];
      /*
       * Replace the length attribute by '.'
       */
      apn[read - 1] = '.';
    }

    read++;
  }

  apn[read - 1] = '\0';
  OAILOG_DEBUG (LOG_S10, "\t- APN %s\n", apn);
  return NW_OK;
}

int
s10_apn_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const char *apn)
{
  NwRcT                                   rc;
  uint8_t                                *value;
  uint8_t                                 apn_length;
  uint8_t                                 offset = 0;
  uint8_t                                *last_size;
  uint8_t                                 word_length = 0;

  DevAssert (apn );
  DevAssert (msg );
  apn_length = strlen (apn);
  value = calloc (apn_length + 1, sizeof (uint8_t));
  last_size = &value[0];

  while (apn[offset]) {
    /*
     * We replace the . by the length of the word
     */
    if (apn[offset] == '.') {
      *last_size = word_length;
      word_length = 0;
      last_size = &value[offset + 1];
    } else {
      word_length++;
      value[offset + 1] = apn[offset];
    }

    offset++;
  }

  *last_size = word_length;
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_APN, apn_length + 1, 0, value);
  DevAssert (NW_OK == rc);
  free_wrapper ((void**) &value);
  return RETURNok;
}

int
s10_apn_plmn_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const char *apn,
  const ServingNetwork_t * serving_network)
{
  NwRcT                                   rc;
  uint8_t                                *value;
  uint8_t                                 apn_length;
  uint8_t                                *last_size;

  DevAssert (serving_network );

  DevAssert (apn );
  DevAssert (msg );
  apn_length = strlen (apn);
  value = calloc (apn_length + 20, sizeof (uint8_t)); //"default" + neu: ".mncXXX.mccXXX.gprs"
  last_size = &value[0];

  memcpy(&value[1], apn, apn_length);
  memcpy(&value[apn_length + 1], ".mnc", 4);
  memcpy(&value[apn_length + 8], ".mcc", 4);
  memcpy(&value[apn_length + 15], ".gprs", 5);
  if (serving_network->mnc[2] == 0x0F) {
    /*
     * Two digits MNC
     */
    value[apn_length + 5] = '0';
    value[apn_length + 6] = serving_network->mnc[0] + '0';
    value[apn_length + 7] = serving_network->mnc[1] + '0';
  } else {
    value[apn_length + 5] = serving_network->mnc[0] + '0';
    value[apn_length + 6] = serving_network->mnc[1] + '0';
    value[apn_length + 7] = serving_network->mnc[2] + '0';
  }
  value[apn_length + 12] = serving_network->mcc[0] + '0';
  value[apn_length + 13] = serving_network->mcc[1] + '0';
  value[apn_length + 14] = serving_network->mcc[2] + '0';

  *last_size = apn_length + 19;
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_APN, apn_length + 20, 0, value);
  DevAssert (NW_OK == rc);
  free_wrapper ((void**) &value);
  return RETURNok;
}

NwRcT
s10_ambr_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  ambr_t                                 *ambr = (ambr_t *) arg;

  DevAssert (ambr );
  ambr->br_ul = ntoh_int32_buf (&ieValue[0]);
  ambr->br_dl = ntoh_int32_buf (&ieValue[4]);
  OAILOG_DEBUG (LOG_S10, "\t- AMBR UL %" PRIu64 "\n", ambr->br_ul);
  OAILOG_DEBUG (LOG_S10, "\t- AMBR DL %" PRIu64 "\n", ambr->br_dl);
  return NW_OK;
}

NwRcT
s10_uli_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  Uli_t                                  *uli = (Uli_t *) arg;

  DevAssert (uli );
  uli->present = ieValue[0];

  if (uli->present & ULI_CGI) {
  }

  return NW_OK;
}

NwRcT
s10_bearer_qos_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  BearerQOS_t                       *bearer_qos = (BearerQOS_t *) arg;

  DevAssert (bearer_qos );

  if (18 <= ieLength) {
    bearer_qos->pci = (ieValue[0] >> 6) & 0x01;
    bearer_qos->pci = (ieValue[0] >> 6) & 0x01;
    bearer_qos->pl  = (ieValue[0] >> 2) & 0x0F;
    bearer_qos->pvi = ieValue[0] & 0x01;
    bearer_qos->qci = ieValue[1];

    memcpy (&bearer_qos->mbr.br_ul, &ieValue[2], 4);
    memcpy (&bearer_qos->mbr.br_dl, &ieValue[6], 4);
    memcpy (&bearer_qos->gbr.br_ul, &ieValue[10], 4);
    memcpy (&bearer_qos->gbr.br_dl, &ieValue[14], 4);

    bearer_qos->mbr.br_ul = ntohl(bearer_qos->mbr.br_ul);
    bearer_qos->mbr.br_dl = ntohl(bearer_qos->mbr.br_dl);
    bearer_qos->gbr.br_ul = ntohl(bearer_qos->gbr.br_ul);
    bearer_qos->gbr.br_dl = ntohl(bearer_qos->gbr.br_dl);
    if (18 < ieLength) {
      OAILOG_ERROR (LOG_S10, "TODO s10_bearer_qos_ie_get() BearerQOS_t\n");
      return NW_GTPV2C_IE_INCORRECT;
    }
    return NW_OK;
  } else {
    return NW_GTPV2C_IE_INCORRECT;
  }
}


int
s10_bearer_qos_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const BearerQOS_t * bearer_qos)
{
  NwRcT                                   rc;
  uint8_t                                 value[22];

  DevAssert (msg );
  DevAssert (bearer_qos );
  value[0] = (bearer_qos->pci << 6) | (bearer_qos->pl << 2) | (bearer_qos->pvi);
  value[1] = bearer_qos->qci;
  /*
   * TODO: check endianness
   */
  memcpy (&value[2], &bearer_qos->mbr.br_ul, 5);
  memcpy (&value[7], &bearer_qos->mbr.br_dl, 5);
  memcpy (&value[12], &bearer_qos->gbr.br_ul, 5);
  memcpy (&value[17], &bearer_qos->gbr.br_dl, 5);
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_BEARER_LEVEL_QOS, 22, 0, value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_ip_address_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  gtp_ip_address_t                       *ip_address = (gtp_ip_address_t *) arg;

  DevAssert (ip_address );

  if (ieLength == 4) {
    /*
     * This is an IPv4 Address
     */
    ip_address->present = GTP_IP_ADDR_v4;
    memcpy (ip_address->address.v4, ieValue, 4);
  } else if (ieLength == 16) {
    /*
     * This is an IPv6 Address
     */
    ip_address->present = GTP_IP_ADDR_v6;
    memcpy (ip_address->address.v6, ieValue, 16);
  } else {
    /*
     * Length doesn't lie in possible values
     */
    return NW_GTPV2C_IE_INCORRECT;
  }

  return NW_OK;
}

int
s10_ip_address_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const gtp_ip_address_t * ip_address)
{
  uint8_t                                 temp[16];
  uint8_t                                 offset = 0;
  NwRcT                                   rc;

  DevAssert (ip_address );

  if (ip_address->present & 0x1) {
    /*
     * If ipv6 or ipv4v6 present
     */
    /** Type is determined from the length. */
    memcpy (&temp[offset], ip_address->address.v6, 16);
    offset += 16;
  }else{
    memcpy (&temp[offset], ip_address->address.v4, 4);
    offset += 4;
  }

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_IP_ADDRESS, offset, 0, temp);
  DevAssert (NW_OK == rc);

  return RETURNok;
}

int
s10_apn_restriction_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
     APNRestriction_t                           *apn_restriction= (APNRestriction_t *) arg;

     DevAssert (arg );

     if (ieLength != 1) {
       return NW_GTPV2C_IE_INCORRECT;
     }

     *apn_restriction= ieValue[0];
     OAILOG_DEBUG (LOG_S10, "\t - APN Restriction Value %u\n", *apn_restriction);
     return NW_OK;
}

NwRcT
s10_delay_value_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  DelayValue_t                           *delay_value = (DelayValue_t *) arg;

  DevAssert (arg );

  if (ieLength != 1) {
    return NW_GTPV2C_IE_INCORRECT;
  }

  *delay_value = ieValue[0];
  OAILOG_DEBUG (LOG_S10, "\t - Delay Value %u\n", *delay_value);
  return NW_OK;
}

int
s10_delay_value_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const DelayValue_t * delay_value)
{
  uint8_t                                 value;
  NwRcT                                   rc;

  DevAssert (msg );
  DevAssert (delay_value );
  value = *delay_value;
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_DELAY_VALUE, 1, 0, (uint8_t *) & value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_ue_time_zone_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  UETimeZone_t                           *ue_time_zone = (UETimeZone_t *) arg;

  DevAssert (ue_time_zone );

  if (ieLength != 2) {
    return NW_GTPV2C_IE_INCORRECT;
  }

  ue_time_zone->time_zone = ieValue[0];
  ue_time_zone->daylight_saving_time = ieValue[1] & 0x03;
  OAILOG_DEBUG (LOG_S10, "\t - Time Zone    %u\n", ue_time_zone->time_zone);
  OAILOG_DEBUG (LOG_S10, "\t - Daylight SVT %u\n", ue_time_zone->daylight_saving_time);
  return NW_OK;
}

int
s10_ue_time_zone_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const UETimeZone_t * ue_time_zone)
{
  uint8_t                                 value[2];
  NwRcT                                   rc;

  DevAssert (msg );
  DevAssert (ue_time_zone );
  value[0] = ue_time_zone->time_zone;
  value[1] = ue_time_zone->daylight_saving_time;
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_UE_TIME_ZONE, 2, 0, value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_target_identification_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  target_identification_t                *target_identification = (target_identification_t *) arg;

  DevAssert (target_identification );
  target_identification->target_type = ieValue[0];

  target_identification->mcc[1] = (ieValue[1] & 0xF0) >> 4;
  target_identification->mcc[0] = (ieValue[1] & 0x0F);
  target_identification->mcc[2] = (ieValue[2] & 0x0F);

  if ((ieValue[1] & 0xF0) == 0xF0) {
    /*
     * Two digits MNC
     */
    target_identification->mnc[0] = 0;
    target_identification->mnc[1] = (ieValue[3] & 0x0F);
    target_identification->mnc[2] = (ieValue[3] & 0xF0) >> 4;
  } else {
    target_identification->mnc[0] = (ieValue[3] & 0x0F);
    target_identification->mnc[1] = (ieValue[3] & 0xF0) >> 4;
    target_identification->mnc[2] = (ieValue[2] & 0xF0) >> 4;
  }

  switch (target_identification->target_type) {
  case TARGET_ID_RNC_ID:{
      target_identification->target_id.rnc_id.lac = (ieValue[4] << 8) | ieValue[5];
      target_identification->target_id.rnc_id.rac = ieValue[6];

      if (ieLength == 11) {
        /*
         * Extended RNC id
         */
        target_identification->target_id.rnc_id.rnc_id = (ieValue[7] << 24) | (ieValue[8] << 16) | (ieValue[9] << 8) | (ieValue[10]);
      } else if (ieLength == 9) {
        /*
         * Normal RNC id
         */
        target_identification->target_id.rnc_id.rnc_id = (ieValue[7] << 8) | ieValue[8];
      } else {
        /*
         * This case is not possible
         */
        return NW_GTPV2C_IE_INCORRECT;
      }

      OAILOG_DEBUG (LOG_S10, "\t\t- LAC 0x%04x\n", target_identification->target_id.rnc_id.lac);
      OAILOG_DEBUG (LOG_S10, "\t\t- RAC 0x%02x\n", target_identification->target_id.rnc_id.rac);
      OAILOG_DEBUG (LOG_S10, "\t\t- RNC 0x%08x\n", target_identification->target_id.rnc_id.rnc_id);
    }
    break;

  case TARGET_ID_MACRO_ENB_ID:{
      if (ieLength != 9) {
        return NW_GTPV2C_IE_INCORRECT;
      }

      target_identification->target_id.macro_enb_id.enb_id = ((ieValue[4] & 0x0F) << 16) | (ieValue[5] << 8) | ieValue[6];
      target_identification->target_id.macro_enb_id.tac = (ieValue[7] << 8) | ieValue[8];
      OAILOG_DEBUG (LOG_S10, "\t\t- ENB Id 0x%06x\n", target_identification->target_id.macro_enb_id.enb_id);
      OAILOG_DEBUG (LOG_S10, "\t\t- TAC    0x%04x\n", target_identification->target_id.macro_enb_id.tac);
    }
    break;

  case TARGET_ID_HOME_ENB_ID:{
      if (ieLength != 10) {
        return NW_GTPV2C_IE_INCORRECT;
      }

      target_identification->target_id.home_enb_id.enb_id = ((ieValue[4] & 0x0F) << 14) | (ieValue[5] << 16) | (ieValue[6] << 8) | ieValue[7];
      target_identification->target_id.home_enb_id.tac = (ieValue[8] << 8) | ieValue[9];
      OAILOG_DEBUG (LOG_S10, "\t\t- ENB Id 0x%07x\n", target_identification->target_id.home_enb_id.enb_id);
      OAILOG_DEBUG (LOG_S10, "\t\t- TAC    0x%04x\n", target_identification->target_id.home_enb_id.tac);
    }
    break;

  default:
    return NW_GTPV2C_IE_INCORRECT;
  }

  return NW_OK;
}

NwRcT
s10_bearer_flags_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  bearer_flags_t                         *bearer_flags = (bearer_flags_t *) arg;

  DevAssert (arg );

  if (ieLength != 1) {
    return NW_GTPV2C_IE_INCORRECT;
  }

  bearer_flags->ppc = ieValue[0] & 0x01;
  bearer_flags->vb = ieValue[0] & 0x02;
  return NW_OK;
}

int
s10_bearer_flags_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const bearer_flags_t * bearer_flags)
{
  NwRcT                                   rc;
  uint8_t                                 value;

  DevAssert (msg );
  DevAssert (bearer_flags );
  value = (bearer_flags->vb << 1) | bearer_flags->ppc;
  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_BEARER_FLAGS, 1, 0, (uint8_t *) & value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_indication_flags_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  indication_flags_t                     *indication_flags = (indication_flags_t *) arg;

  DevAssert (indication_flags );

  if (ieLength != 3) { // think about more than 3 later
    return NW_GTPV2C_IE_INCORRECT;
  }

  indication_flags->daf   = (ieValue[0] >> DAF_FLAG_BIT_POS)   & 0x01;
  indication_flags->dtf   = (ieValue[0] >> DTF_FLAG_BIT_POS)   & 0x01;
  indication_flags->hi    = (ieValue[0] >> HI_FLAG_BIT_POS)    & 0x01;
  indication_flags->dfi   = (ieValue[0] >> DFI_FLAG_BIT_POS)   & 0x01;
  indication_flags->oi    = (ieValue[0] >> OI_FLAG_BIT_POS)    & 0x01;
  indication_flags->isrsi = (ieValue[0] >> ISRSI_FLAG_BIT_POS) & 0x01;
  indication_flags->israi = (ieValue[0] >> ISRAI_FLAG_BIT_POS) & 0x01;
  indication_flags->sgwci = (ieValue[0] >> SGWCI_FLAG_BIT_POS) & 0x01;

  indication_flags->sqci  = (ieValue[1] >> SQSI_FLAG_BIT_POS)  & 0x01;
  indication_flags->uimsi = (ieValue[1] >> UIMSI_FLAG_BIT_POS) & 0x01;
  indication_flags->cfsi  = (ieValue[1] >> CFSI_FLAG_BIT_POS)  & 0x01;
  indication_flags->crsi  = (ieValue[1] >> CRSI_FLAG_BIT_POS)  & 0x01;
  indication_flags->p     = (ieValue[1] >> P_FLAG_BIT_POS)     & 0x01;
  indication_flags->pt    = (ieValue[1] >> PT_FLAG_BIT_POS)    & 0x01;
  indication_flags->si    = (ieValue[1] >> SI_FLAG_BIT_POS)    & 0x01;
  indication_flags->msv   = (ieValue[1] >> MSV_FLAG_BIT_POS)   & 0x01;

  indication_flags->spare1 = 0;
  indication_flags->spare2 = 0;
  indication_flags->spare3 = 0;
  indication_flags->s6af  = (ieValue[2] >> S6AF_FLAG_BIT_POS)  & 0x01;
  indication_flags->s4af  = (ieValue[2] >> S4AF_FLAG_BIT_POS)  & 0x01;
  indication_flags->mbmdt = (ieValue[2] >> MBMDT_FLAG_BIT_POS) & 0x01;
  indication_flags->israu = (ieValue[2] >> ISRAU_FLAG_BIT_POS) & 0x01;
  indication_flags->ccrsi = (ieValue[2] >> CRSI_FLAG_BIT_POS)  & 0x01;
  return NW_OK;
}

int
s10_indication_flags_ie_set (
  NwGtpv2cMsgHandleT * msg,
  const indication_flags_t * indication_flags)
{
  NwRcT                                   rc;
  uint8_t                                 value[3];

  DevAssert (msg );
  DevAssert (indication_flags );
  value[0] = (indication_flags->daf << DAF_FLAG_BIT_POS) |
      (indication_flags->dtf   << DTF_FLAG_BIT_POS) |
      (indication_flags->hi    << HI_FLAG_BIT_POS) |
      (indication_flags->dfi   << DFI_FLAG_BIT_POS) |
      (indication_flags->oi    << OI_FLAG_BIT_POS) |
      (indication_flags->isrsi << ISRSI_FLAG_BIT_POS) |
      (indication_flags->israi << ISRAI_FLAG_BIT_POS) |
      (indication_flags->sgwci << SGWCI_FLAG_BIT_POS);

  value[1] = (indication_flags->sqci << SQSI_FLAG_BIT_POS) |
      (indication_flags->uimsi << UIMSI_FLAG_BIT_POS) |
      (indication_flags->cfsi  << CFSI_FLAG_BIT_POS) |
      (indication_flags->crsi  << CRSI_FLAG_BIT_POS) |
      (indication_flags->p     << P_FLAG_BIT_POS) |
      (indication_flags->pt    << PT_FLAG_BIT_POS) |
      (indication_flags->si    << SI_FLAG_BIT_POS) |
      (indication_flags->msv   << MSV_FLAG_BIT_POS);

  value[2] = (indication_flags->s6af << S6AF_FLAG_BIT_POS) |
      (indication_flags->s4af   << S4AF_FLAG_BIT_POS) |
      (indication_flags->mbmdt  << MBMDT_FLAG_BIT_POS) |
      (indication_flags->israu  << ISRAU_FLAG_BIT_POS) |
      (indication_flags->ccrsi  << CCRSI_FLAG_BIT_POS);

  rc = nwGtpv2cMsgAddIe (*msg, NW_GTPV2C_IE_INDICATION, 1, 3, (uint8_t*)value);
  DevAssert (NW_OK == rc);
  return RETURNok;
}

NwRcT
s10_fqcsid_ie_get (
  uint8_t ieType,
  uint8_t ieLength,
  uint8_t ieInstance,
  uint8_t * ieValue,
  void *arg)
{
  FQ_CSID_t                              *fq_csid = (FQ_CSID_t *) arg;

  DevAssert (fq_csid );
  fq_csid->node_id_type = (ieValue[0] & 0xF0) >> 4;
  OAILOG_DEBUG (LOG_S10, "\t- FQ-CSID type %u\n", fq_csid->node_id_type);

  /*
   * NOTE: Values of Number of CSID other than 1 are only employed in the
   * * * * Delete PDN Connection Set Request and Response.
   */
  if ((ieValue[0] & 0x0F) != 1) {
    return NW_GTPV2C_IE_INCORRECT;
  }

  switch (fq_csid->node_id_type) {
  case GLOBAL_UNICAST_IPv4:{
      if (ieLength != 7) {
        return NW_GTPV2C_IE_INCORRECT;
      }

      fq_csid->node_id.unicast_ipv4 = (ieValue[1] << 24) | (ieValue[2] << 16) | (ieValue[3] << 8) | (ieValue[4]);
      fq_csid->csid = (ieValue[5] << 8) | ieValue[6];
      OAILOG_DEBUG (LOG_S10, "\t- v4 address [" IPV4_ADDR "]\n", IPV4_ADDR_FORMAT (fq_csid->node_id.unicast_ipv4));
    }
    break;

  case GLOBAL_UNICAST_IPv6:{
      char                                    ipv6[40];

      if (ieLength != 19) {
        return NW_GTPV2C_IE_INCORRECT;
      }

      memcpy (fq_csid->node_id.unicast_ipv6, &ieValue[1], 16);
      fq_csid->csid = (ieValue[17] << 8) | ieValue[18];
      /*
       * Convert the ipv6 to printable string
       */
      inet_ntop (AF_INET6, fq_csid->node_id.unicast_ipv6, ipv6, 40);
      OAILOG_DEBUG (LOG_S10, "\t- v6 address [%s]\n", fq_csid->node_id.unicast_ipv6);
    }
    break;

  default:
    return NW_GTPV2C_IE_INCORRECT;
  }

  OAILOG_DEBUG (LOG_S10, "\t- CSID 0x%04x\n", fq_csid->csid);
  return NW_OK;
}
