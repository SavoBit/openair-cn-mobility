/*
 * Copyright (c) 2015, EURECOM (www.eurecom.fr)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
 */
//WARNING: Do not include this header directly. Use intertask_interface.h instead.

/* Messages for S1AP logging */
MESSAGE_DEF(S1AP_UPLINK_NAS_LOG            , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_uplink_nas_log)
MESSAGE_DEF(S1AP_UE_CAPABILITY_IND_LOG     , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_ue_capability_ind_log)
MESSAGE_DEF(S1AP_INITIAL_CONTEXT_SETUP_LOG , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_initial_context_setup_log)
MESSAGE_DEF(S1AP_NAS_NON_DELIVERY_IND_LOG  , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_nas_non_delivery_ind_log)
MESSAGE_DEF(S1AP_DOWNLINK_NAS_LOG          , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_downlink_nas_log)
MESSAGE_DEF(S1AP_S1_SETUP_LOG              , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_s1_setup_log)
MESSAGE_DEF(S1AP_PATH_SWITCH_REQUEST_LOG   , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_path_switch_request_log)
MESSAGE_DEF(S1AP_HANDOVER_REQUIRED_LOG     , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_handover_required_log)
MESSAGE_DEF(S1AP_HANDOVER_CANCEL_LOG       , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_handover_cancel_log)

MESSAGE_DEF(S1AP_ENB_STATUS_TRANSFER_LOG   , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_enb_status_transfer_log)
MESSAGE_DEF(S1AP_HANDOVER_NOTIFY_LOG       , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_handover_notify_log)
MESSAGE_DEF(S1AP_HANDOVER_REQUEST_ACKNOWLEDGE_LOG       , MESSAGE_PRIORITY_MED, IttiMsgText         , s1ap_handover_request_acknowledge_log)

MESSAGE_DEF(S1AP_INITIAL_UE_MESSAGE_LOG    , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_initial_ue_message_log)
MESSAGE_DEF(S1AP_UE_CONTEXT_RELEASE_REQ_LOG, MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_ue_context_release_req_log)
MESSAGE_DEF(S1AP_UE_CONTEXT_RELEASE_COMMAND_LOG, MESSAGE_PRIORITY_MED, IttiMsgText                  , s1ap_ue_context_release_command_log)
MESSAGE_DEF(S1AP_UE_CONTEXT_RELEASE_LOG    , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_ue_context_release_log)
MESSAGE_DEF(S1AP_ENB_RESET_LOG             , MESSAGE_PRIORITY_MED, IttiMsgText                      , s1ap_enb_reset_log)

MESSAGE_DEF(S1AP_UE_CAPABILITIES_IND       ,  MESSAGE_PRIORITY_MED, itti_s1ap_ue_cap_ind_t                ,  s1ap_ue_cap_ind)
MESSAGE_DEF(S1AP_ENB_DEREGISTERED_IND      ,  MESSAGE_PRIORITY_MED, itti_s1ap_eNB_deregistered_ind_t      ,  s1ap_eNB_deregistered_ind)
MESSAGE_DEF(S1AP_DEREGISTER_UE_REQ         ,  MESSAGE_PRIORITY_MED, itti_s1ap_deregister_ue_req_t         ,  s1ap_deregister_ue_req)
MESSAGE_DEF(S1AP_UE_CONTEXT_RELEASE_REQ    ,  MESSAGE_PRIORITY_MED, itti_s1ap_ue_context_release_req_t    ,  s1ap_ue_context_release_req)
MESSAGE_DEF(S1AP_UE_CONTEXT_RELEASE_COMMAND,  MESSAGE_PRIORITY_MED, itti_s1ap_ue_context_release_command_t,  s1ap_ue_context_release_command)
MESSAGE_DEF(S1AP_UE_CONTEXT_RELEASE_COMPLETE, MESSAGE_PRIORITY_MED, itti_s1ap_ue_context_release_complete_t, s1ap_ue_context_release_complete)
MESSAGE_DEF(S1AP_NAS_DL_DATA_REQ           ,  MESSAGE_PRIORITY_MED, itti_s1ap_nas_dl_data_req_t           ,  s1ap_nas_dl_data_req)
MESSAGE_DEF(S1AP_ENB_INITIATED_RESET_REQ   ,  MESSAGE_PRIORITY_MED, itti_s1ap_enb_initiated_reset_req_t   ,  s1ap_enb_initiated_reset_req)
MESSAGE_DEF(S1AP_ENB_INITIATED_RESET_ACK   ,  MESSAGE_PRIORITY_MED, itti_s1ap_enb_initiated_reset_ack_t   ,  s1ap_enb_initiated_reset_ack)

/** Handover Required. */
MESSAGE_DEF(S1AP_HANDOVER_REQUIRED         , MESSAGE_PRIORITY_MED, itti_s1ap_handover_required_t        , s1ap_handover_required)

/** Path Switch Request Failure. */
MESSAGE_DEF(S1AP_PATH_SWITCH_REQUEST_FAILURE, MESSAGE_PRIORITY_MED, itti_s1ap_path_switch_request_failure_t,    s1ap_path_switch_request_failure)

/** Handover Preparation Failure. */
MESSAGE_DEF(S1AP_HANDOVER_PREPARATION_FAILURE, MESSAGE_PRIORITY_MED, itti_s1ap_handover_preparation_failure_t,    s1ap_handover_preparation_failure)
/** Handover Cancel. */
MESSAGE_DEF(S1AP_HANDOVER_CANCEL             , MESSAGE_PRIORITY_MED, itti_s1ap_handover_cancel_t         , s1ap_handover_cancel)
MESSAGE_DEF(S1AP_HANDOVER_CANCEL_ACKNOWLEDGE , MESSAGE_PRIORITY_MED, itti_s1ap_handover_cancel_acknowledge_t         , s1ap_handover_cancel_acknowledge)

/** Handover Request. */
MESSAGE_DEF(S1AP_HANDOVER_REQUEST          , MESSAGE_PRIORITY_MED, itti_s1ap_handover_request_t        , s1ap_handover_request)
/** Handover Command. */
MESSAGE_DEF(S1AP_HANDOVER_COMMAND          , MESSAGE_PRIORITY_MED, itti_s1ap_handover_command_t        , s1ap_handover_command)

/** Handover Request Acknowledge/Failure. */
MESSAGE_DEF(S1AP_HANDOVER_REQUEST_ACKNOWLEDGE  , MESSAGE_PRIORITY_MED, itti_s1ap_handover_request_acknowledge_t,    s1ap_handover_request_acknowledge)
MESSAGE_DEF(S1AP_HANDOVER_FAILURE              , MESSAGE_PRIORITY_MED, itti_s1ap_handover_failure_t    ,    s1ap_handover_failure)

MESSAGE_DEF(S1AP_PATH_SWITCH_REQUEST_ACKNOWLEDGE, MESSAGE_PRIORITY_MED, itti_s1ap_path_switch_request_ack_t  ,    s1ap_path_switch_request_ack)

/** eNB/MME status transfer. */
MESSAGE_DEF(S1AP_ENB_STATUS_TRANSFER       , MESSAGE_PRIORITY_MED, itti_s1ap_status_transfer_t      , s1ap_enb_status_transfer)
MESSAGE_DEF(S1AP_MME_STATUS_TRANSFER       , MESSAGE_PRIORITY_MED, itti_s1ap_status_transfer_t      , s1ap_mme_status_transfer)
/** Handover Notify. */
MESSAGE_DEF(S1AP_HANDOVER_NOTIFY           , MESSAGE_PRIORITY_MED, itti_s1ap_handover_notify_t      ,    s1ap_handover_notify)

/** Paging. */
MESSAGE_DEF(S1AP_PAGING                    , MESSAGE_PRIORITY_MED, itti_s1ap_paging_t               ,    s1ap_paging)
