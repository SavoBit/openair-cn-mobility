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

MESSAGE_DEF(MME_APP_INITIAL_UE_MESSAGE                   , MESSAGE_PRIORITY_MED, itti_mme_app_initial_ue_message_t  , mme_app_initial_ue_message)
MESSAGE_DEF(MME_APP_INITIAL_UE_MESSAGE_CHECK_DUPLICATE   , MESSAGE_PRIORITY_MED, itti_mme_app_initial_ue_message_check_duplicate_t  , mme_app_initial_ue_message_check_duplicate)

MESSAGE_DEF(MME_APP_CONNECTION_ESTABLISHMENT_CNF  , MESSAGE_PRIORITY_MED, itti_mme_app_connection_establishment_cnf_t  , mme_app_connection_establishment_cnf)

// handover messages from NAS to MME_APP after NAS validation (will be forwarded to S1AP)
MESSAGE_DEF(MME_APP_HANDOVER_CNF  , MESSAGE_PRIORITY_MED, itti_mme_app_handover_cnf_t  , mme_app_handover_cnf)
MESSAGE_DEF(MME_APP_HANDOVER_REJ  , MESSAGE_PRIORITY_MED, itti_mme_app_handover_rej_t  , mme_app_handover_rej)

// DUPLICATE CONFIRMATION (todo: if signal saving, we might not need this)
MESSAGE_DEF(MME_APP_S1AP_INITIAL_UE_MESSAGE_DUPLICATE_CNF  , MESSAGE_PRIORITY_MED, itti_mme_app_s1ap_initial_ue_message_duplicate_cnf_t  , mme_app_s1ap_initial_ue_message_duplicate_cnf)

MESSAGE_DEF(MME_APP_INITIAL_CONTEXT_SETUP_RSP     , MESSAGE_PRIORITY_MED, itti_mme_app_initial_context_setup_rsp_t  ,    mme_app_initial_context_setup_rsp)
MESSAGE_DEF(MME_APP_PATH_SWITCH_REQ               , MESSAGE_PRIORITY_MED, itti_mme_app_path_switch_req_t  ,    mme_app_path_switch_req)
MESSAGE_DEF(MME_APP_INITIAL_CONTEXT_SETUP_FAILURE , MESSAGE_PRIORITY_MED, itti_mme_app_initial_context_setup_failure_t  ,    mme_app_initial_context_setup_failure)
MESSAGE_DEF(MME_APP_DELETE_SESSION_RSP     	      , MESSAGE_PRIORITY_MED, itti_mme_app_delete_session_rsp_t  ,    	     mme_app_delete_session_rsp)
MESSAGE_DEF(MME_APP_S1AP_MME_UE_ID_NOTIFICATION	  , MESSAGE_PRIORITY_MED, itti_mme_app_s1ap_mme_ue_id_notification_t  ,  mme_app_s1ap_mme_ue_id_notification)

