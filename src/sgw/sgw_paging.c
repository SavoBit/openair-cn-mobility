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

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

#include "intertask_interface.h"
#include "log.h"
#include "sgw_paging.h"
#include "s11_messages_types.h"
#include "dynamic_memory_check.h"
#include "sgw_context_manager.h"


int sgw_send_paging_request(const struct in_addr* dest_ip) {
  char* imsi = NULL;
  int ret = sgw_get_subscriber_id_from_ipv4(dest_ip, &imsi);
  if (ret > 0) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dest_ip->s_addr), ip_str, INET_ADDRSTRLEN);
    OAILOG_ERROR(TASK_SPGW_APP, "Subscriber could not be found for ip %s\n",
                 ip_str);
    return ret;
  }
  OAILOG_DEBUG(TASK_SPGW_APP, "Paging procedure initiated for IMSI%s\n", imsi);
  MessageDef* message_p = itti_alloc_new_message_sized(TASK_SPGW_APP, S11_PAGING_REQUEST , sizeof(itti_s11_paging_request_t));
  S11_PAGING_REQUEST(message_p)->imsi = strdup(imsi);
  free_wrapper((void**)&imsi);

  ret = itti_send_msg_to_task (TASK_MME_APP, INSTANCE_DEFAULT, message_p);
  return ret;
}
