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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "TrackingAreaUpdateReject.h"

int
decode_tracking_area_update_reject (
  tracking_area_update_reject_msg * tracking_area_update_reject,
  uint8_t * buffer,
  uint32_t len)
{
  uint32_t                                decoded = 0;
  int                                     decoded_result = 0;

  // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
  CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, TRACKING_AREA_UPDATE_REJECT_MINIMUM_LENGTH, len);

  /*
   * Decoding mandatory fields
   */
  if ((decoded_result = decode_emm_cause (&tracking_area_update_reject->emmcause, 0, buffer + decoded, len - decoded)) < 0)
    return decoded_result;
  else
    decoded += decoded_result;


  /*
   * Decoding optional fields
   */
  while (len - decoded > 0) {
    uint8_t                                 ieiDecoded = *(buffer + decoded);

    /*
     * Type | value iei are below 0x80 so just return the first 4 bits
     */
    if (ieiDecoded >= 0x80)
      ieiDecoded = ieiDecoded & 0xf0;

    switch (ieiDecoded) {
    case TRACKING_AREA_UPDATE_REJECT_T3346_VALUE_IEI:
      if ((decoded_result = decode_gprs_timer(&tracking_area_update_reject->t3346value, TRACKING_AREA_UPDATE_REJECT_T3346_VALUE_IEI, buffer + decoded, len - decoded))
          <= 0)
        return decoded_result;

      decoded += decoded_result;
      /*
       * Set corresponding mask to 1 in presencemask
       */
      tracking_area_update_reject->presencemask |= TRACKING_AREA_UPDATE_REJECT_T3346_VALUE_PRESENT;
      break;

    default:
      errorCodeDecoder = TLV_UNEXPECTED_IEI;
      return TLV_UNEXPECTED_IEI;
    }
  }
  return decoded;
}

int
encode_tracking_area_update_reject (
  tracking_area_update_reject_msg * tracking_area_update_reject,
  uint8_t * buffer,
  uint32_t len)
{
  int                                     encoded = 0;
  int                                     encode_result = 0;

  /*
   * Checking IEI and pointer
   */
  CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, TRACKING_AREA_UPDATE_REJECT_MINIMUM_LENGTH, len);

  if ((encode_result = encode_emm_cause (&tracking_area_update_reject->emmcause, 0, buffer + encoded, len - encoded)) < 0)      //Return in case of error
    return encode_result;
  else
    encoded += encode_result;

  if ((tracking_area_update_reject->presencemask & TRACKING_AREA_UPDATE_REJECT_T3346_VALUE_PRESENT)
      == TRACKING_AREA_UPDATE_REJECT_T3346_VALUE_PRESENT) {
    if ((encode_result = encode_gprs_timer (&tracking_area_update_reject->t3346value, TRACKING_AREA_UPDATE_REJECT_T3346_VALUE_IEI, buffer + encoded, len - encoded)) < 0) {
      OAILOG_ERROR (LOG_NAS_EMM, "Failed encode_gprs_timer\n");
      // Return in case of error
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, encode_result);
    } else
      encoded += encode_result;
  }


  return encoded;
}
