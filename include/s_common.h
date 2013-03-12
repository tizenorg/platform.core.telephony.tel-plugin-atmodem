/*
 * tel-plugin-atmodem
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Hayoon Ko <hayoon.ko@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __S_COMMON_H__
#define __S_COMMON_H__

#include <tcore.h>
#include <glib.h>
#include <user_request.h>

#define EVENT_SYS_NOTI_MODEM_POWER          "system_power"
#define EVENT_MODEM_POWER          "modem_power"
#define EVENT_MODEM_PHONE_STATE    "modem_phone_state"

#define EVENT_CALL_STATUS			"call_status"
#define EVENT_CALL_INCOMING		"call_incoming"
#define EVENT_CALL_WAITING			"call_waiting"

#define EVENT_SS_INFO				"ss_info"
#define EVENT_SS_USSD				"ss_ussd"

#define EVENT_PS_CALL_STATUS       "ps_call_status"
#define EVENT_PS_DATA_COUNTER      "ps_data_counter"
#define EVENT_PS_IPCONFIGURATION   "ps_ipconfiguration"
#define EVENT_PS_PIN_CTRL          "ps_pin_control"
#define EVENT_PS_HSDPA_STATUS      "ps_hsdpa_status"
#define EVENT_PS_ATTACH_DETACH     "ps_attach_detach"
#define EVENT_PS_EXTERNAL_CALL     "ps_external_call"

#define EVENT_SAP_STATUS           "sap_status"
#define EVENT_SAP_DISCONNECT       "sap_disconnect"

#define EVENT_SIM_PIN_STATUS       "sim_pin_status"

#define EVENT_SAT_ENVELOPE_RESP       "sat_envelope_response"
#define EVENT_SAT_REFRESH_STATUS       "sat_refresh_status"
#define EVENT_SAT_PROACTIVE_COMMAND       "sat_proactive_command"
#define EVENT_SAT_CONTROL_RESULT       "sat_control_result"


#define EVENT_CALL_STATUS          "call_status"
#define EVENT_CALL_INCOMING        "call_incoming"

#define EVENT_NETWORK_REGISTRATION "network_regist"
#define EVENT_NETWORK_ICON_INFO    "network_icon_info"
#define EVENT_NETWORK_TIME_INFO    "network_time_info"
#define EVENT_NETWORK_IDENTITY     "network_identity"

#define EVENT_SMS_INCOM_MSG        "sms_incom_msg"
#define EVENT_SMS_SEND_ACK         "sms_send_ack"
#define EVENT_SMS_MEMORY_STATUS    "sms_memory_status"
#define EVENT_SMS_CB_INCOM_MSG     "sms_cb_incom_msg"
#define EVENT_SMS_DELETE_MSG_CNF   "sms_delete_msg_cnf"
#define EVENT_SMS_WRITE_MSG_CNF    "sms_write_msg_cnf"
#define EVENT_SMS_DELIVERY_RPT_CNF "sms_deliver_rpt_cnf"
#define EVENT_SMS_DEVICE_READY     "sms_device_ready"

#define EVENT_PHONEBOOK_STATUS       "phonebook_status"
#define EVENT_PHONEBOOK_FIRST_INDEX        "phonebook_first_index"

enum direction_e {
	RX,
	TX
};

struct global_data {
	unsigned int msg_auto_id_current;
	unsigned int msg_auto_id_start;
	unsigned int msg_auto_id_end;
};

struct work_queue_data {
	unsigned int id;
	UserRequest *ur;
};

#define UTIL_ID(hdr)		((hdr).main_cmd << 8 | (hdr).sub_cmd)
#define UTIL_IDP(hdr)		((hdr)->main_cmd << 8 | (hdr)->sub_cmd)

void			hook_hex_dump(enum direction_e d, int size, const void *data);
unsigned int	util_assign_message_sequence_id(TcorePlugin *p);
gboolean		util_add_waiting_job(GQueue *queue, unsigned int id, UserRequest *ur);
UserRequest*	util_pop_waiting_job(GQueue *queue, unsigned int id);
void			util_hex_dump(char *pad, int size, const void *data);
unsigned char	util_hexCharToInt(char c);
char*		util_hexStringToBytes(char * s);

#endif
