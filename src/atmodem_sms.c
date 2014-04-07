/*
 * tel-plugin-atmodem
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <core_object.h>
#include <hal.h>
#include <queue.h>
#include <storage.h>
#include <at.h>

#include <co_sms.h>

#include "atmodem_sms.h"
#include "atmodem_common.h"

#define CR  '\r'
#define CTRL_Z   '\x1A'

#define AT_MT_UNREAD		0	/* Received and Unread */
#define AT_MT_READ		1	/* Received and Read */
#define AT_MO_UNSENT		2	/* Unsent */
#define AT_MO_SENT		3	/* Sent */
#define AT_ALL			4	/* Unknown */

#define ATMODEM_NUM_PLAN_ID(sca)    (gchar)(sca & 0x0F)
#define ATMODEM_TYPE_OF_NUM(sca)    (gchar)((sca & 0x70) >> 4)

/* SCA 12 bytes long and TDPU is 164 bytes long */
#define PDU_LEN_MAX		176
#define HEX_PDU_LEN_MAX	((PDU_LEN_MAX * 2) + 1)

#define ATMODEM_SIM_TON_INTERNATIONAL	1
#define ATMODEM_SIM_TON_NATIONAL	2

/*
 * Notification - SMS-DELIVER
 * +CMT = [<alpha>],<length><CR><LF><pdu> (PDU mode enabled)
 *
 * where,
 * <alpha> alpha_id
 * <length> length of the PDU
 * <pdu> Incomming SMS PDU
 *
 * Notification - SMS-STATUS-REPORT
 * +CDS: <length><CR><LF><pdu> (PDU mode enabled)
 *
 * where,
 * <length> length of the PDU
 * <pdu> Incomming SMS PDU
 *
 */
static gboolean on_notification_atmodem_sms_incoming_msg(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	char *line = NULL;
	int pdu_len = 0, no_of_tokens = 0;
	gchar *byte_pdu = NULL;
	guint buf_len = 0;

	TelSmsDatapackageInfo incoming_msg = {{0}, };
	int sca_length = 0;
	dbg("Enter");

	lines = (GSList *)event_info;
	if (2 != g_slist_length(lines)) {
		err("Invalid number of lines for +CMT. Must be 2");
		return TRUE;
	}
	line = (char *)g_slist_nth_data(lines, 0); /* Fetch Line 1 */
	if (!line) {
		err("Line 1 is invalid");
		return TRUE;
	}
	dbg("Line 1: [%s]", line);
	tokens = tcore_at_tok_new(line); /* Split Line 1 into tokens */
	no_of_tokens = g_slist_length(tokens);

	/*
	 * Incoming SMS: +CMT
	 *	Number of tokens: 2
	 *
	 * Incoming SMS-STATUS-REPORT: +CDS
	 *	Number of tokens: 1
	 */
	if (2 == no_of_tokens) {
		/* Token 0: Alpha ID */
		dbg("Alpha ID: [0x%x]", g_slist_nth_data(tokens, 0));

		/* Token 1: PDU Length */
		pdu_len = atoi((char *)g_slist_nth_data(tokens, 1));
		dbg("pdu_len: [%d]", pdu_len);
	} else if (1 == no_of_tokens) {
		/* 0: PDU Length */
		pdu_len = atoi((char *)g_slist_nth_data(tokens, 0));
		dbg("pdu_len: [%d]", pdu_len);
	}

	/* Fetch Line 2 */
	line = (char *)g_slist_nth_data(lines, 1);
	if (!line) {
		err("Line 2 is invalid");
		tcore_at_tok_free(tokens);
		return TRUE;
	}
	dbg("Line 2: [%s]", line);

	/* Convert to Bytes */
	tcore_util_hexstring_to_bytes(line, &byte_pdu, &buf_len);

	sca_length = byte_pdu[0];
	dbg("SCA length = %d", sca_length);

	if (sca_length) {
		gchar *decoded_sca;
		guint encoded_sca_len;
		/*
		 * byte_pdu[1] - sca_address_type
		 *	Excluding sca_address_type and copy SCA
		 */
		encoded_sca_len = sca_length - 1;
		decoded_sca =
			tcore_util_convert_bcd_to_ascii(&byte_pdu[2], encoded_sca_len, encoded_sca_len*2);
		dbg("Decoded SCA: [%s]", decoded_sca);
		g_strlcpy(incoming_msg.sca.number, decoded_sca, strlen(decoded_sca)+1);
		tcore_free(decoded_sca);

		/*SCA Conversion for Address type*/
		incoming_msg.sca.ton = ATMODEM_TYPE_OF_NUM(byte_pdu[1]);
		incoming_msg.sca.npi = ATMODEM_NUM_PLAN_ID(byte_pdu[1]);
		dbg("TON: [%d] NPI: [%d] SCA: [%s]",
			incoming_msg.sca.ton, incoming_msg.sca.npi,
			incoming_msg.sca.number);
	}
	else {
		dbg("NO SCA Present");
	}


	/* TPDU */
	incoming_msg.tpdu_length = pdu_len;
	memcpy(incoming_msg.tpdu,
		&byte_pdu[sca_length+1], incoming_msg.tpdu_length);

	/* Send notification */
	tcore_object_send_notification(co,
		TCORE_NOTIFICATION_SMS_INCOM_MSG,
		sizeof(TelSmsDatapackageInfo), &incoming_msg);

	tcore_at_tok_free(tokens);
	g_free(byte_pdu);

	return TRUE;
}

static gboolean on_notification_atmodem_sms_device_ready(CoreObject *co,
	const void *event_info, void *user_data)
{
	gboolean sms_status = TRUE;

	dbg("SMS notification - [Device Ready]");

	/* Set Device Ready */
	tcore_sms_set_ready_status(co, sms_status);

	/* Send notification: SMS Device ready */
	tcore_object_send_notification(co,
		TCORE_NOTIFICATION_SMS_DEVICE_READY,
		sizeof(sms_status), &sms_status);

	return TRUE;
}

static void on_response_atmodem_sms_send_more_msg(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;

	dbg("Enter");

	if (at_resp && at_resp->success)
		dbg("Response OK for AT+CMMS: More msgs to send!!");
	else
		err("Response NOK for AT+CMMS: More msgs to send");

	/* Need not send any response */
}

static void on_response_atmodem_sms_send_sms(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;/*TODO: CMS error mapping required */
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			const gchar *line;
			gchar* line_token;
			GSList *tokens = NULL;
			gint msg_ref = 0;

			line = (const gchar *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token != NULL) {
				/*Response from MODEM for send SMS: +CMGS: <mr>[,<ackpdu>]*/
				/*Message Reference is not used by MSG_SERVER and application.So Filling only result*/
				msg_ref = atoi(line_token);

				dbg("Message Reference: [%d]", msg_ref);

				result = TEL_SMS_RESULT_SUCCESS;
			} else {
				dbg("No Message Reference received");
			}
			tcore_at_tok_free(tokens);
		}
	} else {
		err("Response NOK");
	}
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_sms_get_count(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	TelSmsStoredMsgCountInfo count_info = {0, };

	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	GSList *tokens = NULL;
	TelSmsResult result = TEL_SMS_RESULT_FAILURE;

	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			char *line = NULL, *line_token = NULL;

			line = (char *)at_resp->lines->data;
			dbg("line: [%s]",line);

			/*
			 * Tokenize
			 *
			 * +CPMS: <used1>, <total1>, <used2>, <total2>, <used3>, <total3>
			 */
			tokens = tcore_at_tok_new(line);

			/* <used1> */
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token == NULL) {
				err("Line Token for used count is NULL");
				goto ERROR;
			}
			count_info.used_count = atoi(line_token);

			/* <total1> */
			line_token = g_slist_nth_data(tokens, 1);
			if (line_token == NULL) {
				err("Line Token for Total count is NULL");
				goto ERROR;
			}
			count_info.total_count = atoi(line_token);

			dbg("Count - used: [%d] total: [%d]",
				count_info.used_count, count_info.total_count);
			result = TEL_SMS_RESULT_SUCCESS;
		}
		else {
			err("Invalid Response Received: NO Lines Present");
		}
	}
	else {
		err("RESPONSE NOK");
	}

ERROR:
	/* Invoke callback in case of error*/
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &count_info, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);

	tcore_at_tok_free(tokens);
}

static void on_response_atmodem_sms_send_deliver_report(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;  // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success)
		result = TEL_SMS_RESULT_SUCCESS;

	dbg("Send Deliver Report: [%s]",
			(result == TEL_SMS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_sms_set_sca(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		result = TEL_SMS_RESULT_SUCCESS;
	} else {
		err("Response NOK");
	}
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_sms_get_sca(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelSmsSca sca_resp = { 0, };
	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			GSList *tokens = NULL;
			const char *sca_tok_addr;
			gchar *line = NULL, *sca_addr = NULL, *sca_toa = NULL;

			line = (char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			sca_tok_addr = g_slist_nth_data(tokens, 0);
			sca_toa = g_slist_nth_data(tokens, 1);

			sca_addr = tcore_at_tok_extract(sca_tok_addr);
			dbg("SCA: [%s] SCA-TOA: [%s]", sca_addr, sca_toa);
			if ((NULL != sca_addr) && (NULL != sca_toa)) {
				gchar *sca;
				guint sca_len = 0;
				tcore_util_hexstring_to_bytes(sca_addr, &sca, &sca_len); /*TODO : Check*/
				memcpy(sca_resp.number, sca, sca_len);
				g_free(sca);

				/* Type-of-Address */
				if (145 == atoi(sca_toa)) {
					sca_resp.ton = ATMODEM_SIM_TON_INTERNATIONAL;
				} else {
					sca_resp.ton = ATMODEM_SIM_TON_NATIONAL;
				}
				sca_resp.npi = 0;/* TODO */
				result = TEL_SMS_RESULT_SUCCESS;
			} else {
				err("SCA is NULL");
			}
			tcore_at_tok_free(tokens);
			g_free(sca_addr);
		} else {
			err("Invalid Response.No Lines Received");
		}
	} else {
		err("Response NOK");
	}
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &sca_resp, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

/* SMS Operations */
/*
 * Operation - send_sms
 *
 * Request -
 * AT-Command: AT+CMGS
 * 	For PDU mode (+CMGF=0):
 * 	+CMGS=<length><CR>
 * 	PDU is given<ctrl-Z/ESC>
 * where,
 * <length> Length of the pdu.
 * <PDU>    PDU to send.
 *
 * Response -
 *+CMGS: <mr>[,<ackpdu>]
 *	OK
 * Failure:
 *	+CMS ERROR: <error>
 */
static TelReturn atmodem_sms_send_sms(CoreObject *co,
	const TelSmsSendInfo *send_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;

	const unsigned char *tpdu_byte_data;
	gint tpdu_byte_len, pdu_byte_len;
	char buf[HEX_PDU_LEN_MAX];
	char pdu[PDU_LEN_MAX];
	dbg("Enter");

	tpdu_byte_data = send_info->send_data.tpdu;

	/* TPDU length is in byte */
	tpdu_byte_len = send_info->send_data.tpdu_length;

	/* Prepare PDU for hex encoding */
	pdu_byte_len = tcore_util_encode_pdu(&(send_info->send_data.sca),
		tpdu_byte_data, tpdu_byte_len, pdu);

	tcore_util_encode_hex((unsigned char *) pdu, pdu_byte_len, buf);

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/*
	 * More messages
	 * Use same Radio Resource Channel :More Messages to send
	 */
	if (send_info->more_msgs > 0) {
		/* AT Command: More Msgs to Send */
		ret = tcore_at_prepare_and_send_request(co,
			"AT+CMMS=1", "+CMMS:",
			TCORE_AT_COMMAND_TYPE_SINGLELINE,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_sms_send_more_msg, NULL,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
		ATMODEM_CHECK_REQUEST_RET(ret, NULL, "More Msgs to Send");
	}
	/* AT-Command : Send SMS */
	at_cmd = g_strdup_printf("AT+CMGS=%d\r%s\x1A", tpdu_byte_len, buf);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CMGS:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_atmodem_sms_send_sms, resp_cb_data,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Send SMS");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get_sms_count_in_sim
 *
 * Request -
 * AT-Command: AT+CPMS
 *      +CPMS=<mem1>[, <mem2>[,<mem3>]]
 *  where
 * <mem1> memory storage to read.
 *
 * Response -
 * Success: (Single-line output)
 * +CPMS: <mem1>,<used1>,<total1>,<mem2>,<used2>,<total2>,
 * <mem3>,<used3>,<total3>
 * OK
 *
 * Failure:
 *      +CMS ERROR: <error>
 */
static TelReturn atmodem_sms_get_count(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("Enter");

	/*AT Command*/
	at_cmd = g_strdup_printf("AT+CPMS=\"SM\"");

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CPMS",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_atmodem_sms_get_count, resp_cb_data,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get SMS Count");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - send_deliver_report
 *
 * Request -
 *	Modem Takes care of sending the ACK to the network
 *
 * Response -
 * Success: Default response always SUCCESS posted
 *
 */
static TelReturn atmodem_sms_send_deliver_report(CoreObject *co,
	const TelSmsDeliverReportInfo *dr_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("Enter");

	/*AT Command*/
	if(dr_info->report== TEL_SMS_DELIVERY_REPORT_SUCCESS)
		at_cmd = g_strdup_printf("AT+CNMA=0%s", "\r");
	else
		at_cmd = g_strdup_printf("AT+CNMA=2,3%s%x%s", "/n", 0x00ff00, "");


	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_atmodem_sms_send_deliver_report, resp_cb_data,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Send deliver Report");

	/* Free resources */
	g_free(at_cmd);
	return ret;
}

/*
 * Operation - set SCA
 *
 * Request -
 * AT-Command: AT+CSCA
 * 	AT+CSCA=<sca>[,<tosca>]
 * where
 * <sca> Service center number
 * <tosca> address type of SCA
 *
 * Response -
 * Success: No result
 * 	OK
 *
 * Failure:
 *      +CMS ERROR: <error>
 */
 static TelReturn atmodem_sms_set_sca(CoreObject *co,
	const TelSmsSca *sca,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;
	gint address_type;

	address_type = ((sca->ton << 4) | sca->npi ) | 0x80;

	/* AT Command */
	at_cmd = g_strdup_printf("AT+CSCA=\"%s\",%d", sca->number, address_type);

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_atmodem_sms_set_sca, resp_cb_data,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Set SCA");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get SCA
 *
 * Request -
 * AT-Command: AT+CSCA?
 *
 * Response -
 * 	Success: Single-Line
 * 	+CSCA: <sca>,<tosca>
 * 	OK
 * where
 * <sca> Service center number
 * <tosca> address type of SCA
 *
 */
 static TelReturn atmodem_sms_get_sca(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("Enter");

	/* AT Command */
	at_cmd = g_strdup_printf("AT+CSCA?");

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, "+CSCA",
			TCORE_AT_COMMAND_TYPE_SINGLELINE,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_sms_get_sca, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get SCA");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/* SMS Operations */
static TcoreSmsOps atmodem_sms_ops = {
	.send_sms = atmodem_sms_send_sms,
	.read_in_sim = NULL,
	.write_in_sim = NULL,
	.delete_in_sim = NULL,
	.get_count = atmodem_sms_get_count,
	.set_cb_config = NULL,
	.get_cb_config = NULL,
	.get_parameters = NULL, /* TODO - After implemented in imc code */
	.set_parameters = NULL, /* TODO - After implemented in imc code */
	.send_deliver_report = atmodem_sms_send_deliver_report,
	.set_sca = atmodem_sms_set_sca,
	.get_sca = atmodem_sms_get_sca,
	.set_memory_status = NULL,
	.set_message_status = NULL
};

gboolean atmodem_sms_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Entry");

	/* Set operations */
	tcore_sms_set_ops(co, &atmodem_sms_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co,
		"\e+CMT:",
		on_notification_atmodem_sms_incoming_msg, NULL);
	tcore_object_add_callback(co,
		"\%SCDEV",
		on_notification_atmodem_sms_device_ready, NULL);

	dbg("Exit");
	return TRUE;
}

void atmodem_sms_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}
