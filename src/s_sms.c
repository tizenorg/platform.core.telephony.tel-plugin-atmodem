/*
 * tel-plugin-atmodem
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <co_sms.h>
#include <co_sim.h>
#include <user_request.h>
#include <storage.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
#include "s_sms.h"

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

#define SMS_ENCODED_SCA_LEN_MAX			12

#define MAX_GSM_SMS_PARAM_RECORD_SIZE       156

#define ATMODEM_SIM_TON_INTERNATIONAL	1
#define ATMODEM_SIM_TON_NATIONAL		2

#define TEL_UTIL_ENCODED_SCA_LEN_MAX		12

#define CONVERT_TO_HEX(in, out)	(in <= 9) ? \
	(out = '0' + in) : (out = 'A' + in - 10)

/*SIM CRSM SW1 and Sw2 definitions */
#define AT_SW1_SUCCESS 0x90
#define AT_SW2_SUCCESS 0

#define SMS_SWAPBYTES16(x) ((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8))

/* Local functions */
static gchar __util_hexchar_to_int(gchar c);
static gboolean __util_hexstring_to_bytes(char *hex_str,
	char **bytes, guint *bytes_len);
static long __util_encode_hex(const guchar *src,
	long num_bytes, char *buf);
static guint __util_encode_pdu(const guchar sca[SMS_SMSP_ADDRESS_LEN],
	const guchar *tpdu, guint tpdu_len, char *pdu);

static gchar __util_hexchar_to_int(gchar c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	else if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	else if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	else {
		err("Invalid charater!!");
		return -1;
	}
}

static gboolean __util_hexstring_to_bytes(char *hex_str, char **bytes, guint *bytes_len)
{
	char *byte_str;
	guint hex_str_len;
	guint i;

	if (hex_str == NULL)
		return FALSE;

	hex_str_len = strlen(hex_str);

	byte_str = g_try_malloc0((hex_str_len / 2) + 1);
	if (byte_str == NULL) {
		err("Memory allocation failed!!");
		return FALSE;
	}

	dbg("Convert String to Binary!!!");
	for (i = 0; i < hex_str_len; i += 2) {
		byte_str[i / 2] = (gchar)((__util_hexchar_to_int(hex_str[i]) << 4)
				| __util_hexchar_to_int(hex_str[i + 1]));
		msg("		[%02x]", byte_str[i / 2]);
	}

	*bytes_len = (hex_str_len / 2);
	*bytes = byte_str;

	return TRUE;
}

static long __util_encode_hex(const guchar *src, long num_bytes, char *buf)
{
	long i, j;

	if (num_bytes <= 0)
	return -1;

	for (i = 0, j = 0; i < num_bytes; i++, j++) {
		CONVERT_TO_HEX(((src[i] >> 4) & 0xf), buf[j++]);
		CONVERT_TO_HEX((src[i] & 0xf), buf[j]);
	}

	buf[j] = '\0';

	return j;
}

static guint __util_encode_pdu(const guchar *sca,
	const guchar *tpdu, guint tpdu_len, char *pdu)
{
	guint sca_len = 0;
	unsigned char converted_sca[SMS_ENCODED_SCA_LEN_MAX];

	if (sca[0] == 0) {
		converted_sca[0] = 0;
		sca_len = 0;
	} else {
		unsigned int i;
		/*
		 * For PDU, the SC Address length is the number of packed BCD bytes
		 * + 1 byte for SC Address type whereas the length given in
		 * 3GPP 23.040 Address encoding is the number of digits without 1 byte
		 * for address type.
		 */
		sca_len = ((sca[0] + 1) / 2) + 1;

		converted_sca[0] = (unsigned char)sca_len;

		for (i = 1; i <= sca_len; i++)
			converted_sca[i] = sca[i];
	}

	memcpy(pdu, converted_sca, sca_len + 1);
	memcpy(pdu + sca_len + 1, tpdu, tpdu_len);

	return sca_len + 1 + tpdu_len;

}

static int util_sms_decode_smsParameters(unsigned char *incoming, unsigned int length, struct telephony_sms_Params *params)
{
	int alpha_id_len = 0;
	int i = 0;
	int nOffset = 0;

	dbg(" RecordLen = %d", length);

	if (incoming == NULL || params == NULL)
		return FALSE;

	alpha_id_len = length - SMS_SMSP_PARAMS_MAX_LEN;

	if (alpha_id_len > 0) {
		if (alpha_id_len > SMS_SMSP_ALPHA_ID_LEN_MAX)
			alpha_id_len = SMS_SMSP_ALPHA_ID_LEN_MAX;

		for (i = 0; i < alpha_id_len; i++) {
			if (0xff == incoming[i]) {
				dbg(" found");
				break;
			}
		}

		memcpy(params->szAlphaId, incoming, i);

		params->alphaIdLen = i;

		dbg(" Alpha id length = %d", i);
	} else {
		params->alphaIdLen = 0;
		dbg(" Alpha id length is zero");
	}

	params->paramIndicator = incoming[alpha_id_len];

	dbg(" Param Indicator = %02x", params->paramIndicator);

	if ((params->paramIndicator & SMSPValidDestAddr) == 0) {
		nOffset = nDestAddrOffset;

		if (0x00 == incoming[alpha_id_len + nOffset] || 0xff == incoming[alpha_id_len + nOffset]) {
			params->tpDestAddr.dialNumLen = 0;

			dbg("DestAddr Length is 0");
		} else {
			if (0 < (int) incoming[alpha_id_len + nOffset]) {
				params->tpDestAddr.dialNumLen = (int) (incoming[alpha_id_len + nOffset] - 1);

				if (params->tpDestAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
					params->tpDestAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;
			} else {
				params->tpDestAddr.dialNumLen = 0;
			}

			params->tpDestAddr.numPlanId = incoming[alpha_id_len + (++nOffset)] & 0x0f;
			params->tpDestAddr.typeOfNum = (incoming[alpha_id_len + nOffset] & 0x70) >> 4;

			memcpy(params->tpDestAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)], (params->tpDestAddr.dialNumLen));

			dbg("Dest TON is %d", params->tpDestAddr.typeOfNum);
			dbg("Dest NPI is %d", params->tpDestAddr.numPlanId);
			dbg("Dest Length = %d", params->tpDestAddr.dialNumLen);
			dbg("Dest Addr = %s", params->tpDestAddr.diallingNum);
		}
	} else {
		params->tpDestAddr.dialNumLen = 0;
	}

	if ((params->paramIndicator & SMSPValidSvcAddr) == 0) {
		nOffset = nSCAAddrOffset;

		if (0x00 == (int) incoming[alpha_id_len + nOffset] || 0xff == (int) incoming[alpha_id_len + nOffset]) {
			params->tpSvcCntrAddr.dialNumLen = 0;
			dbg(" SCAddr Length is 0");
		} else {
			if (0 < (int) incoming[alpha_id_len + nOffset]) {
				params->tpSvcCntrAddr.dialNumLen = (int) (incoming[alpha_id_len + nOffset] - 1);

				if (params->tpSvcCntrAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
					params->tpSvcCntrAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;

				params->tpSvcCntrAddr.numPlanId = incoming[alpha_id_len + (++nOffset)] & 0x0f;
				params->tpSvcCntrAddr.typeOfNum = (incoming[alpha_id_len + nOffset] & 0x70) >> 4;

				memcpy(params->tpSvcCntrAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)], (params->tpSvcCntrAddr.dialNumLen));

				dbg("SCAddr Length = %d ", params->tpSvcCntrAddr.dialNumLen);
				dbg("SCAddr TON is %d", params->tpSvcCntrAddr.typeOfNum);
				dbg("SCAddr NPI is %d", params->tpSvcCntrAddr.numPlanId);

				for (i = 0; i < (int) params->tpSvcCntrAddr.dialNumLen; i++)
					dbg("SCAddr = %d [%02x]", i, params->tpSvcCntrAddr.diallingNum[i]);
			} else {
				params->tpSvcCntrAddr.dialNumLen = 0;
			}
		}
	} else if ((0x00 < (int) incoming[alpha_id_len + nSCAAddrOffset] && (int) incoming[alpha_id_len + nSCAAddrOffset] <= 12)
			   || 0xff != (int) incoming[alpha_id_len + nSCAAddrOffset]) {
		nOffset = nSCAAddrOffset;

		if (0x00 == (int) incoming[alpha_id_len + nOffset] || 0xff == (int) incoming[alpha_id_len + nOffset]) {
			params->tpSvcCntrAddr.dialNumLen = 0;
			dbg("SCAddr Length is 0");
		} else {
			if (0 < (int) incoming[alpha_id_len + nOffset]) {
				params->tpSvcCntrAddr.dialNumLen = (int) (incoming[alpha_id_len + nOffset] - 1);

				params->tpSvcCntrAddr.dialNumLen = incoming[alpha_id_len + nOffset] - 1;

				if (params->tpSvcCntrAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
					params->tpSvcCntrAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;

				params->tpSvcCntrAddr.numPlanId = incoming[alpha_id_len + (++nOffset)] & 0x0f;
				params->tpSvcCntrAddr.typeOfNum = (incoming[alpha_id_len + nOffset] & 0x70) >> 4;

				memcpy(params->tpSvcCntrAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)],
					   (params->tpSvcCntrAddr.dialNumLen));

				dbg("SCAddr Length = %d ", params->tpSvcCntrAddr.dialNumLen);
				dbg("SCAddr TON is %d", params->tpSvcCntrAddr.typeOfNum);
				dbg("SCAddr NPI is %d", params->tpSvcCntrAddr.numPlanId);

				for (i = 0; i < (int) params->tpSvcCntrAddr.dialNumLen; i++)
					dbg("SCAddr = %d [%02x]", i, params->tpSvcCntrAddr.diallingNum[i]);
			} else {
				params->tpSvcCntrAddr.dialNumLen = 0;
			}
		}
	} else {
			params->tpSvcCntrAddr.dialNumLen = 0;
	}

	if ((params->paramIndicator & SMSPValidPID) == 0
			&& (alpha_id_len + nPIDOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
		params->tpProtocolId = incoming[alpha_id_len + nPIDOffset];

	if ((params->paramIndicator & SMSPValidDCS) == 0
			&& (alpha_id_len + nDCSOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
		params->tpDataCodingScheme = incoming[alpha_id_len + nDCSOffset];

	if ((params->paramIndicator & SMSPValidVP) == 0
			&& (alpha_id_len + nVPOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
		params->tpValidityPeriod = incoming[alpha_id_len + nVPOffset];

	dbg(" Alpha Id(Len) = %d", (int) params->alphaIdLen);

	for (i = 0; i < (int) params->alphaIdLen; i++)
		dbg(" Alpha Id = [%d] [%c]", i, params->szAlphaId[i]);

	dbg(" PID = %d", params->tpProtocolId);
	dbg(" DCS = %d", params->tpDataCodingScheme);
	dbg(" VP = %d", params->tpValidityPeriod);

	return TRUE;
}

/*
 * Notification - SMS-DELIVER
 * +CMT = [<alpha>], <length><CR><LF><pdu> (PDU mode enabled)
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
static gboolean on_notification_sms_incoming_msg(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	char *line = NULL;
	int pdu_len = 0, no_of_tokens = 0;
	char *byte_pdu = NULL;
	guint buf_len = 0;

	struct tnoti_sms_incoming_msg incoming_msg;
	int sca_length = 0;

	dbg("Enter");

	memset(&incoming_msg, 0x0, sizeof(struct tnoti_sms_incoming_msg));

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
	__util_hexstring_to_bytes(line, &byte_pdu, &buf_len);

	sca_length = byte_pdu[0];
	dbg("SCA length = %d", sca_length);

	incoming_msg.msgInfo.msgLength = pdu_len;

	if (sca_length == 0) {
		dbg("SCA length = 0");
		memcpy(incoming_msg.msgInfo.tpduData, &byte_pdu[1], incoming_msg.msgInfo.msgLength);
	} else {
		incoming_msg.msgInfo.sca[0] = sca_length;
		memcpy(&(incoming_msg.msgInfo.sca[1]), &byte_pdu[1], sca_length);
		memcpy(incoming_msg.msgInfo.tpduData, &byte_pdu[sca_length+1], incoming_msg.msgInfo.msgLength);
	}

	/* Send notification */
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co)),
		co, TNOTI_SMS_INCOM_MSG,
		sizeof(struct tnoti_sms_incoming_msg), &incoming_msg);

	tcore_at_tok_free(tokens);
	g_free(byte_pdu);

	return TRUE;
}

#if 0	/* To be used later */
static int __util_map_sms_err(int err)
{
	int sms_error = 0;

	switch (err) {
	case 300: /* ME Failure; */
		sms_error = SMS_PHONE_FAILURE;
	break;

	case 302: /* Operation not allowed; */
	case 303: /* Operation not supported; */
		sms_error = SMS_OPERATION_NOT_SUPPORTED;
	break;

	case 304: /* Invalid PDU mode parameter; */
	case 305: /* Invalid text mode parameter; */
		sms_error = SMS_INVALID_PARAMETER_FORMAT;
	break;

	case 320: /* memory failure; */
	case 321: /* invalid memory index; */
	case 322: /* memory full; */
		sms_error = SMS_MEMORY_FAILURE;
	break;

	case 330: /* SCA unknown; */
	case 500: /* Unknown error; */
	default:
		sms_error = SMS_UNKNOWN;
	break;
	}

	return sms_error;
}
#endif

static gboolean on_notification_sms_device_ready(CoreObject *co,
	const void *event_info, void *user_data)
{
	struct tnoti_sms_ready_status sms_ready_info = {0, };

	dbg("SMS notification - [Device Ready]");

	sms_ready_info.status = TRUE;

	/* Set Device Ready */
	tcore_sms_set_ready_status(co, sms_ready_info.status);

	/* Send notification: SMS Device ready */
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co)),
		co, TNOTI_SMS_DEVICE_READY,
		 sizeof(struct tnoti_sms_ready_status), &sms_ready_info);

	return TRUE;
}

static void on_response_sms_send_more_msg(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;

	dbg("Enter");

	if (at_resp && at_resp->success)
		dbg("Response OK for AT+CMMS: More msgs to send!!");
	else
		err("Response NOK for AT+CMMS: More msgs to send");

	/* Need not send any response */
}

static void on_response_sms_send_sms(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	UserRequest *ur = NULL;

	struct tresp_sms_send_msg send_sms_resp;
	dbg("Enter");

	CHECK_AND_RETURN(co != NULL);

	send_sms_resp.result = SMS_DEVICE_FAILURE;
	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			const char *line;
			char *line_token;
			GSList *tokens = NULL;
			gint msg_ref = 0;

			line = (const char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token != NULL) {
				/*
				 * Response from MODEM for send SMS: +CMGS: <mr>[, <ackpdu>]
				 *
				 * Message Reference is not used by MSG_SERVER and application.
				 * So Filling only result
				 */
				msg_ref = atoi(line_token);

				dbg("Message Reference: [%d]", msg_ref);

				send_sms_resp.result = SMS_SENDSMS_SUCCESS;
			} else {
				dbg("No Message Reference received");
			}
			tcore_at_tok_free(tokens);
		}
	} else {
		err("Response NOK");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SMS_SEND_UMTS_MSG,
			sizeof(struct tresp_sms_send_msg), &send_sms_resp);
	} else {
		err("ur is NULL");
	}
}

static void on_response_sms_get_msg_indices(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_storedMsgCnt *count_info = NULL;

	const struct tcore_at_response *at_resp = data;
	GSList *tokens = NULL;

	dbg("Enter");

	count_info = (struct tresp_sms_get_storedMsgCnt *)user_data;
	count_info->result = TCORE_RETURN_FAILURE;

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			char *line = NULL, *line_token = NULL;
			int line_count = 0, count = 0;

			line_count = g_slist_length(at_resp->lines);
			dbg("No. of lines: [%d]", line_count);

			for (count = 0; count < line_count; count++) {
				line = g_slist_nth_data(at_resp->lines, count);

				dbg("gslist_line [%d] is [%s]", count, line);

				if (NULL != line) {
					tokens = tcore_at_tok_new(line);

					line_token = g_slist_nth_data(tokens, 0);
					if (NULL != line_token) {
						count_info->storedMsgCnt.indexList[count] = atoi(line_token);
						count_info->result = TCORE_RETURN_SUCCESS;
					} else {
						dbg("line_token of line [%d] is NULL", count);
					}
					tcore_at_tok_free(tokens);
				} else {
					dbg("line [%d] is NULL", count);
					continue;
				}
			}
		} else {
			err("Invalid Response Received: NO Lines Present");
			if (count_info->storedMsgCnt.usedCount == 0) /* Check if used count is zero */
				count_info->result = TCORE_RETURN_SUCCESS;
		}
	} else {
		err("RESPONSE NOK");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SMS_GET_STORED_MSG_COUNT,
			sizeof(struct tresp_sms_get_storedMsgCnt), count_info);
	} else {
		err("ur is NULL");
	}

	g_free(count_info);
	tcore_at_tok_free(tokens);
}

static void on_response_sms_get_msg_count(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_storedMsgCnt *count_info;
	TReturn ret = TCORE_RETURN_FAILURE;

	const struct tcore_at_response *at_resp = data;
	GSList *tokens = NULL;

	dbg("Enter");

	ur = tcore_pending_ref_user_request(p);

	count_info = g_try_malloc0(sizeof(struct tresp_sms_get_storedMsgCnt));
	if (NULL == count_info) {
		err("Memory Allocation failed for count_info");
		return;
	}
	count_info->result = TCORE_RETURN_FAILURE;

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			char *line = NULL, *line_token = NULL;

			line = (char *)at_resp->lines->data;
			dbg("line: [%s]", line);

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
			count_info->storedMsgCnt.usedCount = atoi(line_token);

			/* <total1> */
			line_token = g_slist_nth_data(tokens, 1);
			if (line_token == NULL) {
				err("Line Token for Total count is NULL");
				goto ERROR;
			}
			count_info->storedMsgCnt.totalCount = atoi(line_token);

			dbg("Count - used: [%d] total: [%d]",
				count_info->storedMsgCnt.usedCount, count_info->storedMsgCnt.totalCount);
			count_info->result = TCORE_RETURN_SUCCESS;

			if (count_info->storedMsgCnt.usedCount > 0) {
				/* Send Request to modem */
				ur = tcore_user_request_ref(ur);
				ret = tcore_prepare_and_send_at_request(tcore_pending_ref_core_object(p),
					"AT+CMGL=4", "+CMGL",
					TCORE_AT_MULTILINE,
					ur,
					on_response_sms_get_msg_indices, (void *)count_info,
					on_send_at_request, NULL,
					0, NULL, NULL);
				dbg("ret: [0x%x]", ret);

				return;

			} else {
				dbg("No records...!!!");
			}
		} else {
			err("Invalid Response Received: NO Lines Present");
		}
	} else {
		err("RESPONSE NOK");
	}

ERROR:
	if (ur) {
		dbg("Sending response...");
		tcore_user_request_send_response(ur,
			TRESP_SMS_GET_STORED_MSG_COUNT,
			sizeof(struct tresp_sms_get_storedMsgCnt), count_info);
	} else {
		err("ur is NULL");
	}

	g_free(count_info);
	tcore_at_tok_free(tokens);
}

#ifdef EMUL_SUPPORTED
static void on_response_sms_get_sca(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_sca get_sca_resp;
	const struct tcore_at_response *at_resp = data;

	dbg("Enter");

	get_sca_resp.result = SMS_UNKNOWN;
	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			GSList *tokens = NULL;
			const char *sca_tok_addr;
			char *line = NULL, *sca_addr = NULL, *sca_toa = NULL;

			line = (char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			sca_tok_addr = g_slist_nth_data(tokens, 0);
			sca_toa = g_slist_nth_data(tokens, 1);

			sca_addr = tcore_at_tok_extract(sca_tok_addr);
			dbg("SCA: [%s] SCA-TOA: [%s]", sca_addr, sca_toa);
			if ((NULL != sca_addr) && (NULL != sca_toa)) {
				char *sca;
				guint sca_len = 0;

				__util_hexstring_to_bytes(sca_addr, &sca, &sca_len); /*TODO : Check*/
				memcpy(get_sca_resp.scaAddress.diallingNum, sca, sca_len);
				get_sca_resp.scaAddress.dialNumLen = strlen(sca);
				g_free(sca);

				if (145 == atoi(sca_toa))
					get_sca_resp.scaAddress.typeOfNum = SIM_TON_INTERNATIONAL;
				else
					get_sca_resp.scaAddress.typeOfNum = SIM_TON_NATIONAL;
				get_sca_resp.scaAddress.numPlanId = 0;

				get_sca_resp.result = SMS_SUCCESS;
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

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SMS_GET_SCA,
			sizeof(struct tresp_sms_get_sca), &get_sca_resp);
	}  else {
		err("ur is NULL");
	}
}
#endif

#ifdef EMUL_SUPPORTED
static void on_response_sms_set_sca(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur;
	struct tresp_sms_set_sca set_sca_resp = {0, };

	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		set_sca_resp.result = SMS_SUCCESS;
	} else {
		err("Response NOK");
		set_sca_resp.result = SMS_UNKNOWN;
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SMS_SET_SCA,
			sizeof(struct tresp_sms_set_sca), &set_sca_resp);
	}  else {
		err("ur is NULL");
	}
}
#endif

static void on_response_atmodem_sms_send_deliver_report(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur;
	struct tresp_sms_set_delivery_report set_deliver_report_rsp = {0, };

	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		set_deliver_report_rsp.result = SMS_SUCCESS;
	} else {
		err("Response NOK");
		set_deliver_report_rsp.result = SMS_UNKNOWN;
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SMS_SET_DELIVERY_REPORT,
			sizeof(struct tresp_sms_set_delivery_report), &set_deliver_report_rsp);
	}  else {
		err("ur is NULL");
	}
}

static void on_response_sms_get_params(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_params resp_get_params ;
	const struct tcore_at_response *at_resp = data;
	int sw1 = 0, sw2 = 0;
	const char *line = NULL;
	char *line_token = NULL;
	GSList *tokens = NULL;
	char *hexData = NULL;
	char *recordData = NULL;
	int i = 0;

	memset(&resp_get_params, 0, sizeof(struct tresp_sms_get_params));
	resp_get_params.result = SMS_DEVICE_FAILURE;

	if (at_resp->success > 0) {
		dbg("RESPONSE OK");

		if (at_resp->lines) {
			line = (const char *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token != NULL) {
				sw1 = atoi(line_token);
				dbg("sw1 is %d", sw1);
			} else {
				dbg("sw1 is NULL");
			}
			line_token = g_slist_nth_data(tokens, 1);
			if (line_token != NULL) {
				sw2 = atoi(line_token);
				dbg("sw2 is %d", sw2);
				if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91)
					resp_get_params.result = SMS_SENDSMS_SUCCESS;
			} else {
				dbg("sw2 is NULL");
			}
			hexData = g_slist_nth_data(tokens, 2);
			if (hexData != NULL) {

				recordData = util_hexStringToBytes(hexData);
				tcore_util_hex_dump("    ", strlen(hexData) / 2, recordData);

				resp_get_params.paramsInfo.recordLen = strlen(hexData) / 2;

				util_sms_decode_smsParameters((unsigned char *) recordData, strlen(hexData) / 2, &(resp_get_params.paramsInfo));
				resp_get_params.result = SMS_SENDSMS_SUCCESS;

				for (i = 0; i < (int) resp_get_params.paramsInfo.tpSvcCntrAddr.dialNumLen; i++)
					dbg("SCAddr = %d [%02x]", i, resp_get_params.paramsInfo.tpSvcCntrAddr.diallingNum[i]);

				free(recordData);
			} else {
				dbg("No response");

			}
			tcore_at_tok_free(tokens);
		}
	} else {
		dbg("RESPONSE NOK");
	}

	ur = tcore_pending_ref_user_request(pending);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SMS_GET_PARAMS,
			sizeof(struct tresp_sms_get_params), &resp_get_params);
	} else {
		err("ur is NULL");
	}
}

static void on_response_sms_set_params(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_set_params resp_set_sms_params = {0, };
	const struct tcore_at_response *at_resp = data;

	resp_set_sms_params.result = SMS_DEVICE_FAILURE;

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			GSList *tokens = NULL;
			int sw1 = 0, sw2 = 0;
			const char *line = NULL;
			char *line_token = NULL;

			line = (const char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);

			line_token = g_slist_nth_data(tokens, 0);
			if (line_token != NULL) {
				sw1 = atoi(line_token);
			} else {
				err("sw1 is NULL");
				goto EXIT;
			}

			line_token = g_slist_nth_data(tokens, 1);
			if (line_token != NULL) {
				sw2 = atoi(line_token);
			} else {
				err("sw2 is NULL");
				goto EXIT;
			}

			dbg("sw1 - %x sw2 - %x", sw1, sw2);
			if (((sw1 == AT_SW1_SUCCESS) && (sw2 == AT_SW2_SUCCESS)) || (sw1 == 0x91))
				resp_set_sms_params.result = SMS_SENDSMS_SUCCESS;
			else
				err("Status Word 1 and Status Word 2 are invalid");

EXIT:
			tcore_at_tok_free(tokens);
		} else {
			err("No lines");
		}
	} else {
		err("RESPONSE NOK");
	}

	ur = tcore_pending_ref_user_request(pending);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SMS_SET_PARAMS ,
			sizeof(struct tresp_sms_set_params), &resp_set_sms_params);
	} else {
		err("ur is NULL");
	}
}

static void on_response_sms_get_param_count(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	struct tresp_sms_get_paramcnt resp_get_param_cnt = {0, };
	const struct tcore_at_response *at_resp = data;
	char *line = NULL , *line_token = NULL;
	int sw1 = 0 , sw2 = 0, *smsp_record_len = NULL;
	int sim_type = 0;
	GSList *tokens = NULL;
	CoreObject *co_sim = NULL;  /* need this to get the sim type GSM/USIM */
	TcorePlugin *plugin = NULL;

	char *hexData = NULL;
	char *recordData = NULL;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(pending);
	resp_get_param_cnt.result = SMS_DEVICE_FAILURE;

	if (at_resp->success > 0) {
		dbg("RESPONSE OK");

		if (at_resp->lines) {
			line = (char *) at_resp->lines->data;

			/*+CRSM: <sw1>, <sw2>[, <response>]*/
			dbg("line is %s", line);

			tokens = tcore_at_tok_new(line);
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token != NULL)
				sw1 = atoi(line_token);
			else
				dbg("sw1 is NULL");

			line_token = g_slist_nth_data(tokens, 1);
			if (line_token != NULL) {
				sw2 = atoi(line_token);
				if ((sw1 == 144) && (sw2 == 0))
					resp_get_param_cnt.result = SMS_SENDSMS_SUCCESS;
			} else {
				dbg("sw2 is NULL");
			}

			hexData = g_slist_nth_data(tokens, 2);
			if (hexData != NULL) {

				/*1. SIM access success case*/
				if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
					unsigned char tag_len = 0; /*	1 or 2 bytes ??? */
					int record_len = 0;
					char num_of_records = 0;
					unsigned char file_id_len = 0;
					unsigned short file_id = 0;
					unsigned short file_size = 0;
					unsigned short file_type = 0;
					unsigned short arr_file_id = 0;
					int arr_file_id_rec_num = 0;


					/*	handling only last 3 bits */
					unsigned char file_type_tag = 0x07;
					unsigned char *ptr_data;

					dbg("hexData: %s", hexData);
					dbg("hexData: %s", hexData + 1);

					recordData = util_hexStringToBytes(hexData);
					if (!recordData) {
						err("util_hexStringToBytes Failed!!");
						tcore_at_tok_free(tokens);
						return;
					}

					tcore_util_hex_dump("   ", strlen(hexData) / 2, recordData);

					ptr_data = (unsigned char *)recordData;

					co_sim = tcore_plugin_ref_core_object(tcore_pending_ref_plugin(pending), CORE_OBJECT_TYPE_SIM);
					sim_type = tcore_sim_get_type(co_sim);
					dbg("sim type is %d", sim_type);

					if (sim_type ==  SIM_TYPE_USIM) {
						/*
						 ETSI TS 102 221 v7.9.0
							- Response Data
							'62'	FCP template tag
							- Response for an EF
							'82'	M	File Descriptor
							'83'	M	File Identifier
							'A5'	O	Proprietary information
							'8A'	M	Life Cycle Status Integer
							'8B', '8C' or 'AB'	C1	Security attributes
							'80'	M	File size
							'81'	O	Total file size
							'88'	O	Short File Identifier (SFI)
						*/

						/* rsim.res_len  has complete data length received  */

						/* FCP template tag - File Control Parameters tag*/
						if (*ptr_data == 0x62) {
							/* parse complete FCP tag*/
							/* increment to next byte */
							ptr_data++;
							tag_len = *ptr_data++;
							dbg("tag_len=[%d]", tag_len);
							/* FCP file descriptor - file type, accessibility, DF, ADF etc*/
							if (*ptr_data == 0x82) {
								/* increment to next byte */
								ptr_data++;

								/*2 or 5 value*/
								ptr_data++;

								/* consider only last 3 bits*/
								file_type_tag = file_type_tag & (*ptr_data);

								switch (file_type_tag) {
									/* increment to next byte */
									ptr_data++;

								case 0x1:
									dbg("Getting FileType: [Transparent file type]");
									/* increment to next byte */
									ptr_data++;
									file_type = SIM_FTYPE_TRANSPARENT;

									/* data coding byte - value 21 */
									ptr_data++;
								break;

								case 0x2:
									dbg("Getting FileType: [Linear fixed file type]");
									/* increment to next byte */
									ptr_data++;

									/* data coding byte - value 21 */
									ptr_data++;

									/* 2bytes */
									memcpy(&record_len, ptr_data, 2);

									/* swap bytes */
									record_len = SMS_SWAPBYTES16(record_len);
									ptr_data = ptr_data + 2;
									num_of_records = *ptr_data++;

									/* Data lossy conversation from enum (int) to unsigned char */
									file_type = SIM_FTYPE_LINEAR_FIXED;
								break;

								case 0x6:
									dbg(" Cyclic fixed file type");
									/* increment to next byte */
									ptr_data++;

									/* data coding byte - value 21 */
									ptr_data++;

									/* 2bytes */
									memcpy(&record_len, ptr_data, 2);

									/* swap bytes  */
									record_len = SMS_SWAPBYTES16(record_len);
									ptr_data = ptr_data + 2;
									num_of_records = *ptr_data++;
									file_type = SIM_FTYPE_CYCLIC;
								break;

								default:
									dbg("not handled file type [0x%x]", *ptr_data);
								break;
								}
							} else {
								dbg("INVALID FCP received - DEbug!");
								free(recordData);
								tcore_at_tok_free(tokens);

								return;
							}

							/*
							 * File identifier - file id??
							 *
							 * 0x84, 0x85, 0x86 etc are currently ignored and not handled
							 */
							if (*ptr_data == 0x83) {
								/* increment to next byte */
								ptr_data++;
								file_id_len = *ptr_data++;
								memcpy(&file_id, ptr_data, file_id_len);

								/* swap bytes */
								file_id = SMS_SWAPBYTES16(file_id);
								ptr_data = ptr_data + 2;
								dbg("Getting FileID=[0x%x]", file_id);
							} else {
								dbg("INVALID FCP received - DEbug!");
								free(recordData);
								tcore_at_tok_free(tokens);

								return;
							}

							/* proprietary information  */
							if (*ptr_data == 0xA5) {
								unsigned short prop_len;

								/* increment to next byte */
								ptr_data++;

								/* length */
								prop_len = *ptr_data;

								/* skip data */
								ptr_data = ptr_data + prop_len + 1;
							} else {
								dbg("INVALID FCP received - DEbug!");
							}

							/* life cycle status integer [8A][length:0x01][status]*/
							/*
							 * status info b8~b1
							 * 00000000 : No information given
							 * 00000001 : creation state
							 * 00000011 : initialization state
							 * 000001-1 : operation state -activated
							 * 000001-0 : operation state -deactivated
							 * 000011-- : Termination state
							 * b8~b5 !=0, b4~b1=X : Proprietary
							 * Any other value : RFU
							 */
							if (*ptr_data == 0x8A) {
								/* increment to next byte */
								ptr_data++;
								/* length - value 1 */
								ptr_data++;

								switch (*ptr_data) {
								case 0x04:
								case 0x06:
									dbg("<IPC_RX> operation state -deactivated");
									ptr_data++;
								break;

								case 0x05:
								case 0x07:
									dbg("<IPC_RX> operation state -activated");
									ptr_data++;
								break;

								default:
									dbg("<IPC_RX> DEBUG! LIFE CYCLE STATUS =[0x%x]", *ptr_data);
									ptr_data++;
								break;
								}
							}

							/* related to security attributes : currently not handled*/
							if (*ptr_data == 0x86 || *ptr_data == 0x8B || *ptr_data == 0x8C || *ptr_data == 0xAB) {
								/* increment to next byte */
								ptr_data++;

								/* if tag length is 3 */
								if (*ptr_data == 0x03) {
									/* increment to next byte */
									ptr_data++;

									/* EFARR file id */
									memcpy(&arr_file_id, ptr_data, 2);

									/* swap byes */
									arr_file_id = SMS_SWAPBYTES16(arr_file_id);
									ptr_data = ptr_data + 2;
									arr_file_id_rec_num = *ptr_data++;
									dbg("arr_file_id_rec_num=[%d]", arr_file_id_rec_num);
								} else {
									/* if tag length is not 3 */
									/* ignoring bytes	*/
									dbg("Useless security attributes, so jump to next tag");
									ptr_data = ptr_data + (*ptr_data + 1);
								}
							} else {
								dbg("INVALID FCP received[0x%x] - DEbug!", *ptr_data);
								free(recordData);
								tcore_at_tok_free(tokens);

								return;
							}

							dbg("Current ptr_data value is [%x]", *ptr_data);

							/* file size excluding structural info*/
							if (*ptr_data == 0x80) {
								/*
								 * for EF file size is body of file and for Linear or cyclic it is
								 * number of recXsizeof(one record)
								 */
								/* increment to next byte */
								ptr_data++;

								/* length is 1 byte - value is 2 bytes or more */
								ptr_data++;
								memcpy(&file_size, ptr_data, 2);

								/* swap bytes */
								file_size = SMS_SWAPBYTES16(file_size);
								ptr_data = ptr_data + 2;
							} else {
								dbg("INVALID FCP received - Debug!");
								free(recordData);
								tcore_at_tok_free(tokens);

								return;
							}

							/* total file size including structural info*/
							if (*ptr_data == 0x81) {
								int len;
								/* increment to next byte */
								ptr_data++;

								/* length */
								len = *ptr_data;
								dbg("len=[%d]", len);

								/* ignored bytes */
								ptr_data = ptr_data + 3;
							} else {
								dbg("INVALID FCP received - Debug!");
								/* 0x81 is optional tag?? check out! so do not return -1 from here! */
								/* return -1; */
							}

							/* short file identifier ignored */
							if (*ptr_data == 0x88) {
								dbg("0x88: Do Nothing");
								/* DO NOTHING */
							}
						} else {
							dbg("INVALID FCP received - Debug!");
							free(recordData);
							tcore_at_tok_free(tokens);

							return;
						}
					} else if (sim_type == SIM_TYPE_GSM) {
						/* ignore RFU byte1 and byte2 */
						ptr_data++;
						ptr_data++;

						/* file size */
						memcpy(&file_size, ptr_data, 2);

						/* swap bytes */
						file_size = SMS_SWAPBYTES16(file_size);

						/* parsed file size */
						ptr_data = ptr_data + 2;

						/* file id */
						memcpy(&file_id, ptr_data, 2);
						file_id = SMS_SWAPBYTES16(file_id);
						dbg(" FILE id --> [%x]", file_id);
						ptr_data = ptr_data + 2;

						/* save file type - transparent, linear fixed or cyclic */
						file_type_tag = (*(ptr_data + 7));

						switch (*ptr_data) {
						case 0x0:
							/* RFU file type */
							dbg(" RFU file type- not handled - Debug!");
						break;

						case 0x1:
							/* MF file type */
							dbg(" MF file type - not handled - Debug!");
						break;

						case 0x2:
							/* DF file type */
							dbg(" DF file type - not handled - Debug!");
						break;

						case 0x4:
							/* EF file type */
							dbg(" EF file type [%d] ", file_type_tag);
							/*	increment to next byte */
							ptr_data++;

							if (file_type_tag == 0x00 || file_type_tag == 0x01) {
								/* increament to next byte as this byte is RFU */
								ptr_data++;
								file_type =
									(file_type_tag == 0x00) ? SIM_FTYPE_TRANSPARENT : SIM_FTYPE_LINEAR_FIXED;
							} else {
								/* increment to next byte */
								ptr_data++;
								/* For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
								/* the INCREASE command is allowed on the selected cyclic file. */
								file_type = SIM_FTYPE_CYCLIC;
							}

							/* bytes 9 to 11 give SIM file access conditions */
							ptr_data++;

							/* byte 10 has one nibble that is RF U and another for INCREASE which is not used currently */
							ptr_data++;

							/* byte 11 is invalidate and rehabilate nibbles */
							ptr_data++;

							/* byte 12 - file status */
							ptr_data++;

							/* byte 13 - GSM specific data */
							ptr_data++;

							/* byte 14 - structure of EF - transparent or linear or cyclic , already saved above */
							ptr_data++;

							/* byte 15 - length of record for linear and cyclic , for transparent it is set to 0x00. */
							record_len = *ptr_data;
							dbg("record length[%d], file size[%d]", record_len, file_size);

							if (record_len != 0)
								num_of_records = (file_size / record_len);

							dbg("Number of records [%d]", num_of_records);
						break;

						default:
							dbg(" not handled file type");
						break;
						}
					} else {
						dbg(" Card Type - UNKNOWN  [%d]", sim_type);
					}

					dbg("EF[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]",
						file_id, file_size, file_type, num_of_records, record_len);

					resp_get_param_cnt.recordCount = num_of_records;
					resp_get_param_cnt.result = SMS_SUCCESS;

					/* TO Store smsp record length in the property */
					plugin = tcore_pending_ref_plugin(pending);
					smsp_record_len = tcore_plugin_ref_property(plugin, "SMSPRECORDLEN");
					memcpy(smsp_record_len, &record_len, sizeof(int));
					dbg("Property Updated");

					free(recordData);
				} else {
					/*2. SIM access fail case*/
					dbg("SIM access fail");
					resp_get_param_cnt.result = SMS_UNKNOWN;
				}
			} else {
				dbg("presp is NULL");
			}
		} else {
			dbg("line is blank");
		}
	} else {
		dbg("RESPONSE NOK");
	}

	if (ur)
		tcore_user_request_send_response(ur,
			TRESP_SMS_GET_PARAMCNT,
			sizeof(struct tresp_sms_get_paramcnt), &resp_get_param_cnt);
	else
		err("ur is NULL");

	if (tokens)
		tcore_at_tok_free(tokens);

}

/* SMS Operations */
/*
 * Operation - send_sms
 *
 * Request -
 * AT-Command: AT+CMGS
 *	For PDU mode (+CMGF=0):
 *	+CMGS=<length><CR>
 *	PDU is given<ctrl-Z/ESC>
 * where,
 * <length> Length of the pdu.
 * <PDU>    PDU to send.
 *
 * Response -
 *+CMGS: <mr>[, <ackpdu>]
 *	OK
 * Failure:
 *	+CMS ERROR: <error>
 */
static TReturn send_umts_msg(CoreObject *co, UserRequest *ur)
{
	const struct treq_sms_send_msg *send_sms_req = NULL;
	char *at_cmd = NULL;
	const unsigned char *tpdu_byte_data, *sca_byte_data;
	guint tpdu_byte_len, pdu_byte_len, pdu_hex_len;
	char buf[HEX_PDU_LEN_MAX];
	char pdu[PDU_LEN_MAX];
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Send SMS");

	send_sms_req = tcore_user_request_ref_data(ur, NULL);
	tpdu_byte_data = send_sms_req->msgDataPackage.tpduData;
	sca_byte_data = send_sms_req->msgDataPackage.sca;

	/* TPDU length is in byte */
	tpdu_byte_len = send_sms_req->msgDataPackage.msgLength;
	dbg("TDPU length: [%d] SCA semi-octet length: [%d]", tpdu_byte_len, sca_byte_data[0]);

	/* Prepare PDU for hex encoding */
	pdu_byte_len = __util_encode_pdu(sca_byte_data,
		tpdu_byte_data, tpdu_byte_len, pdu);

	pdu_hex_len = (int) __util_encode_hex((unsigned char *) pdu,
						pdu_byte_len, buf);
	dbg("PDU hexadecimal length: [%d]", pdu_hex_len);

	/*
	 * More messages
	 * Use same Radio Resource Channel :More Messages to send
	 */
	dbg("Send more SMS: [%s]", (send_sms_req->more == 0 ? "NO" : "YES"));
	if (send_sms_req->more) {
		/* AT Command: More Msgs to Send */
		ret = tcore_prepare_and_send_at_request(co,
			"AT+CMMS=1", "+CMMS:",
			TCORE_AT_SINGLELINE,
			NULL,
			on_response_sms_send_more_msg, NULL,
			on_send_at_request, NULL,
			0, NULL, NULL);
	}

	/* AT-Command : Send SMS */
	at_cmd = g_strdup_printf("AT+CMGS=%d\r%s%x", tpdu_byte_len, buf, 0x1A);

	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, "+CMGS",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_sms_send_sms, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get_sms_count_in_sim
 *
 * Request -
 * AT-Command: AT+CPMS
 *      +CPMS=<mem1>[, <mem2>[, <mem3>]]
 *  where
 * <mem1> memory storage to read.
 *
 * Response -
 * Success: (Single-line output)
 * +CPMS: <mem1>, <used1>, <total1>, <mem2>, <used2>, <total2>,
 * <mem3>, <used3>, <total3>
 * OK
 *
 * Failure:
 *      +CMS ERROR: <error>
 */
static TReturn sms_get_msg_count(CoreObject *co, UserRequest *ur)
{
	TReturn ret;

	dbg("Enter");

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co,
		"AT+CPMS=\"SM\"", "+CPMS",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_sms_get_msg_count, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	return ret;
}

/*
 * Operation - get SCA
 *
 * Request -
 * AT-Command: AT+CSCA?
 *
 * Response -
 *	Success: Single-Line
 *	+CSCA: <sca>, <tosca>
 *	OK
 * where
 * <sca> Service center number
 * <tosca> address type of SCA
 */
#ifdef EMUL_SUPPORTED
static TReturn get_sca(CoreObject *co, UserRequest *ur)
{
	TReturn ret;

	dbg("Enter");

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co,
		"AT+CSCA?", "+CSCA",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_sms_get_sca, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	return ret;
}
#endif

/*
 * Operation - set SCA
 *
 * Request -
 * AT-Command: AT+CSCA
 *	AT+CSCA=<sca>[, <tosca>]
 * where
 * <sca> Service center number
 * <tosca> address type of SCA
 *
 * Response -
 * Success: No result
 *	OK
 *
 * Failure:
 *	+CMS ERROR: <error>
 */
#ifdef EMUL_SUPPORTED
static TReturn set_sca(CoreObject *co, UserRequest *ur)
{
	char *at_cmd;
	const struct treq_sms_set_sca *set_sca_req;
	gint address_type;
	TReturn ret;

	dbg("Enter");

	set_sca_req = tcore_user_request_ref_data(ur, NULL);
	if (set_sca_req->scaInfo.typeOfNum == SIM_TON_INTERNATIONAL)
		address_type = 145;
	else
		address_type = 129;

	/* AT Command */
	at_cmd = g_strdup_printf("AT+CSCA=\"%s\", %d", set_sca_req->scaInfo.diallingNum, address_type);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_sms_set_sca, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}
#endif

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
static TReturn set_delivery_report(CoreObject *co, UserRequest *ur)
{
	const struct treq_sms_set_delivery_report *set_deliver_report_req = NULL;
	char *at_cmd;
	TReturn ret;

	dbg("Enter");

	set_deliver_report_req = tcore_user_request_ref_data(ur, NULL);

	/*AT Command*/
	if (set_deliver_report_req->rspType == SMS_SENDSMS_SUCCESS)
		at_cmd = g_strdup_printf("AT+CNMA=0%s", "\r");
	else
		at_cmd = g_strdup_printf("AT+CNMA=2, 3%s%x%s", "/n", 0x00ff00, "");

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_atmodem_sms_send_deliver_report, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn get_sms_params(CoreObject *co, UserRequest *ur)
{
	TReturn ret;
	char *cmd_str = NULL;
	const struct treq_sms_get_params *get_sms_params_data = NULL;
	int record_len = 0 , *smsp_record_len = NULL;

	dbg("Entry");

	get_sms_params_data = tcore_user_request_ref_data(ur, NULL);

	smsp_record_len = (int *)tcore_plugin_ref_property(tcore_object_ref_plugin(co), "SMSPRECORDLEN");
	if (NULL == smsp_record_len) {
		err("SMSP record is NULL");
		return TCORE_RETURN_FAILURE;
	}

	record_len = *smsp_record_len;
	dbg("record len from property %d", record_len);

	/* AT+CRSM=command>[, <fileid>[, <P1>, <P2>, <P3>[, <data>[, <pathid>]]]] */
	cmd_str = g_strdup_printf("AT+CRSM=178, 28482, %d, 4, %d", (get_sms_params_data->index+1), record_len);

	ret =  tcore_prepare_and_send_at_request(co,
			cmd_str, "+CRSM",
			TCORE_AT_SINGLELINE,
			ur,
			on_response_sms_get_params, NULL,
			on_send_at_request, NULL,
			0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(cmd_str);

	return ret;
}

static TReturn set_sms_params(CoreObject *co, UserRequest *ur)
{
	TReturn ret;
	char *cmd_str = NULL;

	unsigned char *encoded_data;
	char *params_hex_data = NULL;

	int smsp_record_length = 0, *smsp_record_len = NULL;
	const struct treq_sms_set_params *set_sms_params_data = NULL;

	dbg("Entry");

	/* Updating the SMSP record length from the property*/
	set_sms_params_data = (struct treq_sms_set_params *)tcore_user_request_ref_data(ur, NULL);

	smsp_record_len = (int *)tcore_plugin_ref_property(tcore_object_ref_plugin(co), "SMSPRECORDLEN");
	if (NULL == smsp_record_len) {
		err("SMSP record is NULL");
		return TCORE_RETURN_FAILURE;
	}

	smsp_record_length = *smsp_record_len;
	dbg("smsp_record_length [%d]", smsp_record_length);

	encoded_data = g_try_malloc0(smsp_record_length);
	if (NULL == encoded_data) {
		err("Memory Allocation failed for encoded_data");
		return TCORE_RETURN_ENOMEM;
	}

	params_hex_data = g_try_malloc0(smsp_record_length * 2 + 1);
	if (NULL == params_hex_data) {
		err("Memory Allocation Failed for Params hex data");
		g_free(encoded_data);
		return TCORE_RETURN_ENOMEM;
	}
	_tcore_util_sms_encode_smsParameters(&(set_sms_params_data->params),
					encoded_data, smsp_record_length);

	util_byte_to_hex((const char *)encoded_data, (char *)params_hex_data, smsp_record_length);

	cmd_str = g_strdup_printf("AT+CRSM=220, 28482, %d, 4, %d, \"%s\"",
					(set_sms_params_data->params.recordIndex+1), smsp_record_length, params_hex_data);

	ret =  tcore_prepare_and_send_at_request(co,
				cmd_str, "+CRSM:",
				TCORE_AT_SINGLELINE,
				ur,
				on_response_sms_set_params, NULL,
				on_send_at_request, NULL,
				0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(cmd_str);
	g_free(encoded_data);
	g_free(params_hex_data);

	return ret;
}

static TReturn get_param_count(CoreObject *co, UserRequest *ur)
{
	TReturn ret;
	char *cmd_str = NULL;

	dbg("Entry");

	/* AT+CRSM=command>[, <fileid>[, <P1>, <P2>, <P3>[, <data>[, <pathid>]]]] */
	cmd_str = g_strdup_printf("AT+CRSM=192, 28482");

	tcore_util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	ret =  tcore_prepare_and_send_at_request(co,
			cmd_str, "+CRSM",
			TCORE_AT_SINGLELINE,
			ur,
			on_response_sms_get_param_count, NULL,
			on_send_at_request, NULL,
			0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(cmd_str);

	return ret;
}

/* SMS Operations */
static struct tcore_sms_operations sms_ops = {
	.send_umts_msg = send_umts_msg,
	.read_msg = NULL,
	.save_msg = NULL,
	.delete_msg = NULL,
	.get_storedMsgCnt = sms_get_msg_count,
	.get_sca = NULL,
	.set_sca = NULL,
	.get_cb_config = NULL,
	.set_cb_config = NULL,
	.set_mem_status = NULL,
	.get_pref_brearer = NULL,
	.set_pref_brearer = NULL,
	.set_delivery_report = set_delivery_report,
	.set_msg_status = NULL,
	.get_sms_params = get_sms_params,
	.set_sms_params = set_sms_params,
	.get_paramcnt = get_param_count,
	.send_cdma_msg = NULL,
};

gboolean s_sms_init(TcorePlugin *p, TcoreHal *hal)
{
	CoreObject *co;
	int *smsp_record_len = NULL;

	co = tcore_sms_new(p, "umts_sms", &sms_ops, hal);
	if (!co) {
		err("Failed to create SMS core object");
		return FALSE;
	}

	/* Add Callbacks */
	tcore_object_add_callback(co,
		"\e+CMT:",
		on_notification_sms_incoming_msg, NULL);
	tcore_object_add_callback(co,
		"+SCDEV",
		on_notification_sms_device_ready, NULL);

	/* Storing smsp record length */
	smsp_record_len = g_try_malloc0(sizeof(int));
	tcore_plugin_link_property(p, "SMSPRECORDLEN", smsp_record_len);

	dbg("Exit");
	return TRUE;
}


void s_sms_exit(TcorePlugin *p)
{
	CoreObject *co;
	int *smsp_record_len = NULL;

	co = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SMS);
	if (!co) {
		err("SMS core object is NULL");
		return;
	}

	smsp_record_len = tcore_plugin_ref_property(p, "SMSPRECORDLEN");
	g_free(smsp_record_len);

	tcore_sms_free(co);
}

