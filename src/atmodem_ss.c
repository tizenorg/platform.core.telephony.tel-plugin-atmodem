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

#include <co_ss.h>

#include "atmodem_ss.h"
#include "atmodem_common.h"

/* AT+CUSD = [<n> [, <str> [, <dcs>]]]
 * where,
 * <n>
 * 0 Disable
 * 1 Enable
 * 2 Cancel the session
 *
 * <str>
 * Ussd string
 *
 * <dcs>
 * Decoding format
 */
static gboolean on_notification_atmodem_ss_ussd(CoreObject *co,
	const void *event_data, void *user_data)
{
	gchar *cmd;
	gchar *resp_str = NULL;
	guchar *dcs_str = NULL;
	TelUtilAlphabetFormat dcs = TEL_UTIL_ALPHABET_FORMAT_SMS_DEFAULT;
	gushort len;
	GSList *tokens = NULL;
	GSList *lines = NULL;
	gint ussd_status = 0;
	TelSsUssdNoti ussd_noti = {0,};

	lines = (GSList *) event_data;
	if (g_slist_length(lines) != 1) {
		dbg("Unsolicited message but multiple lines");
		return TRUE;
	}

	cmd = (gchar *)lines->data;
	tokens = tcore_at_tok_new(cmd);

	/* Parse USSD status */
	resp_str = g_slist_nth_data(tokens, 0);
	if (NULL == resp_str) {
		err("Status is missing from +CUSD Notification");
		goto out;
	} else {
		ussd_status = atoi(resp_str);
		dbg("USSD status[%d]", ussd_status);

		if (ussd_status < TEL_SS_USSD_STATUS_NO_ACTION_REQUIRED ||
				ussd_status > TEL_SS_USSD_STATUS_TIME_OUT) {
			err("Invalid USSD status");
			goto out;
		}

		/*
		 * When network terminated the USSD session,
		 * no need to send notification to application
		 */
		if (ussd_status == TEL_SS_USSD_STATUS_TERMINATED_BY_NETWORK) {
			/* Destroy USSD session, if any exists */
			UssdSession *ussd_session = tcore_ss_ussd_get_session(co);
			if (ussd_session)
				tcore_ss_ussd_destroy_session(ussd_session);

			goto out;
		}

		/* Parse USSD string */
		resp_str = g_slist_nth_data(tokens, 1);

		resp_str = tcore_at_tok_extract(resp_str);
		if (resp_str) {
			len = strlen((gchar *)resp_str);
			dbg("USSD String: [%s] Length: [%d]", resp_str, len);
		} else {
			dbg("USSD strings is missing from +CUSD Notification");
			goto out;
		}

		dcs_str = g_slist_nth_data(tokens, 2);
	}

	if (dcs_str) {
		dcs = tcore_util_get_cbs_coding_scheme(atoi((gchar *)dcs_str));
	} else {
		warn("No DCS string! Using default DCS value");
	}

	ussd_noti.str = tcore_malloc0(len+1);
	tcore_util_convert_str_to_utf8(ussd_noti.str,
		&len, dcs, (const guchar *)resp_str, len+1);
	ussd_noti.status = ussd_status;

	/* Send notification */
	tcore_object_send_notification(co,
		TCORE_NOTIFICATION_SS_USSD,
		sizeof(TelSsUssdNoti), (void *)&ussd_noti);

	tcore_free(resp_str);
	tcore_free(ussd_noti.str);

out:
	tcore_at_tok_free(tokens);
	return TRUE;
}

static gboolean __atmodem_ss_convert_modem_class_to_class(gint classx,
	TelSsClass *class)
{
	switch (classx) {
	case 7:
		*class = TEL_SS_CLASS_ALL_TELE;
	break;

	case 1:
		*class = TEL_SS_CLASS_VOICE;
	break;

	case 2:
		*class = TEL_SS_CLASS_ALL_DATA_TELE;
	break;

	case 4:
		*class = TEL_SS_CLASS_FAX;
	break;

	case 8:
		*class = TEL_SS_CLASS_SMS;
	break;

	case 16:
		*class = TEL_SS_CLASS_ALL_CS_SYNC;
	break;

	case 32:
		*class = TEL_SS_CLASS_ALL_CS_ASYNC;
	break;

	case 64:
		*class = TEL_SS_CLASS_ALL_DEDI_PS;
	break;

	case 128:
		*class = TEL_SS_CLASS_ALL_DEDI_PAD;
	break;

	default:
		err("Invalid modem class: [%d]", classx);
		return FALSE;
	}

	return TRUE;
}

static guint __atmodem_ss_convert_class_to_atmodem_class(TelSsClass class)
{
	switch (class) {
	case TEL_SS_CLASS_ALL_TELE:
		return 7;

	case TEL_SS_CLASS_VOICE:
		return 1;

	case TEL_SS_CLASS_ALL_DATA_TELE:
		return 2;

	case TEL_SS_CLASS_FAX:
		return 4;

	case TEL_SS_CLASS_SMS:
		return 8;

	case TEL_SS_CLASS_ALL_CS_SYNC:
		return 16;

	case TEL_SS_CLASS_ALL_CS_ASYNC:
		return 32;

	case TEL_SS_CLASS_ALL_DEDI_PS:
		return 64;

	case TEL_SS_CLASS_ALL_DEDI_PAD:
		return 128;

	default:
		dbg("Unsupported class: [%d], returning default value 7", class);
		return 7;
	}
}

static gboolean __atmodem_ss_convert_barring_type_to_facility(TelSsBarringType type,
	gchar **facility)
{
	switch (type) {
	case TEL_SS_CB_TYPE_BAOC:
		*facility = "AO";
	break;

	case TEL_SS_CB_TYPE_BOIC:
		*facility = "OI";
	break;

	case TEL_SS_CB_TYPE_BOIC_NOT_HC:
		*facility = "OX";
	break;

	case TEL_SS_CB_TYPE_BAIC:
		*facility = "AI";
	break;

	case TEL_SS_CB_TYPE_BIC_ROAM:
		*facility = "IR";
	break;

	case TEL_SS_CB_TYPE_AB:
		*facility = "AB";
	break;

	case TEL_SS_CB_TYPE_AOB:
		*facility = "AG";
	break;

	case TEL_SS_CB_TYPE_AIB:
		*facility = "AC";
	break;

	case TEL_SS_CB_TYPE_NS:
		*facility = "NS";
	break;

	default:
		err("Unspported type: [%d]", type);
		return FALSE;
	}
	return TRUE;
}

static gboolean __atmodem_ss_convert_forwarding_mode_to_modem_mode(TelSsForwardMode mode,
	guint *modex)
{
	switch (mode) {
	case TEL_SS_CF_MODE_DISABLE:
		*modex = 0;
	break;

	case TEL_SS_CF_MODE_ENABLE:
		*modex = 1;
	break;

	case TEL_SS_CF_MODE_REGISTER:
		*modex = 3;
	break;

	case TEL_SS_CF_MODE_DEREGISTER:
		*modex = 4;
	break;

	default:
		err("Unspported mode: [%d]", mode);
		return FALSE;
	}

	return TRUE;
}

static gboolean __atmodem_ss_convert_forwarding_condition_to_modem_reason(TelSsForwardCondition condition,
	guint *reason)
{
	switch (condition) {
	case TEL_SS_CF_COND_CFU:
		*reason = 0;
	break;

	case TEL_SS_CF_COND_CFB:
		*reason = 1;
	break;

	case TEL_SS_CF_COND_CFNRY:
		*reason = 2;
	break;

	case TEL_SS_CF_COND_CFNRC:
		*reason = 3;
	break;

	case TEL_SS_CF_COND_ALL:
		*reason = 4;
	break;

	case TEL_SS_CF_COND_ALL_CFC:
		*reason = 5;
	break;

	default:
		dbg("Unsupported condition: [%d]", condition);
		return FALSE;
	}
	return TRUE;
}

static gboolean __atmodem_ss_convert_modem_cli_dev_status_cli_status(TelSsCliType cli_type,
	gint dev_status, gint *status)
{
	if (cli_type == TEL_SS_CLI_CLIR) {
		switch (dev_status) {
		case 0:
			*status = TEL_CLIR_STATUS_DEFAULT;
		break;

		case 1:
			*status = TEL_CLIR_STATUS_INVOCATION;
		break;

		case 2:
			*status = TEL_CLIR_STATUS_SUPPRESSION;
		break;
		default:
			err("Invalid dev status: [%d]", dev_status);
			return FALSE;
		}
	} else { //CLIP, COLP,COLR,CNAP.
		switch (dev_status) {
		case 0:
			*status  = TEL_SS_CLI_DISABLE;
		break;

		case 1:
			*status  = TEL_SS_CLI_ENABLE;
		break;

		default:
			err("Invalid dev status: [%d]", dev_status);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean __atmodem_ss_convert_modem_cli_net_status_cli_status(TelSsCliType cli_type, gint net_status,
	 gint *status)
{
	if (cli_type == TEL_SS_CLI_CLIR) {
		switch (net_status) {
			case 0:
				*status = TEL_CLIR_STATUS_NOT_PROVISIONED;
				break;
			case 1:
				*status = TEL_CLIR_STATUS_PROVISIONED;
				break;
			case 2:
				*status = TEL_CLIR_STATUS_UNKNOWN;
				break;
			case 3:
				*status = TEL_CLIR_STATUS_TEMP_RESTRICTED;
				break;
			case 4:
				*status = TEL_CLIR_STATUS_TEMP_ALLOWED;
				break;
			default:
				err("Invalid clir net status: [%d]", net_status);
				return FALSE;
		}
	} else { //CLIP, COLP,COLR,CNAP.
		switch (net_status) {
		case 0:
			*status = TEL_SS_CLI_NOT_PROVISIONED;
			break;
		case 1:
			*status = TEL_SS_CLI_PROVISIONED;
			break;
		case 2:
			*status = TEL_SS_CLI_UNKNOWN;
			break;
		default:
			err("Invalid status: [%d]", net_status);
			return FALSE;
		}
	}
	return TRUE;
}


/* SS Responses */
static void on_response_atmodem_ss_set_barring(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelSsResult result = TEL_SS_RESULT_FAILURE; // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success)
		result = TEL_SS_RESULT_SUCCESS;

	dbg("Setting Barring status: [%s]",
			(result == TEL_SS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_ss_get_barring_status(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	TelSsBarringResp barring_resp = {0,};
	TelSsBarringGetInfo *req_info;
	gint valid_records = 0;
	GSList *resp_data = NULL;

	TelSsResult result = TEL_SS_RESULT_FAILURE; // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	req_info = (TelSsBarringGetInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp) {
		if (at_resp->lines && at_resp->success) {
			resp_data = (GSList *) at_resp->lines;
			barring_resp.record_num= g_slist_length(resp_data);
			dbg("Total records: [%d]", barring_resp.record_num);
		}
		else {
			err("RESPONSE - [NOK]");
		}
	} else {
		err("No response data");
	}

	if (barring_resp.record_num > 0) {
		barring_resp.records = tcore_malloc0(
			(barring_resp.record_num) * sizeof(TelSsBarringInfoRecord));
		for (valid_records = 0; resp_data != NULL; resp_data = resp_data->next) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const gchar *) resp_data->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) > 0) {
				gchar *classx_str;
				gchar *status = NULL;

				status = g_slist_nth_data(tokens, 0);
				if (!status) {
					dbg("Status is missing");
					tcore_at_tok_free(tokens);
					continue;
				}

				if (atoi(status) == 1) {
					barring_resp.records[valid_records].enable = TRUE;
				} else {
					barring_resp.records[valid_records].enable = FALSE;
				}

				classx_str = g_slist_nth_data(tokens, 1);
				if (!classx_str) {
					dbg("Class error. Setting to the requested class: [%d]", req_info->class);
					barring_resp.records[valid_records].class = req_info->class;
				} else {
					if (__atmodem_ss_convert_modem_class_to_class(atoi(classx_str),
							&(barring_resp.records[valid_records].class)) == FALSE) {
						tcore_at_tok_free(tokens);
						continue;
					}
				}

				barring_resp.records[valid_records].type= req_info->type;
				result = TEL_SS_RESULT_SUCCESS;
				valid_records++;
			} else {
				err("Invalid response message");
			}
			tcore_at_tok_free(tokens);
		}
	}

	dbg("Getting Barring status: [%s]",
			(result == TEL_SS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));
	barring_resp.record_num = valid_records;

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &barring_resp, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);

	if (barring_resp.records) {
		tcore_free(barring_resp.records);
	}
}

static void on_response_atmodem_ss_change_barring_password(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelSsResult result = TEL_SS_RESULT_FAILURE;  // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success)
		result = TEL_SS_RESULT_SUCCESS;

	dbg("Change Barring Password: [%s]",
			(result == TEL_SS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_ss_set_forwarding(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelSsResult result = TEL_SS_RESULT_FAILURE;  // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success)
		result = TEL_SS_RESULT_SUCCESS;

	dbg("Set Forwarding Status: [%s]",
			(result == TEL_SS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_ss_get_forwarding_status(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	TelSsForwardingResp forwarding_resp = {0,};
	TelSsForwardGetInfo *req_info;
	gint valid_records = 0;
	GSList *resp_data = NULL;

	TelSsResult result = TEL_SS_RESULT_FAILURE; // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	req_info = (TelSsForwardGetInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp) {
		if (at_resp->lines && at_resp->success) {
			resp_data = (GSList *) at_resp->lines;
			forwarding_resp.record_num= g_slist_length(resp_data);
			dbg("Total records: [%d]", forwarding_resp.record_num);
		}
		else {
			err("RESPONSE - [NOK]");
		}
	} else {
		err("No response data");
	}

	if (forwarding_resp.record_num > 0) {
		forwarding_resp.records = tcore_malloc0(
			(forwarding_resp.record_num) * sizeof(TelSsForwardingInfoRecord));
		for (valid_records = 0; resp_data != NULL; resp_data = resp_data->next) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const gchar *) resp_data->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) > 0) {
				gchar *classx_str;
				gchar *status = NULL;
				gchar *number = NULL;
				gchar *time_str = NULL;

				status = g_slist_nth_data(tokens, 0);
				if (!status) {
					dbg("Status is missing");
					tcore_at_tok_free(tokens);
					continue;
				}

				if (atoi(status) == 1) {
					forwarding_resp.records[valid_records].enable = TRUE;
				} else {
					forwarding_resp.records[valid_records].enable = FALSE;
				}

				classx_str = g_slist_nth_data(tokens, 1);
				if (!classx_str) {
					dbg("Class error. Setting to the requested class: [%d]", req_info->class);
					forwarding_resp.records[valid_records].class = req_info->class;
				} else {
					if (__atmodem_ss_convert_modem_class_to_class(atoi(classx_str),
							&(forwarding_resp.records[valid_records].class)) == FALSE) {
						tcore_at_tok_free(tokens);
						continue;
					}
				}

				number = g_slist_nth_data(tokens, 2);
				if (number)
					memcpy((forwarding_resp.records[valid_records].number),
						number, strlen(number));

				time_str = g_slist_nth_data(tokens, 6);
				if (time_str)
					forwarding_resp.records[valid_records].wait_time = atoi(time_str);

				forwarding_resp.records[valid_records].condition = req_info->condition;

				result = TEL_SS_RESULT_SUCCESS;
				valid_records++;
			} else {
				err("Invalid response message");
			}
			tcore_at_tok_free(tokens);
		}
	}

	dbg("Getting Forwarding Status: [%s]",
			(result == TEL_SS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));
	forwarding_resp.record_num = valid_records;

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &forwarding_resp, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);

	if (forwarding_resp.records) {
		tcore_free(forwarding_resp.records);
	}
}

static void on_response_atmodem_ss_set_waiting(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelSsResult result = TEL_SS_RESULT_FAILURE;  // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success)
		result = TEL_SS_RESULT_SUCCESS;

	dbg("Set Waiting Status: [%s]",
			(result == TEL_SS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_ss_get_waiting_status(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	TelSsWaitingResp waiting_resp = {0,};
	TelSsClass *class;
	gint valid_records = 0;
	GSList *resp_data = NULL;

	TelSsResult result = TEL_SS_RESULT_FAILURE; // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	class = (TelSsClass *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp) {
		if (at_resp->lines && at_resp->success) {
			resp_data = (GSList *) at_resp->lines;
			waiting_resp.record_num= g_slist_length(resp_data);
			dbg("Total records: [%d]", waiting_resp.record_num);
		}
		else {
			err("RESPONSE - [NOK]");
		}
	} else {
		err("No response data");
	}

	if (waiting_resp.record_num > 0) {
		waiting_resp.records = tcore_malloc0(
			(waiting_resp.record_num) * sizeof(TelSsWaitingInfo));
		for (valid_records = 0; resp_data != NULL; resp_data = resp_data->next) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const gchar *) resp_data->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) > 0) {
				gchar *classx_str;
				gchar *status = NULL;

				status = g_slist_nth_data(tokens, 0);
				if (!status) {
					dbg("Status is missing");
					tcore_at_tok_free(tokens);
					continue;
				}

				if (atoi(status) == 1) {
					waiting_resp.records[valid_records].enable= TRUE;
				} else {
					waiting_resp.records[valid_records].enable = FALSE;
				}

				classx_str = g_slist_nth_data(tokens, 1);
				if (!classx_str) {
					dbg("Class error. Setting to the requested class: [%d]", *class);
					waiting_resp.records[valid_records].class = *class;
				} else {
					if (__atmodem_ss_convert_modem_class_to_class(atoi(classx_str),
							&(waiting_resp.records[valid_records].class)) == FALSE) {
						tcore_at_tok_free(tokens);
						continue;
					}
				}

				result = TEL_SS_RESULT_SUCCESS;
				valid_records++;
			} else {
				err("Invalid response message");
			}
			tcore_at_tok_free(tokens);
		}
	}

	dbg("Getting Waiting Status: [%s]",
			(result == TEL_SS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));
	waiting_resp.record_num = valid_records;

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result,
			&waiting_resp, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);

	if (waiting_resp.records)
		tcore_free(waiting_resp.records);
}

static void on_response_atmodem_ss_get_cli_status(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	TelSsCliResp cli_resp = {0,};
	TelSsCliType *cli_type;
	GSList *tokens = NULL;

	TelSsResult result = TEL_SS_RESULT_FAILURE; // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	cli_type = (TelSsCliType *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (*cli_type == TEL_SS_CLI_CDIP) {
		err("Unsupported CLI type: [%d]", *cli_type);
		result = TEL_SS_RESULT_INVALID_PARAMETER;
		goto out;
	}

	if (at_resp && at_resp->success) {
		const gchar *line;
		gchar  *status = NULL;
		gint net_status;
		gint dev_status;

		if (!at_resp->lines) {
			err("Invalid response message");
			goto out;
		}
		line = (const gchar *)at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("Invalid response message");
			goto out;
		}

		dbg("RESPONSE OK");
		status = g_slist_nth_data(tokens, 0);
		if (!status) {
			err("dev_status is missing");
			goto out;
		}
		if (!__atmodem_ss_convert_modem_cli_dev_status_cli_status(*cli_type,
				atoi(status), &dev_status))
			goto out;

		status = g_slist_nth_data(tokens, 1);
		if (!status) {
			err("net_status is missing");
			goto out;
		}
		if (!__atmodem_ss_convert_modem_cli_net_status_cli_status(*cli_type,
				atoi(status), &net_status))
			goto out;

		switch (*cli_type){
		case TEL_SS_CLI_CLIR:
			cli_resp.status.clir.net_status = net_status;
			cli_resp.status.clir.dev_status = dev_status;
		break;

		case TEL_SS_CLI_CLIP:
			cli_resp.status.clip.net_status = net_status;
			cli_resp.status.clip.dev_status = dev_status;
		break;

		case TEL_SS_CLI_COLP:
			cli_resp.status.colp.net_status = net_status;
			cli_resp.status.colp.dev_status = dev_status;
		break;

		case TEL_SS_CLI_COLR:
			cli_resp.status.colr.net_status = net_status;
			cli_resp.status.colr.dev_status = dev_status;
		break;

		case TEL_SS_CLI_CNAP:
			cli_resp.status.cnap.net_status = net_status;
			cli_resp.status.cnap.dev_status = dev_status;
		break;

		default:
			err("Unsupported CLI type: [%d]", *cli_type);
			result = TEL_SS_RESULT_INVALID_PARAMETER;
			goto out;
		}

		cli_resp.type = *cli_type;
	} else {
		err("RESPONSE NOK");
	}

out:
	tcore_at_tok_free(tokens);

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result,
			&cli_resp, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_ss_send_ussd_request(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	TelSsUssdResp ussd_resp = {0,};
	UssdSession *ussd_s = NULL;


	TelSsResult result = TEL_SS_RESULT_FAILURE;  // TODO: CMEE error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	ussd_s = tcore_ss_ussd_get_session(co);
	tcore_check_return(ussd_s != NULL);

	tcore_ss_ussd_get_session_type(ussd_s, &ussd_resp.type);

	if (at_resp && at_resp->success)
		result = TEL_SS_RESULT_SUCCESS;

	dbg("Send Ussd Request: [%s]",
		(result == TEL_SS_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	tcore_ss_ussd_destroy_session(ussd_s);

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &ussd_resp, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

/* SS Operations */
/*
 * Operation - set_barring/get_barring_status
 *
 * Request -
 * AT-Command: AT+CLCK=<fac>,<mode>[,<passwd>[,<class>]]
 * where,
 * <fac>
 * Barring facility type. Ref #TelSsBarringType
 *
 * <mode>
 * 0 unlock
 * 1 lock
 * 2 query status
 *
 * <passwd>
 * Barring Password
 *
 * <class>
 * SS class. Ref #TelSsClass
 *
 * <status>
 * 0 not active
 * 1 active
 *
 * Success: when <mode>=2:
 * 	OK
 * 	+CLCK: <status>[,<class1> [<CR><LF>
 * 	+CLCK: <status>,<class2> [...]]
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_ss_set_barring(CoreObject *co,
	const TelSsBarringInfo *barring_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	guint mode;
	guint classx;
	gchar *facility = NULL;
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	if (barring_info->enable == TRUE)
		mode = 1;
	else
		mode = 0;

	if (__atmodem_ss_convert_barring_type_to_facility(
			barring_info->type, &facility) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	classx = __atmodem_ss_convert_class_to_atmodem_class(barring_info->class);

	dbg("facility: [%s], classx:[%d], mode: [%d]", facility, classx, mode);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CLCK=\"%s\",%d,\"%s\",%d",
		facility, mode, barring_info->pwd, classx);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, NULL,
			TCORE_AT_COMMAND_TYPE_NO_RESULT,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_set_barring, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Barring");

	g_free(at_cmd);
	return ret;
}

static TelReturn atmodem_ss_get_barring_status(CoreObject *co,
	const TelSsBarringGetInfo *get_barring_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	guint mode;
	guint classx;
	gchar *facility = NULL;
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	mode = 2; /* query status - mode is fixed to 2 */

	if (__atmodem_ss_convert_barring_type_to_facility(
			get_barring_info->type, &facility) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	classx = __atmodem_ss_convert_class_to_atmodem_class(get_barring_info->class);

	dbg("facility: [%s], classx:[%d], mode: [%d]", facility, classx, mode);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CLCK=\"%s\",%d,,%d",
			facility, mode, classx);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
		(void *)get_barring_info, sizeof(TelSsBarringGetInfo));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, "+CLCK",
			TCORE_AT_COMMAND_TYPE_MULTILINE,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_get_barring_status, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Barring Status");

	g_free(at_cmd);
	return ret;
}

/*
 * Operation - change_barring_password
 *
 * Request -
 * AT-Command: AT+CPWD= <fac>,<oldpwd>,<newpwd>
 * where,
 * <fac>
 * Barring facility type. Ref #TelSsBarringType
 * Eg: "AB" All Barring services
 *
 * <oldpwd>
 * Old Barring Password
 *
 * <newpwd>
 * New Barring Password
 *
 * Success:
 * 	OK
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_ss_change_barring_password(CoreObject *co,
	const TelSsBarringPwdInfo *barring_pwd_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	if (barring_pwd_info->old_pwd== NULL || barring_pwd_info->new_pwd == NULL) {
		err("Invalid data");
		return ret;
	}

	dbg("Old password: [%s], New password: [%s]",
		barring_pwd_info->old_pwd, barring_pwd_info->new_pwd);

	at_cmd = g_strdup_printf("AT+CPWD=\"%s\",\"%s\",\"%s\"", "AB",
		barring_pwd_info->old_pwd, barring_pwd_info->new_pwd);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, NULL,
			TCORE_AT_COMMAND_TYPE_NO_RESULT,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_change_barring_password, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Change Barring Password");

	g_free(at_cmd);
	return ret;
}

/*
 * Operation - set_forwarding/get_forwarding_status
 *
 * Request -
 * AT-Command: AT+CCFC=<reason>,<mode>[,<number>[,<type>[,<class>[,<subaddr>[,<satype>[,<time>]]]]]]
 * where,
 * <reason>
 * Forwarding Condition. Ref #TelSsForwardCondition
 *
 * <mode>
 * Forwarding Mode. Ref #TelSsForwardMode
 * 0 disable
 * 1 enable
 * 2 query status
 * 3 registration
 * 4 erasure
 *
 *
 * <number>
 * Call Forwarding Number
 *
 * <type>
 * Default 145 when available string includes "+"
 * Otherwise 129
 *
 * <subaddr>
 * Parameter String type subaddress of format specified by <satype>
 *
 * <satype>
 * Parameter type of subaddress octet in integer format
 * Default 128
 *
 * <time>
 * Parameter time in seconds to wait before call is forwarded
 * Default 20, but only when <reason>=2 (no reply) is enabled
 *
 * <class>
 * SS class. Ref #TelSsClass
 *
 * <status>
 * 0 not active
 * 1 active
 *
 * Success: when <mode>=2:
 * 	OK
 * 	+CCFC: <status>,<class1>[,<number>,<type>[,<subaddr>,<satype>[,<time>]]][<CR><LF>
 *	+CCFC: <status>,<class2>[,<number>,<type>[,<subaddr>,<satype>[,<time>]]][...]]
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_ss_set_forwarding(CoreObject *co,
	const TelSsForwardInfo *forwarding_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	gchar *tmp_cmd = NULL;
	guint classx;
	guint reason;
	guint mode;
	guint num_type;
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	classx = __atmodem_ss_convert_class_to_atmodem_class(forwarding_info->class);

	if (__atmodem_ss_convert_forwarding_mode_to_modem_mode(
			forwarding_info->mode, &mode) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	if (__atmodem_ss_convert_forwarding_condition_to_modem_reason(
			forwarding_info->condition, &reason) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	if (forwarding_info->number[0] == '+')
		num_type = 145;
	else
		num_type = 129;

	dbg("classx: [%d], reason:[%d], mode: [%d]", classx, reason, mode);

	if (mode == 3)	/* TEL_SS_CF_MODE_REGISTER */
		tmp_cmd = g_strdup_printf("AT+CCFC=%d,%d,\"%s\",%d,%d",
			reason, mode, forwarding_info->number, num_type, classx);
	else
		tmp_cmd = g_strdup_printf("AT+CCFC=%d,%d,,,%d",
			reason, mode, classx);

	if (reason == 2)	/* TEL_SS_CF_COND_CFNRY */
		at_cmd = g_strdup_printf("%s,,,%d", tmp_cmd, forwarding_info->wait_time);
	else
		at_cmd = g_strdup_printf("%s", tmp_cmd);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, NULL,
			TCORE_AT_COMMAND_TYPE_NO_RESULT,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_set_forwarding, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Forwarding");

	g_free(tmp_cmd);
	g_free(at_cmd);
	return ret;
}

static TelReturn atmodem_ss_get_forwarding_status(CoreObject *co,
	const TelSsForwardGetInfo *get_forwarding_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	guint classx;
	guint reason;
	guint mode = 2; /* query status */
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	classx = __atmodem_ss_convert_class_to_atmodem_class(get_forwarding_info->class);

	if (__atmodem_ss_convert_forwarding_condition_to_modem_reason(
			get_forwarding_info->condition, &reason) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	dbg("classx: [%d], reason: [%d], mode: [%d]", classx, reason, mode);

	at_cmd = g_strdup_printf("AT+CCFC=%d,%d,,,%d", reason, mode, classx);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
		(void *)get_forwarding_info, sizeof(TelSsForwardGetInfo));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, "+CCFC",
			TCORE_AT_COMMAND_TYPE_MULTILINE,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_get_forwarding_status, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Forwarding Status");

	g_free(at_cmd);
	return ret;
}

/*
 * Operation - set_waiting/get_waiting_status
 *
 * Request -
 * AT-Command: AT+CCWA=[<n>[,<mode>[,<class>]]]
 * where,
 * <n>
 * Parameter Sets/shows the result code presentation status to the TE.
 * 0 presentation status is disabled to TE(default)
 * 1 presentation status is enabled to TE
 *
 * <mode>
 * 0 Disable call waiting
 * 1 Enable call waiting
 * 2 Query status
 *
 * <class>
 * SS class. Ref #TelSsClass
 *
 * <status>
 * 0 not active
 * 1 active
 *
 * Success: when <mode>=2:
 * 	OK
 * 	+CCWA: <status>,<class1>
 *	+CCWA: <status>,<class2>
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_ss_set_waiting(CoreObject *co,
	const TelSsWaitingInfo *waiting_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	guint classx;
	guint mode;
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	if (waiting_info->enable == TRUE)
		mode = 1;
	else
		mode = 0;

	classx = __atmodem_ss_convert_class_to_atmodem_class(waiting_info->class);

	dbg("mode: [%d], class: [%d]", mode, classx);

	at_cmd = g_strdup_printf("AT+CCWA=1,%d,%d", mode, classx);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, NULL,
			TCORE_AT_COMMAND_TYPE_NO_RESULT,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_set_waiting, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Waiting");

	g_free(at_cmd);
	return ret;
}

static TelReturn atmodem_ss_get_waiting_status(CoreObject *co,
	TelSsClass ss_class,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	guint classx;
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	classx = __atmodem_ss_convert_class_to_atmodem_class(ss_class);

	dbg("class: [%d]", classx);

	at_cmd = g_strdup_printf("AT+CCWA=1,2,%d", classx);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
		&ss_class, sizeof(TelSsClass));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, "+CCWA",
			TCORE_AT_COMMAND_TYPE_MULTILINE,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_get_waiting_status, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Waiting Status");

	g_free(at_cmd);
	return ret;
}

/*
 * Operation - get_cli_status
 *
 * Request -
 * AT-Command:
 * For CLIR: AT+CLIR?
 * For CLIP: AT+CLIP?
 * For COLP: AT+COLP?
 * For COLR: AT+COLR?
 * For CNAP: AT+CNAP?
 *
 * Success:
 * 	OK
 *	+CLIR: <n>,<m>
 *
 * where,
 * <m> All CLI except CLIR
 * 0 Not provisioned
 * 1 Provisioned
 * 2 Unknown
 *
 *<m> For CLIR
 * 0 Not provisioned
 * 1 Provisioned in permanent mode
 * 2 Unknown (e.g. no network, etc.)
 * 3 Temporary mode presentation restricted
 * 4 Temporary mode presentation allowed
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_ss_get_cli_status(CoreObject *co,
	TelSsCliType cli_type,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	gchar *cmd_prefix = NULL;
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	switch (cli_type) {
	case TEL_SS_CLI_CLIR:
		cmd_prefix = "+CLIR";
	break;

	case TEL_SS_CLI_CLIP:
		cmd_prefix = "+CLIP";
	break;

	case TEL_SS_CLI_COLP:
		cmd_prefix = "+COLP";
	break;

	case TEL_SS_CLI_COLR:
		cmd_prefix = "+COLR";
	break;

	case TEL_SS_CLI_CNAP:
		cmd_prefix = "+CNAP";
	break;

	case TEL_SS_CLI_CDIP:
	default:
		dbg("Unsupported CLI type: [%d]", cli_type);
		return ret;
	}

	at_cmd = g_strdup_printf("AT%s?", cmd_prefix);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, &cli_type, sizeof(TelSsCliType));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, cmd_prefix,
			TCORE_AT_COMMAND_TYPE_SINGLELINE,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_get_cli_status, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Cli Status");

	g_free(at_cmd);
	return ret;
}

/*
 * Operation - send_ussd_request
 *
 * Request -
 * AT-Command: AT+CUSD = [<n> [, <str> [, <dcs>]]]
 * where,
 * <n>
 * 0 Disable the result code presentation to the TE(default)
 * 1 Enable the result code presentation to the TE
 * 2 Cancel session (not applicable to read command response)
 *
 * <str>
 * USSD string
 *
 * <dcs>
 * Cell Broadcast Data Coding Scheme. Default value is 0.
 *
 * Success:
 * 	OK
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_ss_send_ussd_request(CoreObject *co,
	const TelSsUssdInfo *ussd_request,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	UssdSession *ussd_s = NULL;
	AtmodemRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	ussd_s = tcore_ss_ussd_get_session(co);
	if (!ussd_s) {
		dbg("USSD session does not exist");
		tcore_ss_ussd_create_session(co, ussd_request->type,
			(void *)ussd_request->str,
			strlen((gchar *)ussd_request->str));
	} else {
		if (ussd_request->type == TEL_SS_USSD_TYPE_USER_INIT) {
			err("USSD session exists");
			return TEL_RETURN_OPERATION_NOT_SUPPORTED;
		}
		tcore_ss_ussd_set_session_type(ussd_s, ussd_request->type);
	}

	at_cmd = g_strdup_printf("AT+CUSD=1,\"%s\",%d", ussd_request->str, 0x0f);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, NULL,
			TCORE_AT_COMMAND_TYPE_NO_RESULT,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_atmodem_ss_send_ussd_request, resp_cb_data,
			on_send_atmodem_request, NULL,
			0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Send Ussd Request");

	g_free(at_cmd);
	return ret;
}

/* SS Operations */
static TcoreSsOps atmodem_ss_ops = {
	.set_barring = atmodem_ss_set_barring,
	.get_barring_status = atmodem_ss_get_barring_status,
	.change_barring_password = atmodem_ss_change_barring_password,
	.set_forwarding = atmodem_ss_set_forwarding,
	.get_forwarding_status = atmodem_ss_get_forwarding_status,
	.set_waiting = atmodem_ss_set_waiting,
	.get_waiting_status = atmodem_ss_get_waiting_status,
	.set_cli = NULL,
	.get_cli_status = atmodem_ss_get_cli_status,
	.send_ussd_request = atmodem_ss_send_ussd_request
};

gboolean atmodem_ss_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Entry");

	/* Set operations */
	tcore_ss_set_ops(co, &atmodem_ss_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co,
		"+CUSD:",
		on_notification_atmodem_ss_ussd, NULL);

	dbg("Exit");
	return TRUE;
}

void atmodem_ss_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}
