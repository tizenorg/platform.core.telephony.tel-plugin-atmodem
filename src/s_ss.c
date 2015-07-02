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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_call.h>
#include <co_ss.h>
#include <user_request.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
#include "s_ss.h"
#include "util.h"

enum  telephony_ss_opcode {
	TIZEN_SS_OPCO_DEACTIVATE = 0x01,
	TIZEN_SS_OPCO_ACTIVATE,
	TIZEN_SS_OPCO_REG,
	TIZEN_SS_OPCO_DEREG,
	TIZEN_SS_OPCO_MAX
} ;

struct ss_resp_cb_data {
	enum telephony_ss_opcode opco;
};

static void _ss_ussd_response(UserRequest *ur, const char *ussd_str,
	enum telephony_ss_ussd_type type, enum telephony_ss_ussd_status status)
{
	struct tresp_ss_ussd resp;

	if (!ur) {
		err("ur : (NULL)");
		return ;
	}

	resp.type = type;
	resp.status = status;
	resp.err = SS_ERROR_NONE;

	if (ussd_str) {
		int len = strlen(ussd_str);

		if (len < MAX_SS_USSD_LEN) {
			memcpy(resp.str, ussd_str, len);
			resp.str[len] = '\0';
		} else {
			memcpy(resp.str, ussd_str, MAX_SS_USSD_LEN);
			resp.str[MAX_SS_USSD_LEN - 1] = '\0';
		}

		dbg("resp.str : %s", resp.str);
	} else {
		memset(resp.str, '\0', MAX_SS_USSD_LEN);
	}

	tcore_user_request_send_response(ur,
		TRESP_SS_SEND_USSD,
		sizeof(struct tresp_ss_ussd), &resp);
}

static void _ss_ussd_notification(TcorePlugin *p,
	const char *ussd_str, enum telephony_ss_ussd_status status)
{
	CoreObject *o = 0;
	struct tnoti_ss_ussd noti;

	if (!p) {
		err("p : (NULL)");
		return ;
	}

	noti.status = status;

	if (ussd_str) {
		int len = strlen(ussd_str);

		if (len < MAX_SS_USSD_LEN) {
			memcpy(noti.str, ussd_str, len);
			noti.str[len] = '\0';
		} else {
			memcpy(noti.str, ussd_str, MAX_SS_USSD_LEN);
			noti.str[MAX_SS_USSD_LEN - 1] = '\0';
		}
	} else {
		memset(noti.str, '\0', MAX_SS_USSD_LEN);
	}

	o = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SS);

	tcore_server_send_notification(tcore_plugin_ref_server(p),
			o,
			TNOTI_SS_USSD,
			sizeof(struct tnoti_ss_ussd),
			(void *)&noti);
}

static gboolean on_notification_ss_ussd(CoreObject *o, const void *data, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	gchar *resp_str = NULL;
	guchar *dcs_str = NULL;
	const gchar *line;

	gushort len;
	enum telephony_ss_ussd_status status;
	UssdSession *ussd_session = 0;
	char *ussd_str = 0;
	TcorePlugin *p = 0;
	int m = 0, dcs = 0;

	p = tcore_object_ref_plugin(o);

	ussd_session = tcore_ss_ussd_get_session(o);

	lines = (GSList *)data;
	if (g_slist_length(lines) != 1) {
		dbg("Unsolicited message but multiple lines");
		return TRUE;
	}
	line = (const gchar *)lines->data;
	tokens = tcore_at_tok_new(line);

	resp_str = g_slist_nth_data(tokens, 0);
	if (NULL == resp_str) {
		err("Status is missing from +CUSD Notification");
		goto out;
	} else {
		m = atoi(resp_str);
		switch (m) {
		case 0:
			status = SS_USSD_NO_ACTION_REQUIRE;
		break;

		case 1:
			status = SS_USSD_ACTION_REQUIRE;
		break;

		case 2:
			status = SS_USSD_TERMINATED_BY_NET;
		break;

		case 3:
			status = SS_USSD_OTHER_CLIENT;
		break;

		case 4:
			status = SS_USSD_NOT_SUPPORT;
		break;

		case 5:
			status = SS_USSD_TIME_OUT;
		break;

		default:
			dbg("unsupported m : %d", m);
			status = SS_USSD_MAX;
		break;
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
		switch (tcore_util_get_cbs_coding_scheme(dcs)) {
		case TCORE_DCS_TYPE_7_BIT:
		case TCORE_DCS_TYPE_UNSPECIFIED: {
			ussd_str = (char *)tcore_util_unpack_gsm7bit((const unsigned char *)resp_str, strlen(resp_str));
		}
		break;

		case TCORE_DCS_TYPE_UCS2:
		case TCORE_DCS_TYPE_8_BIT: {
			if (strlen(resp_str)  > 0) {
				ussd_str = g_new0(char, strlen(resp_str)  + 1);
				memcpy(ussd_str, resp_str, strlen(resp_str));
				ussd_str[strlen(resp_str)] = '\0';
			}
		}
		break;

		default: {
			err("unknown dcs type. ussd_session : %x", ussd_session);
			if (ussd_session) {
				UserRequest *ur = 0;
				enum telephony_ss_ussd_type type;
				tcore_ss_ussd_get_session_data(ussd_session, (void **)&ur);

				if (!ur) {
					err("ur : (NULL)");
					goto out;
				}
				type = (enum telephony_ss_ussd_type)tcore_ss_ussd_get_session_type(ussd_session);

				_ss_ussd_response(ur, ussd_str, type, status);
			}
			g_free(resp_str);
			return TRUE;
		}
		}
	} else {
		warn("No DCS string! Using default DCS value");
	}

	switch (status) {
	case SS_USSD_NO_ACTION_REQUIRE:
	case SS_USSD_ACTION_REQUIRE:
	case SS_USSD_OTHER_CLIENT:
	case SS_USSD_NOT_SUPPORT:
	case SS_USSD_TIME_OUT: {
		if (ussd_session) {
			UserRequest *ur = 0;
			enum telephony_ss_ussd_type type;

			tcore_ss_ussd_get_session_data(ussd_session, (void **)&ur);
			if (!ur) {
				err("ur : (NULL)");
				return TRUE;
			}

			type = (enum telephony_ss_ussd_type)tcore_ss_ussd_get_session_type(ussd_session);
			_ss_ussd_response(ur, (const char *)ussd_str, type, status);

			g_free(ussd_str);
		} else {
			tcore_ss_ussd_create_session(o, TCORE_SS_USSD_TYPE_NETWORK_INITIATED, 0, 0);
			_ss_ussd_notification(p, (const char *)ussd_str, status);

			g_free(ussd_str);
		}
	}
	break;

	case SS_USSD_TERMINATED_BY_NET: {
		if (ussd_session) {
			UserRequest *ur = 0;

			tcore_ss_ussd_get_session_data(ussd_session, (void **)&ur);
			if (ur)
				tcore_user_request_unref(ur);

			tcore_ss_ussd_destroy_session(ussd_session);
		}

	}
	break;

	default:
	break;
	}
	g_free(resp_str);
out:
	tcore_at_tok_free(tokens);
	return TRUE;
}

static gboolean __atmodem_ss_convert_forwarding_mode_to_modem_reason(enum telephony_ss_forwarding_mode condition,
	guint *reason)
{
	switch (condition) {
	case SS_CF_MODE_CFU:
		*reason = 0;
	break;
	case SS_CF_MODE_CFB:
		*reason = 1;
	break;
	case SS_CF_MODE_CFNRy:
		*reason = 2;
	break;
	case SS_CF_MODE_CFNRc:
		*reason = 3;
	break;
	case SS_CF_MODE_CF_ALL:
		*reason = 4;
	break;
	case SS_CF_MODE_CFC:
		*reason = 5;
	break;
	default:
		dbg("Unsupported condition: [0x%x]", condition);
		return FALSE;
	}

	return TRUE;
}

static gboolean __atmodem_ss_convert_forwarding_opcode_to_modem_mode(enum telephony_ss_opcode mode,
	guint *modex)
{
	switch (mode) {
	case TIZEN_SS_OPCO_DEACTIVATE:
		*modex = 0;
	break;
	case TIZEN_SS_OPCO_ACTIVATE:
		*modex = 1;
	break;
	case TIZEN_SS_OPCO_REG:
		*modex = 3;
	break;
	case TIZEN_SS_OPCO_DEREG:
		*modex = 4;
	break;
	default:
		err("Unspported mode: [%d]", mode);
		return FALSE;
	}

	return TRUE;
}

static gboolean __atmodem_ss_convert_modem_class_to_class(gint classx,
	enum telephony_ss_class *class)
{
	switch (classx) {
	case 7:
		*class = SS_CLASS_ALL_TELE;
	break;
	case 1:
		*class = SS_CLASS_VOICE;
	break;
	case 2:
		*class = SS_CLASS_ALL_DATA_TELE;
	break;
	case 4:
		*class = SS_CLASS_FAX;
	break;
	case 8:
		*class = SS_CLASS_SMS;
	break;
	case 16:
		*class = SS_CLASS_ALL_CS_SYNC;
	break;
	case 32:
		*class = SS_CLASS_ALL_CS_ASYNC;
	break;
	case 64:
		*class = SS_CLASS_ALL_DEDI_PS;
	break;
	case 128:
		*class = SS_CLASS_ALL_DEDI_PAD;
	break;
	default:
		err("Invalid modem class: [%d]", classx);
		return FALSE;
	}

	return TRUE;
}

static guint __atmodem_ss_convert_class_to_atmodem_class(enum telephony_ss_class class)
{
	switch (class) {
	case SS_CLASS_ALL_TELE:
		return 7;
	case SS_CLASS_VOICE:
		return 1;
	case SS_CLASS_ALL_DATA_TELE:
		return 2;
	case SS_CLASS_FAX:
		return 4;
	case SS_CLASS_SMS:
		return 8;
	case SS_CLASS_ALL_CS_SYNC:
		return 16;
	case SS_CLASS_ALL_CS_ASYNC:
		return 32;
	case SS_CLASS_ALL_DEDI_PS:
		return 64;
	case SS_CLASS_ALL_DEDI_PAD:
		return 128;
	default:
		dbg("Unsupported class: [%d], returning default value 7", class);
		return 7;
	}
}

static gboolean __atmodem_ss_convert_barring_type_to_facility(enum telephony_ss_barring_mode mode,
	const char *facility)
{
	switch (mode) {
	case SS_BARR_MODE_BAOC:
		facility = "AO";
	break;
	case SS_BARR_MODE_BOIC:
		facility = "OI";
	break;
	case SS_BARR_MODE_BOIC_NOT_HC:
		facility = "OX";
	break;
	case SS_BARR_MODE_BAIC:
		facility = "AI";
	break;
	case SS_BARR_MODE_BIC_ROAM:
		facility = "IR";
	break;
	case SS_BARR_MODE_AB:
		facility = "AB";
	break;
	case SS_BARR_MODE_AOB:
		facility = "AG";
	break;
	case SS_BARR_MODE_AIB:
		facility = "AC";
	break;
	case SS_BARR_MODE_BIC_NOT_SIM:
		facility = "NS";
	break;
	default:
		err("Unspported type: [%d]", mode);
		return FALSE;
	}
	return TRUE;
}

/* SS Responses */
static void on_response_atmodem_ss_set_barring(TcorePending *p,
		int data_len, const void *data, void *user_data)
{
	struct tresp_ss_barring resp = {0, };
	const struct treq_ss_barring *req = NULL;
	struct ss_resp_cb_data *cb_data = user_data;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");
	ur = tcore_pending_ref_user_request(p);

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = SS_ERROR_NONE;

			req = tcore_user_request_ref_data(ur, NULL);
			resp.record_num = 1;
			resp.record = g_malloc0(sizeof(struct barring_info) * resp.record_num);
			resp.record[0].class = req->class;
			resp.record[0].mode = req->mode;
			if (cb_data->opco == TIZEN_SS_OPCO_ACTIVATE)
				resp.record[0].status = SS_STATUS_ACTIVATE;
			else
				resp.record[0].status = SS_STATUS_DEACTIVATE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = SS_ERROR_UNKNOWNERROR;
		}
	} else {
		err("No response data");
	}

	if (ur) {
		enum tcore_response_command resp_cmd;
		if (cb_data->opco == TIZEN_SS_OPCO_ACTIVATE)
			resp_cmd = TRESP_SS_BARRING_ACTIVATE;
		else
			resp_cmd = TRESP_SS_BARRING_DEACTIVATE;
		tcore_user_request_send_response(ur, resp_cmd,
			sizeof(struct tresp_ss_barring), &resp);
	} else {
		err("ur is NULL");
	}

	g_free(resp.record);
	g_free(cb_data);
}

static void on_response_atmodem_ss_get_barring_status(TcorePending *p,
		int data_len, const void *data, void *user_data)
{
	struct tresp_ss_barring resp = {0, };
	struct treq_ss_barring *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;
	int valid_records = 0;
	GSList *resp_data = NULL;
	TReturn result = TCORE_RETURN_FAILURE;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	if (ur)
		req_buf = (struct treq_ss_barring *)tcore_user_request_ref_data(ur, 0);
	else
		err("User Request is NULL");

	if (at_resp) {
		if (at_resp->lines && at_resp->success) {
			resp_data = (GSList *)at_resp->lines;
			resp.record_num = g_slist_length(resp_data);
			dbg("Total records: [%d]", resp.record_num);
		} else {
			err("RESPONSE - [NOK]");
		}
	} else {
		err("No response data");
	}

	if (req_buf) {
		if (resp.record_num > 0) {
			resp.record = g_try_malloc0(
				(resp.record_num) * sizeof(struct barring_info));
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

					if (atoi(status) == 1)
						resp.record[valid_records].status = SS_STATUS_REG;
					else
						resp.record[valid_records].status = SS_STATUS_DEREG;

					classx_str = g_slist_nth_data(tokens, 1);
					if (!classx_str) {
						dbg("Class error. Setting to the requested class: [%d]", req_buf->class);
						resp.record[valid_records].class = req_buf->class;
					} else {
						if (__atmodem_ss_convert_modem_class_to_class(atoi(classx_str),
								&(resp.record[valid_records].class)) == FALSE) {
							tcore_at_tok_free(tokens);
							continue;
						}
					}

					resp.record[valid_records].mode = req_buf->mode;
					result = TCORE_RETURN_SUCCESS;
					valid_records++;
				} else {
					err("Invalid response message");
				}
				tcore_at_tok_free(tokens);
			}
		}
	} else {
		err("req_buf is NULL");
	}

	dbg("Getting Barring status: [%s]",
			(result == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));
	resp.record_num = valid_records;

	tcore_user_request_send_response(ur,
			TRESP_SS_BARRING_GET_STATUS,
			sizeof(struct tresp_ss_barring), &resp);
	g_free(resp.record);
}

#ifdef EMUL_SUPPORTED
static void on_response_atmodem_ss_change_barring_password(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_ss_barring resp = {0, };
/*	struct treq_ss_barring *req_buf = NULL; */
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp && at_resp->success) {
		err("Response: [OK]");
		resp.err = SS_ERROR_NONE;
	} else {
		err("Response: [NOK] - [%s]", at_resp->final_response);
		resp.err = SS_ERROR_UNKNOWNERROR;
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		/*TODO :
			req_buf = (struct treq_ss_barring *) tcore_user_request_ref_data(ur, 0);
			resp.record->class = req_buf.class;
			resp.record->mode = req_buf.mode;
		Confirm data to be passed up and send accordingly*/
		tcore_user_request_send_response(ur,
			TRESP_SS_BARRING_CHANGE_PASSWORD,
			sizeof(struct tresp_ss_barring), &resp);
	} else {
		err("ur is NULL");
	}
}
#endif

static void on_response_atmodem_ss_set_forwarding(TcorePending *p,
		int data_len, const void *data, void *user_data)
{
	struct tresp_ss_forwarding resp = {0, };
	const struct treq_ss_forwarding *req = NULL;
	struct ss_resp_cb_data *cb_data = user_data;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");
	ur = tcore_pending_ref_user_request(p);

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = SS_ERROR_NONE;

			req = tcore_user_request_ref_data(ur, NULL);
			resp.record_num = 1;
			resp.record = g_malloc0(sizeof(struct forwarding_info) * resp.record_num);
			if (cb_data->opco == TIZEN_SS_OPCO_ACTIVATE || cb_data->opco == TIZEN_SS_OPCO_REG)
				resp.record[0].status = SS_STATUS_ACTIVATE;
			else
				resp.record[0].status = SS_STATUS_DEACTIVATE;
			resp.record[0].class = req->class;
			resp.record[0].mode = req->mode;
			if (strlen(req->number)) {
				g_strlcpy(resp.record[0].number, req->number, MAX_SS_FORWARDING_NUMBER_LEN);
				resp.record[0].number_present = TRUE;
			}
			resp.record[0].ton = req->ton;
			resp.record[0].npi = req->npi;
			if (req->time > 0)
				resp.record[0].time = req->time;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = SS_ERROR_UNKNOWNERROR;
		}
	} else {
		err("No response data");
	}

	if (ur) {
		enum tcore_response_command resp_cmd;
		if (cb_data->opco == TIZEN_SS_OPCO_ACTIVATE)
			resp_cmd = TRESP_SS_FORWARDING_ACTIVATE;
		else
			resp_cmd = TRESP_SS_FORWARDING_DEACTIVATE;
		tcore_user_request_send_response(ur, resp_cmd,
			sizeof(struct tresp_ss_barring), &resp);
	} else {
		err("ur is NULL");
	}

	g_free(resp.record);
	g_free(cb_data);
}

static void on_response_atmodem_ss_get_forwarding_status(TcorePending *p,
		int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	struct tresp_ss_forwarding resp = {0, };
	struct treq_ss_forwarding *req_buf = NULL;
	int valid_records = 0;
	GSList *resp_data = NULL;
	UserRequest *ur = NULL;
	TReturn result = TCORE_RETURN_FAILURE;

	dbg("Enter");

	ur = tcore_pending_ref_user_request(p);
	if (ur)
		req_buf = (struct treq_ss_forwarding *)tcore_user_request_ref_data(ur, 0);

	if (at_resp) {
		if (at_resp->lines && at_resp->success) {
			resp_data = (GSList *)at_resp->lines;
			resp.record_num = g_slist_length(resp_data);
			dbg("Total records: [%d]", resp.record_num);
		} else {
			err("RESPONSE - [NOK]");
			resp.err = SS_ERROR_UNKNOWNERROR;
		}
	} else {
		err("No response data");
	}

	if (req_buf) {
		if (resp.record_num > 0) {
		resp.record = g_try_malloc0(
			(resp.record_num) * sizeof(struct forwarding_info));
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

				if (atoi(status) == 1)
					resp.record[valid_records].status = SS_STATUS_ACTIVATE;
				else
					resp.record[valid_records].status = SS_STATUS_DEACTIVATE;

				classx_str = g_slist_nth_data(tokens, 1);
				if (!classx_str) {
					dbg("Class error. Setting to the requested class: [%d]", req_buf->class);
					resp.record[valid_records].class = req_buf->class;
				} else {
					if (__atmodem_ss_convert_modem_class_to_class(atoi(classx_str),
							&(resp.record[valid_records].class)) == FALSE) {
						tcore_at_tok_free(tokens);
						continue;
					}
				}

				number = g_slist_nth_data(tokens, 2);
				if (number)
					memcpy((resp.record[valid_records].number),
						number, strlen(number));

				time_str = g_slist_nth_data(tokens, 6);
				if (time_str)
					resp.record[valid_records].time = atoi(time_str);

				resp.record[valid_records].mode = req_buf->mode;

				result = TCORE_RETURN_SUCCESS;
				valid_records++;
			} else {
				err("Invalid response message");
			}
			tcore_at_tok_free(tokens);
			}
		}
	} else {
		err("req_buf is NULL");
	}

	dbg("Getting Forwarding Status: [%s]",
			(result == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));
	resp.record_num = valid_records;

	tcore_user_request_send_response(ur,
			TRESP_SS_FORWARDING_GET_STATUS,
			sizeof(struct tresp_ss_forwarding), &resp);
	g_free(resp.record);
}

static void on_response_atmodem_ss_set_waiting(TcorePending *p,
		int data_len, const void *data, void *user_data)
{
	struct tresp_ss_waiting resp = {0, };
	const struct treq_ss_waiting *req = NULL;
	struct ss_resp_cb_data *cb_data = user_data;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");
	ur = tcore_pending_ref_user_request(p);

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = SS_ERROR_NONE;

			req = tcore_user_request_ref_data(ur, NULL);
			resp.record_num = 1;
			resp.record = g_malloc0(sizeof(struct waiting_info) * resp.record_num);
			resp.record[0].class = req->class;
			if (cb_data->opco == TIZEN_SS_OPCO_ACTIVATE)
				resp.record[0].status = SS_STATUS_ACTIVATE;
			else
				resp.record[0].status = SS_STATUS_DEACTIVATE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = SS_ERROR_UNKNOWNERROR;
		}
	} else {
		err("No response data");
	}

	if (ur) {
		enum tcore_response_command resp_cmd;
		if (cb_data->opco == TIZEN_SS_OPCO_ACTIVATE)
			resp_cmd = TRESP_SS_WAITING_ACTIVATE;
		else
			resp_cmd = TRESP_SS_WAITING_DEACTIVATE;
		tcore_user_request_send_response(ur, resp_cmd,
			sizeof(struct tresp_ss_waiting), &resp);
	} else {
		err("ur is NULL");
	}

	g_free(resp.record);
	g_free(cb_data);
}

static void on_response_atmodem_ss_get_waiting_status(TcorePending *p,
		int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	struct tresp_ss_waiting waiting_resp = {0, };
	struct treq_ss_waiting *req_buf = NULL;
	int valid_records = 0;
	GSList *resp_data = NULL;
	UserRequest *ur = NULL;
	TReturn result = TCORE_RETURN_FAILURE;

	dbg("Enter");

	ur = tcore_pending_ref_user_request(p);
	if (ur)
		req_buf = (struct treq_ss_waiting *)tcore_user_request_ref_data(ur, 0);
	else
		err("User Request is NULL");

	if (at_resp) {
		if (at_resp->lines && at_resp->success) {
			resp_data = (GSList *)at_resp->lines;
			waiting_resp.record_num = g_slist_length(resp_data);
			dbg("Total records: [%d]", waiting_resp.record_num);
			waiting_resp.err = SS_ERROR_NONE;
		} else {
			err("RESPONSE - [NOK]");
			waiting_resp.err = SS_ERROR_UNKNOWNERROR;
		}
	} else {
		err("No response data");
	}

	if (req_buf) {
		if (waiting_resp.record_num > 0) {
			waiting_resp.record = g_try_malloc0(
				(waiting_resp.record_num) * sizeof(struct waiting_info));
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

					if (atoi(status) == 1)
						waiting_resp.record[valid_records].status = SS_STATUS_ACTIVATE;
					else
						waiting_resp.record[valid_records].status = SS_STATUS_DEACTIVATE;

					classx_str = g_slist_nth_data(tokens, 1);
					if (!classx_str) {
						dbg("Class error. Setting to the requested class: [%d]", req_buf->class);
						waiting_resp.record[valid_records].class = req_buf->class;
					} else {
						if (__atmodem_ss_convert_modem_class_to_class(atoi(classx_str),
								&(waiting_resp.record[valid_records].class)) == FALSE) {
							tcore_at_tok_free(tokens);
							continue;
						}
					}

					result = TCORE_RETURN_SUCCESS;
					valid_records++;
				} else {
					err("Invalid response message");
				}
				tcore_at_tok_free(tokens);
			}
		}
	}

	dbg("Getting Waiting Status: [%s]",
			(result == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));
	waiting_resp.record_num = valid_records;

	tcore_user_request_send_response(ur,
			TRESP_SS_WAITING_GET_STATUS,
			sizeof(struct tresp_ss_waiting), &waiting_resp);
	g_free(waiting_resp.record);
}

#ifdef EMUL_SUPPORTED
static void on_response_atmodem_ss_get_cli_status(TcorePending *p,
		int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	struct tresp_ss_cli cli_resp = {0, };
	struct treq_ss_cli *req_buf = NULL;
	UserRequest *ur = NULL;
	TReturn result = TCORE_RETURN_FAILURE;
	GSList *tokens = NULL;

	dbg("Enter");

	ur = tcore_pending_ref_user_request(p);
	if (ur)
		req_buf = (struct treq_ss_cli *)tcore_user_request_ref_data(ur, 0);

	if (req_buf->type == SS_CLI_TYPE_CDIP) {
		err("Unsupported CLI type: [%d]", req_buf->type);
		result = TCORE_RETURN_EINVAL;
		goto out;
	}

	if (at_resp && at_resp->success) {
		const gchar *line;

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
		/*
		 * TODO: Confirm Status Mapping and pass accordingly
		 */
		cli_resp.type = req_buf->type;
		result = TCORE_RETURN_SUCCESS;
	} else {
		err("RESPONSE NOK");
	}


	dbg("Getting CLI Status: [%s]",
			(result == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));

	tcore_user_request_send_response(ur,
			TRESP_SS_CLI_GET_STATUS,
			sizeof(struct tresp_ss_cli), &cli_resp);

out:
	tcore_at_tok_free(tokens);
}
#endif

#ifdef EMUL_SUPPORTED
static void on_response_atmodem_ss_send_ussd_request(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	struct tresp_ss_ussd ussd_resp = {0, };
	UssdSession *ussd_s = NULL;
	UserRequest *ur = NULL;
	CoreObject *co = NULL;

	dbg("Enter");

	co = tcore_pending_ref_core_object(p);

	ussd_s = tcore_ss_ussd_get_session(co);
	if (!ussd_s) {
		err("USSD Session not present");
		return;
	}

	if (at_resp && at_resp->success)
		ussd_resp.err = SS_ERROR_NONE;

	dbg("Send Ussd Request: [%s]",
		(ussd_resp.err == SS_ERROR_NONE ? "SUCCESS" : "FAIL"));

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		/*TODO : Map response and send accordingly*/
	tcore_user_request_send_response(ur,
			TRESP_SS_SEND_USSD,
			sizeof(struct tresp_ss_ussd), &ussd_resp);
	} else {
		err("UR is missing");
	}
	tcore_ss_ussd_destroy_session(ussd_s);

}
#endif

static TReturn _ss_barring_set(CoreObject *o, UserRequest *ur, enum telephony_ss_opcode op)
{
	gchar *at_cmd = NULL;
	struct treq_ss_barring *barring_info = NULL;
	struct ss_resp_cb_data *cb_data = NULL;
	guint mode;
	guint classx;
	const char *facility = NULL;
	char password[MAX_SS_BARRING_PASSWORD_LEN + 1];
	TReturn ret = TCORE_RETURN_FAILURE;

	barring_info =  (struct treq_ss_barring *)tcore_user_request_ref_data(ur, 0);

	if (op == TIZEN_SS_OPCO_ACTIVATE)
		mode = 1;
	else
		mode = 0;

	if (__atmodem_ss_convert_barring_type_to_facility(
			barring_info->mode, facility) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	classx = __atmodem_ss_convert_class_to_atmodem_class(barring_info->class);

	memcpy(password, barring_info->password, MAX_SS_BARRING_PASSWORD_LEN);
	password[MAX_SS_BARRING_PASSWORD_LEN] = '\0';

	dbg("facility: [%s], classx:[%d], mode: [%d]", facility, classx, mode);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\", %d",
		facility, mode, password, classx);
	dbg("request command : %s", at_cmd);

	/* Make resp_cb_data */
	cb_data = g_malloc0(sizeof(struct ss_resp_cb_data));
	cb_data->opco = op;

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_atmodem_ss_set_barring, cb_data,
		on_send_at_request, NULL, 0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS) {
		err("Request failed!!!");
		g_free(cb_data);
	}

	g_free(at_cmd);
	return ret;
}

static TReturn _ss_barring_get(CoreObject *o,
		UserRequest *ur,
		enum telephony_ss_class class,
		enum telephony_ss_barring_mode mode)
{
	gchar *at_cmd = NULL;
	guint classx;
	const char *facility = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	if (__atmodem_ss_convert_barring_type_to_facility(
		mode, facility) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	classx = __atmodem_ss_convert_class_to_atmodem_class(class);

	dbg("facility: [%s], classx:[%d], mode: [%d]", facility, classx, mode);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CLCK=\"%s\", %d, , %d",
			facility, mode, classx);
	dbg("request command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_SINGLELINE,
		ur,
		on_response_atmodem_ss_get_barring_status, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);
	return ret;
}

static TReturn s_ss_barring_activate(CoreObject *o, UserRequest *ur)
{
	return _ss_barring_set(o, ur, TIZEN_SS_OPCO_ACTIVATE);
}

static TReturn s_ss_barring_deactivate(CoreObject *o, UserRequest *ur)
{
	return _ss_barring_set(o, ur, TIZEN_SS_OPCO_DEACTIVATE);
}

#ifdef EMUL_SUPPORTED
static TReturn s_ss_barring_change_password(CoreObject *o, UserRequest *ur)
{
	gchar *at_cmd = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;
	struct treq_ss_barring_change_password *barring_info = 0;
	char old_password[MAX_SS_BARRING_PASSWORD_LEN + 1];
	char new_password[MAX_SS_BARRING_PASSWORD_LEN + 1];

	dbg("Entry");

	barring_info = (struct treq_ss_barring_change_password *)tcore_user_request_ref_data(ur, 0);

	memcpy(old_password, barring_info->password_old, MAX_SS_BARRING_PASSWORD_LEN);
	old_password[MAX_SS_BARRING_PASSWORD_LEN] = '\0';
	memcpy(new_password, barring_info->password_new, MAX_SS_BARRING_PASSWORD_LEN);
	new_password[MAX_SS_BARRING_PASSWORD_LEN] = '\0';

	dbg("old passwd - %s new passwd- %s", old_password, new_password);
	at_cmd = g_strdup_printf("AT+CPWD=\"%s\", \"%s\", \"%s\"", "AB", old_password, new_password);
	dbg("request command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_atmodem_ss_change_barring_password, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);

	return ret;
}
#endif

static TReturn s_ss_barring_get_status(CoreObject *o, UserRequest *ur)
{
	struct treq_ss_barring *barring_info = 0;
	barring_info = (struct treq_ss_barring *)tcore_user_request_ref_data(ur, 0);

	return _ss_barring_get(o, ur, barring_info->class, SS_BARR_MODE_BOIC);
}

static TReturn _ss_forwarding_set(CoreObject *o, UserRequest *ur, enum telephony_ss_opcode op)
{
	gchar *at_cmd = NULL;
	struct treq_ss_forwarding *forwarding_info = NULL;
	struct ss_resp_cb_data *cb_data = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *tmp_cmd = NULL;
	guint classx;
	guint reason;
	guint mode;
	guint num_type;

	dbg("Entry");

	forwarding_info = (struct treq_ss_forwarding *)tcore_user_request_ref_data(ur, 0);

	classx = __atmodem_ss_convert_class_to_atmodem_class(forwarding_info->class);
	if (__atmodem_ss_convert_forwarding_opcode_to_modem_mode(
			op, &mode) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	if (__atmodem_ss_convert_forwarding_mode_to_modem_reason(
			forwarding_info->mode, &reason) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	if (forwarding_info->number[0] == '+')
		num_type = 145;
	else
		num_type = 129;

	dbg("classx: [%d], reason:[%d], mode: [%d]", classx, reason, mode);

	if (mode == 3)	/* TIZEN_SS_OPCO_REGISTER */
		tmp_cmd = g_strdup_printf("AT+CCFC=%d, %d, \"%s\", %d, %d",
			reason, mode, forwarding_info->number, num_type, classx);
	else
		tmp_cmd = g_strdup_printf("AT+CCFC=%d, %d, , , %d",
			reason, mode, classx);

	if (reason == 2)	/* SS_CF_MODE_CFNRy */
		at_cmd = g_strdup_printf("%s, , , %d", tmp_cmd, forwarding_info->time);
	else
		at_cmd = g_strdup_printf("%s", tmp_cmd);
	dbg("request command : %s", at_cmd);

	/* Make resp_cb_data */
	cb_data = g_malloc0(sizeof(struct ss_resp_cb_data));
	cb_data->opco = op;

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_atmodem_ss_set_forwarding, cb_data,
		on_send_at_request, NULL, 0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS) {
		err("Request failed!!!");
		g_free(cb_data);
	}

	g_free(at_cmd);
	g_free(tmp_cmd);
	return ret;
}

static TReturn _ss_forwarding_get(CoreObject *o,
		UserRequest *ur,
		enum telephony_ss_class class,
		enum telephony_ss_forwarding_mode mode)
{
	gchar *at_cmd = NULL;
	guint classx;
	guint reason;
	guint query_mode = 2; /* query status */
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	classx = __atmodem_ss_convert_class_to_atmodem_class(class);

	if (__atmodem_ss_convert_forwarding_mode_to_modem_reason(
			mode, &reason) == FALSE) {
		err("Invalid arguments");
		return ret;
	}

	dbg("classx: [%d], reason: [%d], mode: [%d]", classx, reason, query_mode);

	at_cmd = g_strdup_printf("AT+CCFC=%d, %d, , , %d", reason, query_mode, classx);
	dbg("request command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_SINGLELINE,
		ur,
		on_response_atmodem_ss_get_forwarding_status, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);

	return ret;
}

static TReturn s_ss_forwarding_activate(CoreObject *o, UserRequest *ur)
{
	return _ss_forwarding_set(o, ur, TIZEN_SS_OPCO_ACTIVATE);
}

static TReturn s_ss_forwarding_deactivate(CoreObject *o, UserRequest *ur)
{
	return _ss_forwarding_set(o, ur, TIZEN_SS_OPCO_DEACTIVATE);
}

static TReturn s_ss_forwarding_register(CoreObject *o, UserRequest *ur)
{
	return _ss_forwarding_set(o, ur, TIZEN_SS_OPCO_REG);
}

static TReturn s_ss_forwarding_deregister(CoreObject *o, UserRequest *ur)
{
	return _ss_forwarding_set(o, ur, TIZEN_SS_OPCO_DEREG);
}

static TReturn s_ss_forwarding_get_status(CoreObject *o, UserRequest *ur)
{
	struct treq_ss_forwarding *forwarding_info = 0;
	forwarding_info = (struct treq_ss_forwarding *)tcore_user_request_ref_data(ur, 0);

	return _ss_forwarding_get(o, ur, forwarding_info->class, forwarding_info->mode);
}

static TReturn _ss_waiting_set(CoreObject *o, UserRequest *ur, enum telephony_ss_opcode opco)
{
	gchar *at_cmd = NULL;
	struct treq_ss_waiting *waiting_info = 0;
	struct ss_resp_cb_data *cb_data = NULL;
	guint classx;
	guint mode;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	waiting_info = (struct treq_ss_waiting *)tcore_user_request_ref_data(ur, 0);

	if (opco ==  TIZEN_SS_OPCO_ACTIVATE)
		mode = 1;
	else
		mode = 0;

	classx = __atmodem_ss_convert_class_to_atmodem_class(waiting_info->class);
	dbg("mode: [%d], class: [%d]", mode, classx);

	at_cmd = g_strdup_printf("AT+CCWA=1, %d, %d", mode, classx);
	dbg("request command : %s", at_cmd);

	/* Make resp_cb_data */
	cb_data = g_malloc0(sizeof(struct ss_resp_cb_data));
	cb_data->opco = opco;

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_atmodem_ss_set_waiting, cb_data,
		on_send_at_request, NULL, 0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS) {
		err("Request failed!!!");
		g_free(cb_data);
	}

	g_free(at_cmd);
	return ret;
}

static TReturn _ss_waiting_get(CoreObject *o,
		UserRequest *ur,
		enum telephony_ss_class class)
{
	gchar *at_cmd = NULL;
	guint classx;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	classx = __atmodem_ss_convert_class_to_atmodem_class(class);
	dbg("class: [%d]", classx);

	at_cmd = g_strdup_printf("AT+CCWA=1, 2, %d", classx);
	dbg("request command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_SINGLELINE,
		ur,
		on_response_atmodem_ss_get_waiting_status, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);

	return ret;
}

static TReturn s_ss_waiting_activate(CoreObject *o, UserRequest *ur)
{
	return _ss_waiting_set(o, ur, TIZEN_SS_OPCO_ACTIVATE);
}

static TReturn s_ss_waiting_deactivate(CoreObject *o, UserRequest *ur)
{
	return _ss_waiting_set(o, ur, TIZEN_SS_OPCO_DEACTIVATE);
}

static TReturn s_ss_waiting_get_status(CoreObject *o, UserRequest *ur)
{
	struct treq_ss_waiting *waiting = 0;
	waiting = (struct treq_ss_waiting *)tcore_user_request_ref_data(ur, 0);

	return _ss_waiting_get(o, ur, waiting->class);
}

#ifdef EMUL_SUPPORTED
static TReturn s_ss_cli_get_status(CoreObject *o, UserRequest *ur)
{
	gchar *at_cmd = NULL;
	gchar *cmd_prefix = NULL;
	struct treq_ss_cli *cli_info = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	cli_info = (struct treq_ss_cli *)tcore_user_request_ref_data(ur, 0);

	switch (cli_info->type) {
	case SS_CLI_TYPE_CLIR:
		cmd_prefix = "+CLIR";
	break;

	case SS_CLI_TYPE_CLIP:
		cmd_prefix = "+CLIP";
	break;

	case SS_CLI_TYPE_COLP:
		cmd_prefix = "+COLP";
	break;

	case SS_CLI_TYPE_COLR:
		cmd_prefix = "+COLR";
	break;

	case SS_CLI_TYPE_CNAP:
		cmd_prefix = "+CNAP";
	break;

	case SS_CLI_TYPE_CDIP:
	default:
		dbg("Unsupported CLI type: [%d]", cli_info->type);
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("AT%s?", cmd_prefix);
	dbg("request command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_SINGLELINE,
		ur,
		on_response_atmodem_ss_get_cli_status, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);

	return ret;
}
#endif

#ifdef EMUL_SUPPORTED
static TReturn s_ss_send_ussd(CoreObject *o, UserRequest *ur)
{
	UssdSession *ussd_s = 0;
	gchar *at_cmd = NULL;
	struct treq_ss_ussd *ussd = 0;
	TReturn ret = TCORE_RETURN_FAILURE;

	ussd = (struct treq_ss_ussd *)tcore_user_request_ref_data(ur, 0);

	ussd_s = tcore_ss_ussd_get_session(o);
	if (!ussd_s) {
		dbg("USSD session does not exist");
		tcore_ss_ussd_create_session(o, (enum tcore_ss_ussd_type)ussd->type,
			(void *)tcore_user_request_ref(ur), 0);
	} else {

		if (ussd->type == SS_USSD_TYPE_USER_INITIATED) {
			err("ussd session is already exist");

			g_free(ussd_s);
			return TCORE_RETURN_FAILURE;
		}

		tcore_ss_ussd_set_session_type(ussd_s, (enum tcore_ss_ussd_type)ussd->type);
	}

	at_cmd = g_strdup_printf("AT+CUSD=1, \"%s\", %d", ussd->str, 0x0f);
	dbg("request command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_atmodem_ss_send_ussd_request, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);

	return ret;

}
#endif

static struct tcore_ss_operations ss_ops = {
	.barring_activate = s_ss_barring_activate,
	.barring_deactivate = s_ss_barring_deactivate,
	.barring_change_password = NULL,
	.barring_get_status = s_ss_barring_get_status,
	.forwarding_activate = s_ss_forwarding_activate,
	.forwarding_deactivate = s_ss_forwarding_deactivate,
	.forwarding_register = s_ss_forwarding_register,
	.forwarding_deregister = s_ss_forwarding_deregister,
	.forwarding_get_status = s_ss_forwarding_get_status,
	.waiting_activate = s_ss_waiting_activate,
	.waiting_deactivate = s_ss_waiting_deactivate,
	.waiting_get_status = s_ss_waiting_get_status,
	.cli_activate = NULL,
	.cli_deactivate = NULL,
	.cli_get_status = NULL,
	.send_ussd = NULL,
};

gboolean s_ss_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *so = 0;

	dbg("s_ss_init()");

	so = tcore_ss_new(p, "ss", &ss_ops, h);
	if (!so) {
		err("[error] ss_new()");
		return FALSE;
	}

/*	tcore_object_add_callback(so, EVENT_SS_INFO, on_notification_ss_info, 0); */
	tcore_object_add_callback(so, "+CUSD:", on_notification_ss_ussd, 0);

	return TRUE;
}

void s_ss_exit(TcorePlugin *p)
{
	CoreObject *o;
	struct property_network_info *data;

	o = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SS);

	data = tcore_plugin_ref_property(p, "SS");
	if (data)
		g_free(data);

	tcore_ss_free(o);
}
