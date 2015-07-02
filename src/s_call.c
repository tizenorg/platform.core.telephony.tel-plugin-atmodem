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
#include <storage.h>
#include <co_call.h>
#include <user_request.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
#include "s_call.h"

static int __call_convert_handle_to_call_id(CoreObject *o, int handle)
{
	CallObject *co = NULL;
	co = tcore_call_object_find_by_handle(o, handle);

	if (co == NULL) {
		err("CallObject with handle %d not found", handle);
		return -1;
	}
	return tcore_call_object_get_id(co);
}

static enum tcore_call_status _call_status(unsigned int status)
{
	switch (status) {
	case 0:
		return TCORE_CALL_STATUS_ACTIVE;

	case 1:
		return TCORE_CALL_STATUS_HELD;

	case 2:
		return TCORE_CALL_STATUS_DIALING;

	case 3:
		return TCORE_CALL_STATUS_ALERT;

	case 4:
		return TCORE_CALL_STATUS_INCOMING;

	case 5:
		return TCORE_CALL_STATUS_WAITING;

	case 6:
		return TCORE_CALL_STATUS_DIALING; /* connecting not exist. set to dialing */

	case 7:
		return TCORE_CALL_STATUS_IDLE;

	default:
		return TCORE_CALL_STATUS_IDLE;
	}

	return TCORE_CALL_STATUS_IDLE;
}

static enum tcore_call_type _call_type(int type)
{
	switch (type) {
	case 0:
		return TCORE_CALL_TYPE_VOICE;

	case 1:
		return TCORE_CALL_TYPE_VIDEO;

	default:
	break;
	}

	err("invalid call type, returing default call type as voice");
	return TCORE_CALL_TYPE_VOICE;
}

static void _call_branch_by_status(CoreObject *co,
	CallObject *call_obj, enum tcore_call_status call_state)
{
	guint call_handle;
	enum tcore_call_type call_type;
	enum tcore_call_status state;
	TcorePlugin *p = tcore_object_ref_plugin(co);

	state = tcore_call_object_get_status(call_obj);

	dbg("Call State - Present : [%d] New: [%d]", state, call_state);
	if (call_state == state) {
		dbg("No change in Call State...");
		return;
	}

	call_type = tcore_call_object_get_type(call_obj);
	call_handle = tcore_call_object_get_handle(call_obj);

	/* Update Call status */
	tcore_call_object_set_status(call_obj, call_state);

	if (call_type == TCORE_CALL_TYPE_VOICE) {	/* Voice call notification */
		switch (call_state) {
		case TCORE_CALL_STATUS_ACTIVE: {
			struct tnoti_call_status_active data = {0, };

			data.type = call_type;
			data.handle = call_handle;

			/* Send notification */
			tcore_server_send_notification(tcore_plugin_ref_server(p), co,
				TNOTI_CALL_STATUS_ACTIVE,
				sizeof(struct tnoti_call_status_active), &data);
		}
		break;

		case TCORE_CALL_STATUS_HELD: {
			struct tnoti_call_status_held data = {0, };

			data.type = call_type;
			data.handle = call_handle;

			/* Send notification */
			tcore_server_send_notification(tcore_plugin_ref_server(p), co,
				TNOTI_CALL_STATUS_HELD,
				sizeof(struct tnoti_call_status_held), &data);
		}
		break;

		case TCORE_CALL_STATUS_DIALING: {
			struct tnoti_call_status_dialing data = {0, };

			data.type = call_type;
			data.handle = call_handle;

			/* Send notification */
			tcore_server_send_notification(tcore_plugin_ref_server(p), co,
				TNOTI_CALL_STATUS_DIALING,
				sizeof(struct tnoti_call_status_dialing), &data);
		}
		break;

		case TCORE_CALL_STATUS_ALERT: {
			struct tnoti_call_status_alert data = {0, };

			data.type = call_type;
			data.handle = call_handle;

			/* Send notification */
			tcore_server_send_notification(tcore_plugin_ref_server(p), co,
				TNOTI_CALL_STATUS_ALERT,
				sizeof(struct tnoti_call_status_alert), &data);
		}
		break;

		case TCORE_CALL_STATUS_INCOMING:
		case TCORE_CALL_STATUS_WAITING: {
			struct tnoti_call_status_incoming data = {0, };

			data.type = call_type;
			data.handle = call_handle;
			tcore_call_object_get_number(call_obj, data.cli.number);
			data.cli.mode = tcore_call_object_get_cli_mode(call_obj);
			data.cna.mode = tcore_call_object_get_cna_mode(call_obj);
			tcore_call_object_get_name(call_obj, data.cna.name);
			data.forward = FALSE;
			data.active_line = tcore_call_object_get_active_line(call_obj);

			/* Send notification */
			tcore_server_send_notification(tcore_plugin_ref_server(p), co,
				TNOTI_CALL_STATUS_INCOMING,
				sizeof(struct tnoti_call_status_incoming), &data);
		}
		break;

		case TCORE_CALL_STATUS_IDLE: {
			struct tnoti_call_status_idle idle;

			idle.handle = call_handle;
			/* TODO - get proper call end cause. */
			idle.cause = CALL_END_CAUSE_NONE;
			idle.type = TCORE_CALL_TYPE_VOICE;

			/* Send notification */
			tcore_server_send_notification(tcore_plugin_ref_server(p), co,
				TNOTI_CALL_STATUS_IDLE,
				sizeof(struct tnoti_call_status_idle), &idle);

			/* Free Call object */
			tcore_call_object_free(co, call_obj);
		}
		break;

		default:
			/* Do nothing */
			dbg("Default case executed.");
		break;
		}
	} else {
		err("Unknown Call type: [%d]", call_type);
	}
}

static void _handle_call_get_call_list(CoreObject *co,
	gboolean flag, void *data)
{
	gint call_handle;
	gint direction;
	gint mode;
	enum tcore_call_status state;
	gint mpty;
	gint ton = 0;
	GSList *tokens = NULL;
	gchar *resp = NULL;
	gchar *line;
	gchar *num = NULL;
	gint num_type;
	gchar number[MAX_CALL_NUMBER_LEN + 1] = {0, };
	GSList *lines = data;
	CallObject *call_obj = NULL;

	 while (lines != NULL) {
		line = (gchar *)lines->data;
		/* point to next node */
		lines = lines->next;

		/* free previous tokens*/
		tcore_at_tok_free(tokens);

		tokens = tcore_at_tok_new(line);

		resp = g_slist_nth_data(tokens, 0);
		if (NULL == resp) {
			err("Invalid call_id");
			continue;
		}
		call_handle = atoi(resp);

		resp = g_slist_nth_data(tokens, 1);
		if (NULL == resp) {
			err("Invalid direction");
			continue;
		}
		direction = (atoi(resp) == 0) ? 1 : 0;

		resp = g_slist_nth_data(tokens, 2);
		if (NULL == resp) {
			err("Invalid state");
			continue;
		}
		state = _call_status(atoi(resp));

		resp = g_slist_nth_data(tokens, 3);
		if (NULL == resp) {
			err("Invalid mode");
			continue;
		}
		mode = _call_type(atoi(resp));

		resp = g_slist_nth_data(tokens, 4);
		if (NULL == resp) {
			err("Invalid mpty");
			continue;
		}
		mpty = atoi(resp);

		resp = g_slist_nth_data(tokens, 5);
		if (NULL == resp) {
			err("Number is NULL");
		} else {
			/* Strike off double quotes */
			num = tcore_at_tok_extract(resp);
			dbg("Number: [%s]", num);

			resp = g_slist_nth_data(tokens, 6);
			if (!resp) {
				err("Invalid Number type");
			} else {
				num_type = atoi(resp);

				/* Check if number is International or National */
				ton = ((num_type) >> 4) & 0x07;
				if (num) {
					if (ton == 1 && num[0] != '+') {
						/* International number */
						number[0] = '+';
						memcpy(&number[1], num, strlen(num));
					} else {
						memcpy(number, num, strlen(num));
					}
				}
			}
			g_free(num);
		}

		dbg("Call Handle: [%d] Direction: [%s] Call Type: [%d] " \
			"Multi-party: [%s] Number: [%s] Type-of-Number: [%d] State: [%d]", \
			call_handle, (direction ? "Outgoing" : "Incoming"),
			mode, (mpty ? "YES" : "NO"), number, ton, state);

		call_obj = tcore_call_object_find_by_handle(co, call_handle);
		if (NULL == call_obj) {
			call_obj = tcore_call_object_new(co);
			if (NULL == call_obj) {
				err("Unable to create call object");
				continue;
			}
		}

		/* Set Call parameters */
		tcore_call_object_set_type(call_obj, mode);
		tcore_call_object_set_direction(call_obj, direction);
		tcore_call_object_set_multiparty_state(call_obj, mpty);
		if (number[0] != '\0')
			tcore_call_object_set_cli_info(call_obj,
				TCORE_CALL_CLI_MODE_PRESENT, TCORE_CALL_NO_CLI_CAUSE_NONE, number, strlen(number));
		else
			tcore_call_object_set_cli_info(call_obj,
				TCORE_CALL_CLI_MODE_UNAVAILABLE, TCORE_CALL_NO_CLI_CAUSE_UNAVAILABLE, number, strlen(number));
		tcore_call_object_set_active_line(call_obj, 0);

		if (flag == TRUE)
			_call_branch_by_status(co, call_obj, state);
		else
			tcore_call_object_set_status(call_obj, state);
	}
}

static void _on_response_call_get_call_list(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	GSList *lines = NULL;
	gint count;
	gboolean *flag = NULL;

	dbg("Entry");

	if (co == NULL) {
		err("co missing.");
		return;
	}

	flag = (gboolean *)user_data;

	if (at_resp && at_resp->success) {
		if (NULL == at_resp->lines) {
			err("invalid response received");
			return;
		}

		lines = (GSList *)at_resp->lines;
		count = g_slist_length(lines);
		dbg("Total records : %d", g_slist_length(lines));
		if (0 == count) {
			err("Call count is zero");
			return;
		}

		dbg("RESPONSE OK");

		/* Process +CLCC notification parameter */
		_handle_call_get_call_list(co, *flag, lines);
	} else {
		err("RESPONSE NOK");
	}
}

static int _call_get_call_list(CoreObject *co, gboolean flag)
{
	gboolean *data = NULL;
	guint ret = -1;
	dbg("Entry");

	if (NULL == co) {
		err("Core Object is NULL");
		return ret;
	}
	/* Response callback data */
	data = g_try_malloc(sizeof(flag));
	if (data == NULL) {
		err("Memory allocation failed!!");
		return ret;
	}

	*data = flag;

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co,
		"AT+CLCC", "+CLCC",
		TCORE_AT_MULTILINE,
		NULL,
		_on_response_call_get_call_list, data,
		NULL, NULL, 0, NULL, NULL);

	return ret;
}


/* NOTIFICATION */
static void __on_notification_call_incoming(CoreObject *co,
	guint call_id, const void *data)
{
	GSList *list = NULL;
	GSList *tokens = NULL;
	gchar *resp = NULL;
	gchar *line;
	gboolean direction = TRUE;
	gint mode;
	gpointer state;
	enum tcore_call_status call_state;
	gint mpty;
	gint ton = 0;
	gchar *num = NULL;
	gchar number[MAX_CALL_NUMBER_LEN + 1] = {0, };
	GSList *lines = (GSList *)data;
	CallObject *call_obj = NULL;

	dbg("Entry");

	/* Check call with 'Incoming' status already exist */
	list = tcore_call_object_find_by_status(co, TCORE_CALL_STATUS_INCOMING);
	if (list != NULL) {
		err("Incoming Call already exist... Skip!!!");
		return;
	}

	call_obj = tcore_call_object_find_by_id(co, call_id);
	if (call_obj != NULL) {
		err("co with same id already exist. skip");
		return;
	}

	/* Create Call object */
	call_obj = tcore_call_object_new(co);
	if (NULL == call_obj) {
		err(" Unable to create call object");
		return;
	}
	tcore_call_object_set_id(call_obj, call_id);

	lines = (GSList *)data;
	if (lines == NULL) {
		err("Invalid response received");
		return;
	}

	line = (gchar *)lines->data;

	/* Tokenize */
	tokens = tcore_at_tok_new(line);

	state = g_slist_nth_data(tokens, 2);
	if (NULL == state) {
		err("State is missing");
		goto out;
	}
	call_state = _call_status(atoi(state));

	resp = g_slist_nth_data(tokens, 3);
	if (NULL == resp) {
		err("Invalid mode");
		goto out;
	}
	mode = _call_type(atoi(resp));

	resp = g_slist_nth_data(tokens, 4);
	if (NULL == resp) {
		err("Invalid mpty");
		goto out;
	}
	mpty = atoi(resp);

	resp = g_slist_nth_data(tokens, 5);
	if (NULL == resp) {
		err("Number is NULL");
	} else {
		/* Strike off double quotes */
		num = tcore_at_tok_extract(resp);
		if (num) {
			dbg("Number: [%s]", num);
			memcpy(number, num, strlen(num));
			number[strlen(num)] = '\0';
			g_free(num);
		}
	}

	dbg("Call ID: [%d] Direction: [%s] Call Type: [%d] " \
		"Multi-party: [%s] Number: [%s] Type-of-Number: [%d] State: [%d]", \
		call_id, (direction ? "Outgoing" : "Incoming"),
		mode, (mpty ? "YES" : "NO"), number, ton, call_state);	/* Set Call parameters */

	/* Update Call Object */
	tcore_call_object_set_type(call_obj, mode);
	tcore_call_object_set_direction(call_obj, TCORE_CALL_DIRECTION_INCOMING);
	tcore_call_object_set_multiparty_state(call_obj, mpty);
	if (number[0] != '\0')
		tcore_call_object_set_cli_info(call_obj,
			TCORE_CALL_CLI_MODE_PRESENT, TCORE_CALL_NO_CLI_CAUSE_NONE, number, strlen(number));
	else
		tcore_call_object_set_cli_info(call_obj,
			TCORE_CALL_CLI_MODE_UNAVAILABLE, TCORE_CALL_NO_CLI_CAUSE_UNAVAILABLE, number,  strlen(number));
	tcore_call_object_set_active_line(call_obj, 0);

	/* Send notification */
	_call_branch_by_status(co, call_obj, call_state);

out:
	/* Free tokens */
	tcore_at_tok_free(tokens);
}

static void __on_notification_call_status(CoreObject *co,
	guint call_id, enum tcore_call_status call_state)
{
	CallObject *call_obj = NULL;

	dbg("call_state = %d", call_state);

	switch (call_state) {
	case TCORE_CALL_STATUS_ACTIVE:
	{
		int prev_status;

		dbg("TCORE_CALL_STATUS_ACTIVE");
		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (call_obj == NULL) {
			err("Unable to find Call Object - Call ID: [%d]", call_id);
			return;
		}
		/*
		* Active / Held status notification will be handled in _call_get_call_list().
		* Because of timing issue, we should not notifity this event before updating call info.
		* One exception is that we will send this event when active status is receviced during dialing or incoming.
		*/
		prev_status = tcore_call_object_get_status(call_obj);
		if ((prev_status == TCORE_CALL_STATUS_DIALING)
			|| (prev_status == TCORE_CALL_STATUS_ALERT)
			|| (prev_status == TCORE_CALL_STATUS_INCOMING)
			|| (prev_status == TCORE_CALL_STATUS_WAITING)) {
			_call_branch_by_status(co, call_obj, call_state);
		}
	}
	break;
	case TCORE_CALL_STATUS_HELD:{
		dbg("TCORE_CALL_STATUS_HELD");
		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (!call_obj) {
			call_obj = tcore_call_object_new(co);
			if (!call_obj) {
				err("Unable to create Call Object");
				return;
			}
			tcore_call_object_set_id(call_obj, call_id);
		}

		/*
		 * Make request to get current Call list.
		 * Then send notification to application
		 */
		_call_get_call_list(co, TRUE);
	}
	break;
	case TCORE_CALL_STATUS_ALERT:
	case TCORE_CALL_STATUS_IDLE: {
		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (call_obj == NULL) {
			err("Unable to find Call Object - Call ID: [%d]", call_id);
			return;
		}

		/* Send notification to application */
		_call_branch_by_status(co, call_obj, call_state);
	}
	break;

	case TCORE_CALL_STATUS_DIALING: {
		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (!call_obj) {
			call_obj = tcore_call_object_new(co);
			if (!call_obj) {
				err("Unable to create Call Object");
				return;
			}
			tcore_call_object_set_id(call_obj, call_id);
		}

		/*
		 * Make request to get current Call list.
		 * Update CallObject with <number>
		 * and send notification to application
		 */
		_call_get_call_list(co, TRUE);
	}
	break;

	default:
		err("Unhandled Call Status: [%d]", call_state);
	break;
	}
}

static gboolean on_notification_call_status(CoreObject *co,
	const void *data, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	const gchar *line = NULL;
	gchar *state = NULL, *call_handle = NULL;
	enum tcore_call_status status;
	guint call_id;

	dbg("Entry");

	lines = (GSList *)data;
	if (lines == NULL) {
		err("Invalid response received");
		return TRUE;
	}

	line = (gchar *)lines->data;

	/* Tokenize */
	tokens = tcore_at_tok_new(line);
	call_handle = g_slist_nth_data(tokens, 0);
	if (NULL == call_handle) {
		err("call_id missing");
		goto out;
	}
	call_id = atoi(call_handle);

	state = g_slist_nth_data(tokens, 2);
	if (NULL == state) {
		err("State is missing");
		goto out;
	}
	status = _call_status(atoi(state));

	dbg("Call ID: [%d] Call Status: [%d]", call_id, status);

	switch (status) {
	case TCORE_CALL_STATUS_INCOMING:
	case TCORE_CALL_STATUS_WAITING:
		dbg("Incoming/Waiting Call...");
		__on_notification_call_incoming(co, call_id, data);
	break;

	default:
		__on_notification_call_status(co, call_id, status);
	break;
	}

out:
	/* Free tokens */
	tcore_at_tok_free(tokens);
	return TRUE;
}

static gboolean on_notification_call_cssu_info(CoreObject *co,
	const void *event_data, void *user_data)
{
	GSList *tokens = NULL;
	enum tcore_notification_command command = TNOTI_UNKNOWN;
	gchar *resp = NULL;
	gchar *cmd = 0;
	gint local_index = 0;
	gint code2 = -1;
	gchar number[MAX_CALL_NUMBER_LEN + 1] = {'\0', };
	TcorePlugin *p = NULL;

	dbg("Entry");

	if (1 != g_slist_length((GSList *) event_data)) {
		err("unsolicited msg but multiple line");
		return TRUE;
	}

	cmd = (gchar *) ((GSList *) event_data)->data;
	dbg("ss notification message[%s]", cmd);

	tokens = tcore_at_tok_new(cmd);

	/* parse <code2> */
	resp = g_slist_nth_data(tokens, 0);
	if (NULL == resp) {
		err("Code2 is missing from %CSSU indiaction");
		tcore_at_tok_free(tokens);
		return TRUE;
	}
	code2 = atoi(resp);

	/* parse [ <index>, <number>] */
	if ((resp = g_slist_nth_data(tokens, 1)))
		local_index = atoi(resp);

	if ((resp = g_slist_nth_data(tokens, 2))) {
		resp = tcore_at_tok_extract((const gchar *)resp);
		if (resp) {
			memcpy(number, resp, strlen(resp));
			number[strlen(resp)] = '\0';;
			g_free(resp);
		}
	}
	dbg("+CSSU: <code2>: %d <index>: %d <number>: %s ", code2, local_index, number);

	/* <code2> - other values will be ignored */
	switch (code2) {
	case 0:
		command = TNOTI_CALL_INFO_FORWARDED;
	break;

	case 2:
		command = TNOTI_CALL_INFO_HELD;
	break;

	case 3:
		command = TNOTI_CALL_INFO_ACTIVE;
	break;

	case 4:
		command = TNOTI_CALL_INFO_JOINED;
	break;

	case 7:
	case 8:
		command = TNOTI_CALL_INFO_TRANSFERED_CALL;
	break;

	case 9:
		command = TNOTI_CALL_INFO_DEFLECTED;
	break;

	default:
		dbg("Unsupported +CSSU notification: [%d]", code2);
	break;
	}

	p = tcore_object_ref_plugin(co);

	if (command != TNOTI_UNKNOWN)
		tcore_server_send_notification(tcore_plugin_ref_server(p), co,
		command, 0, NULL);

	tcore_at_tok_free(tokens);
	return TRUE;
}

/* Response */
static void on_response_call_outgoing(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_dial resp = {0, };
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_CALL_DIAL,
			sizeof(struct tresp_call_dial), &resp);
	} else {
		err("ur is NULL");
	}
}

static void on_response_call_answer(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_answer resp = {0, };
	struct treq_call_answer *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_answer *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		tcore_user_request_send_response(ur,
			TRESP_CALL_ANSWER,
			sizeof(struct tresp_call_answer), &resp);
	} else {
		err("ur is NULL");
	}
}

static void on_response_call_release(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_end resp = {0, };
	struct treq_call_end *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_end *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		resp.type = req_buf->type;
		tcore_user_request_send_response(ur,
			TRESP_CALL_END,
			sizeof(struct tresp_call_end), &resp);
	} else {
		err("ur is NULL");
	}
}

static void on_response_call_hold(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_hold resp = {0, };
	struct treq_call_hold *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_hold *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		tcore_user_request_send_response(ur,
			TRESP_CALL_HOLD,
			sizeof(struct tresp_call_hold), &resp);
	} else {
		err("ur is NULL");
	}
}

static void on_response_call_active(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_active resp = {0, };
	struct treq_call_active *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;
	CoreObject *core_obj = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_active *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		tcore_user_request_send_response(ur,
			TRESP_CALL_ACTIVE,
			sizeof(struct tresp_call_active), &resp);
	} else {
		err("ur is NULL");
	}

	core_obj = tcore_pending_ref_core_object(p);
	_call_get_call_list(core_obj, TRUE);

}

static void on_response_call_swap(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_swap resp = {0, };
	struct treq_call_swap *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_swap *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		tcore_user_request_send_response(ur,
			TRESP_CALL_SWAP,
			sizeof(struct tresp_call_swap), &resp);
	} else {
		err("ur is NULL");
	}
}

static void on_response_call_join(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_join resp = {0, };
	struct treq_call_join *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;
	CoreObject *core_obj = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_join *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		tcore_user_request_send_response(ur,
			TRESP_CALL_JOIN,
			sizeof(struct tresp_call_join), &resp);
	} else {
		err("ur is NULL");
	}

	core_obj = tcore_pending_ref_core_object(p);
	_call_get_call_list(core_obj, TRUE);

}

static void on_response_call_split(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_split resp = {0, };
	struct treq_call_split *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_split *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		tcore_user_request_send_response(ur,
			TRESP_CALL_SPLIT,
			sizeof(struct tresp_call_split), &resp);
	} else {
		err("ur is NULL");
	}

}

static void on_response_call_deflect(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_deflect resp = {0, };
	struct treq_call_deflect *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_deflect *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		tcore_user_request_send_response(ur,
			TRESP_CALL_DEFLECT,
			sizeof(struct tresp_call_deflect), &resp);
	} else {
		err("ur is NULL");
	}
}

static void on_response_call_transfer(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_call_transfer resp = {0, };
	struct treq_call_transfer *req_buf = NULL;
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	if (at_resp) {
		if (at_resp->success) {
			dbg("Response: [OK]");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("Response: [NOK] - [%s]", at_resp->final_response);
			resp.err = CALL_ERROR_UNKNOWN;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
		}
	} else {
		err("No response data");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		req_buf = (struct treq_call_transfer *)tcore_user_request_ref_data(ur, 0);
		resp.handle = req_buf->handle;
		tcore_user_request_send_response(ur,
			TRESP_CALL_TRANSFER,
			sizeof(struct tresp_call_transfer), &resp);
	} else {
		err("ur is NULL");
	}
}

 /* Request */
static TReturn s_call_outgoing(CoreObject *o, UserRequest *ur)
{
	gchar *at_cmd;
	const gchar *clir;
	gchar *num;
	struct treq_call_dial *dial_info = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	dial_info = (struct treq_call_dial *)tcore_user_request_ref_data(ur, 0);

	if (dial_info->type == CALL_TYPE_VIDEO) {
		err("Video call is not supported in atmodem");
		return TCORE_RETURN_EPERM;
	}

	if (!strncmp(dial_info->number, "*31#", 4)) {
		dbg("clir suppression");
		clir = "i";
		num = (gchar *)&(dial_info->number[4]);
	} else if (!strncmp(dial_info->number, "#31#", 4)) {
		dbg("clir invocation");
		clir = "I";
		num = (gchar *)&(dial_info->number[4]);
	} else {
		dbg("set clir state to default");
		clir = "";
		num = (gchar *)dial_info->number;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("ATD%s%s;", num, clir);
	dbg(" at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_outgoing, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_answer(CoreObject *o, UserRequest *ur)
{
	gchar *at_cmd;
	struct treq_call_answer *ans_info = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	ans_info = (struct treq_call_answer *)tcore_user_request_ref_data(ur, 0);

	if (ans_info->type == CALL_ANSWER_TYPE_ACCEPT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "ATA");
	} else if (ans_info->type == CALL_ANSWER_TYPE_REJECT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=0");
	} else if (ans_info->type == CALL_ANSWER_TYPE_REPLACE) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=1");
	} else if (ans_info->type == CALL_ANSWER_TYPE_HOLD_ACCEPT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	} else {
		err("Unsupported call answer type");
		return ret;
	}

	/* AT-Command */
	dbg(" at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_answer, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_release(CoreObject *o, UserRequest *ur)
{
	gchar *at_cmd;
	struct treq_call_end *end_info = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;
	int call_id;

	dbg("Entry");

	end_info = (struct treq_call_end *)tcore_user_request_ref_data(ur, 0);

	call_id = __call_convert_handle_to_call_id(o, end_info->handle);

	if (end_info->type == CALL_END_TYPE_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "ATH");
	} else if (end_info->type == CALL_END_TYPE_DEFAULT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s%d", "AT+CHLD=1", call_id);
	} else if (end_info->type == CALL_END_TYPE_ACTIVE_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=1");
	} else if (end_info->type == CALL_END_TYPE_HOLD_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=0");
	} else {
		err("Unsupported call end type");
		return TCORE_RETURN_FAILURE;
	}

	/* AT-Command */
	dbg(" at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_release, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_hold(CoreObject *o, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *at_cmd;

	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_hold, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_active(CoreObject *o, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *at_cmd;

	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_active, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_swap(CoreObject *o, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *at_cmd;

	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_swap, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_join(CoreObject *o, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *at_cmd;

	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=3");
	dbg("at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_join, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_split(CoreObject *o, UserRequest *ur)
{
	gchar *at_cmd;
	struct treq_call_split *split_info = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;
	int call_id;

	dbg("Entry");

	split_info = (struct treq_call_split *)tcore_user_request_ref_data(ur, 0);
	call_id = __call_convert_handle_to_call_id(o, split_info->handle);

	at_cmd = g_strdup_printf("%s%d", "AT+CHLD=2", call_id);

	/* AT-Command */
	dbg(" at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_split, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_deflect(CoreObject *o, UserRequest *ur)
{
	gchar *at_cmd;
	struct treq_call_deflect *deflect_info = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	deflect_info = (struct treq_call_deflect *)tcore_user_request_ref_data(ur, 0);

	at_cmd = g_strdup_printf("AT+CTFR=%s", deflect_info->number);
	dbg("at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_deflect, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_call_transfer(CoreObject *o, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *at_cmd;

	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=4");
	dbg("at command : %s", at_cmd);

	ret = tcore_prepare_and_send_at_request(o, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_call_transfer, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn s_get_preferred_voice_subscription(CoreObject *o, UserRequest *ur)
{
	struct tresp_call_get_preferred_voice_subscription resp_data = {0, };
	TReturn ret = TCORE_RETURN_FAILURE;
	Server *server;
	Storage *strg = NULL;

	dbg("Entry");

	server = tcore_plugin_ref_server(tcore_object_ref_plugin(o));
	strg = tcore_server_find_storage(server, "vconf");

	/* VCONFKEY is aligned to resp_data->preferred_subs type */
	resp_data.preferred_subs = tcore_storage_get_int(strg, STORAGE_KEY_TELEPHONY_PREFERRED_VOICE_SUBSCRIPTION);
	dbg("Preferred Subscription: [%d]", resp_data.preferred_subs);

	resp_data.err = CALL_ERROR_NONE;
	/* Send Response */
	ret = tcore_user_request_send_response(ur,
		TRESP_CALL_GET_PREFERRED_VOICE_SUBSCRIPTION,
		sizeof(struct tresp_call_get_preferred_voice_subscription), &resp_data);

	dbg("ret: [0x%x]", ret);
	return ret;
}

/* Call Operations */
static struct tcore_call_operations call_ops = {
	.dial = s_call_outgoing,
	.answer = s_call_answer,
	.end = s_call_release,
	.hold = s_call_hold,
	.active = s_call_active,
	.swap = s_call_swap,
	.join = s_call_join,
	.split = s_call_split,
	.deflect = s_call_deflect,
	.transfer = s_call_transfer,
	.start_cont_dtmf = NULL,
	.stop_cont_dtmf = NULL,
	.send_burst_dtmf = NULL,
	.set_sound_path = NULL,
	.set_sound_volume_level = NULL,
	.get_sound_volume_level = NULL,
	.set_sound_mute_status = NULL,
	.get_sound_mute_status = NULL,
	.set_preferred_voice_subscription = NULL,
	.get_preferred_voice_subscription = s_get_preferred_voice_subscription,
};

gboolean s_call_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *o = NULL;

	dbg("entry");

	o = tcore_call_new(p, "call", &call_ops, h);
	if (!o)
		return FALSE;

	tcore_object_add_callback(o, "+SCLCC", on_notification_call_status, NULL);
	tcore_object_add_callback(o, "+CSSU:", on_notification_call_cssu_info, NULL);

	return TRUE;
}

void s_call_exit(TcorePlugin *p)
{
	CoreObject *o;

	o = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL);

	tcore_call_free(o);
}
