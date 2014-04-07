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

#include <co_call.h>

#include "atmodem_call.h"
#include "atmodem_common.h"

/* Call Status */
typedef enum {
	ATMODEM_CALL_STATUS_ACTIVE,
	ATMODEM_CALL_STATUS_HELD,
	ATMODEM_CALL_STATUS_DIALING,
	ATMODEM_CALL_STATUS_ALERT,
	ATMODEM_CALL_STATUS_INCOMING,
	ATMODEM_CALL_STATUS_WAITING,
	ATMODEM_CALL_STATUS_CONNECTING,
	ATMODEM_CALL_STATUS_DISCONNECTED,
	ATMODEM_CALL_STATUS_IDLE
} AtmodemCallStatus;

static void on_response_atmodem_call_default(TcorePending *p,
	guint data_len, const void *data, void *user_data);

static TelReturn __atmodem_call_get_call_list(CoreObject *co, gboolean flag);

static TelCallType __atmodem_call_type(gint type)
{
	dbg("Entry");

	switch (type) {
	case 0:
		return TEL_CALL_TYPE_VOICE;
	case 1:
		return TEL_CALL_TYPE_VIDEO;
	default:
		err("invalid call type, returing default call type as voice");
		return TEL_CALL_TYPE_VOICE;
	}
}

static TelCallState __atmodem_call_state(AtmodemCallStatus state)
{
	dbg("Entry");

	switch (state) {
	case ATMODEM_CALL_STATUS_ACTIVE:
		return TEL_CALL_STATE_ACTIVE;

	case ATMODEM_CALL_STATUS_HELD:
		return TEL_CALL_STATE_HELD;

	case ATMODEM_CALL_STATUS_DIALING:
		return TEL_CALL_STATE_DIALING;

	case ATMODEM_CALL_STATUS_ALERT:
		return TEL_CALL_STATE_ALERT;

	case ATMODEM_CALL_STATUS_INCOMING:
	case ATMODEM_CALL_STATUS_WAITING:
		return TEL_CALL_STATE_INCOMING;

	default:
		return TEL_CALL_STATE_IDLE;
	}
}

static void __atmodem_call_branch_by_status(CoreObject *co,
	CallObject *call_obj, TelCallState call_state)
{
	guint call_id;
	TelCallType call_type;
	TelCallState state;
	TcoreNotification command = TCORE_NOTIFICATION_UNKNOWN;

	if (tcore_call_object_get_state(call_obj, &state) == FALSE) {
		err("Unable to get Call status");
		return;
	}

	dbg("Call State - Present : [%d] New: [%d]", state, call_state);
	if (call_state == state) {
		dbg("No change in Call State...");
	  	return;
	}

	if (tcore_call_object_get_call_type(call_obj, &call_type) == FALSE) {
		err("Unable to get Call type");
		return;
	}

	if (tcore_call_object_get_id(call_obj, &call_id) == FALSE) {
		err("Unable to get Call id");
		return;
	}

	/* Update Call state */
	tcore_call_object_set_state(call_obj, call_state);

	if (call_type == TEL_CALL_TYPE_VOICE) {	/* Voice call notification */
		switch (call_state) {
		case TEL_CALL_STATE_ACTIVE:
			command = TCORE_NOTIFICATION_CALL_STATUS_ACTIVE;
		break;

		case TEL_CALL_STATE_HELD:
			command = TCORE_NOTIFICATION_CALL_STATUS_HELD;
		break;

		case TEL_CALL_STATE_DIALING:
			command = TCORE_NOTIFICATION_CALL_STATUS_DIALING;
			break;

		case TEL_CALL_STATE_ALERT:
			command = TCORE_NOTIFICATION_CALL_STATUS_ALERT;
		break;

		case TEL_CALL_STATE_INCOMING:
		case TEL_CALL_STATE_WAITING:
			command = TCORE_NOTIFICATION_CALL_STATUS_INCOMING;
		break;

		case TEL_CALL_STATE_IDLE: {
			TelCallStatusIdleNoti idle;

			idle.call_id = call_id;
			/* TODO - get proper call end cause. */
			idle.cause = TEL_CALL_END_CAUSE_NONE;

			/* Send notification */
			tcore_object_send_notification(co,
				TCORE_NOTIFICATION_CALL_STATUS_IDLE,
				sizeof(TelCallStatusIdleNoti), &idle);

			/* Free Call object */
			tcore_call_object_free(co, call_obj);

			return;
		}
		}
	} else {
		err("Unknown Call type: [%d]", call_type);
		return;
	}

	/* Send notification */
	tcore_object_send_notification(co,
		command, sizeof(call_id), &call_id);
}

static void __atmodem_handle_call_get_call_list(CoreObject *co,
	gboolean flag, void *data)
{
	gint call_id;
	gint direction;
	gint mode;
	gint state;
	gint mpty;
	gint ton;
	GSList *tokens = NULL;
	gchar *resp = NULL;
	gchar *line;
	gchar *num = NULL;
	gint num_type;
	gchar number[TEL_CALL_CALLING_NUMBER_LEN_MAX + 1] = {0, };
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

		call_id = atoi(resp);
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

		state = __atmodem_call_state(atoi(resp));
		resp = g_slist_nth_data(tokens, 3);
		if (NULL == resp) {
			err("Invalid mode");
			continue;
		}
		mode = __atmodem_call_type(atoi(resp));

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
				if (ton == 1 && num[0] != '+') {
					/* International number */
					number[0] = '+';
					memcpy(&number[1], num, strlen(num));
				} else {
					memcpy(number, num, strlen(num));
				}
			}
			g_free(num);
		}

		dbg("Call ID: [%d] Direction: [%s] Call Type: [%d] " \
			"Multi-party: [%s] Number: [%s] Type-of-Number: [%d] State: [%d]", \
			call_id, (direction ? "Outgoing" : "Incoming"),
			mode, (mpty ? "YES" : "NO"), number, ton, state);

		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (NULL == call_obj) {
			call_obj = tcore_call_object_new(co, call_id);
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
				TEL_CALL_CLI_VALIDITY_VALID, number);
		else
			tcore_call_object_set_cli_info(call_obj,
				TEL_CALL_CLI_VALIDITY_NOT_AVAILABLE, number);
		tcore_call_object_set_active_line(call_obj, TEL_CALL_ACTIVE_LINE1);
		if (flag == TRUE)
			__atmodem_call_branch_by_status(co, call_obj, state);
		else
			tcore_call_object_set_state(call_obj, state);
	}
}

/* Incoming Call notification */
static void __on_notification_atmodem_call_incoming(CoreObject *co,
	guint call_id, const void *data)
{
	GSList *list = NULL;
	GSList *tokens = NULL;
	gchar *resp = NULL;
	gchar *line;
	gboolean direction = TRUE;
	gint mode;
	gpointer state;
	gint call_state;
	gint mpty;
	gint ton;
	gchar *num = NULL;
	gchar number[TEL_CALL_CALLING_NUMBER_LEN_MAX + 1] = {0, };
	GSList *lines = (GSList *)data;
	CallObject *call_obj = NULL;

	dbg("Entry");

	/* Check call with 'Incoming' status already exist */
	list = tcore_call_object_find_by_status(co, TEL_CALL_STATE_INCOMING);
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
	call_obj = tcore_call_object_new(co, (guint)call_id);
	if (NULL == call_obj) {
		err(" Unable to create call object");
		return;
	}

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
	call_state = __atmodem_call_state(atoi(state));

	resp = g_slist_nth_data(tokens, 3);
	if (NULL == resp) {
		err("Invalid mode");
		goto out;
	}
	mode = __atmodem_call_type(atoi(resp));

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
		dbg("Number: [%s]", num);

		memcpy(number, num, strlen(num));
		number[strlen(num)] = '\0';
		g_free(num);
	}

	dbg("Call ID: [%d] Direction: [%s] Call Type: [%d] " \
		"Multi-party: [%s] Number: [%s] Type-of-Number: [%d] State: [%d]", \
		call_id, (direction ? "Outgoing" : "Incoming"),
		mode, (mpty ? "YES" : "NO"), number, ton, call_state);	/* Set Call parameters */

	/* Update Call Object */
	tcore_call_object_set_type(call_obj, mode);
	tcore_call_object_set_direction(call_obj, direction);
	tcore_call_object_set_multiparty_state(call_obj, mpty);
	if (number[0] != '\0')
		tcore_call_object_set_cli_info(call_obj,
			TEL_CALL_CLI_VALIDITY_VALID, number);
	else
		tcore_call_object_set_cli_info(call_obj,
			TEL_CALL_CLI_VALIDITY_NOT_AVAILABLE, number);
	tcore_call_object_set_active_line(call_obj, TEL_CALL_ACTIVE_LINE1);

	/* Send notification */
	__atmodem_call_branch_by_status(co, call_obj, call_state);

out:
	/* Free tokens */
	tcore_at_tok_free(tokens);
}

static void __on_notification_atmodem_call_status(CoreObject *co,
	guint call_id, AtmodemCallStatus call_state)
{
	CallObject *call_obj = NULL;
	TelCallState state;

	state = __atmodem_call_state(call_state);
	dbg("Call state [%d]", state);

	switch (state) {
	case TEL_CALL_STATE_ACTIVE:
	case TEL_CALL_STATE_HELD:
	case TEL_CALL_STATE_ALERT:
	case TEL_CALL_STATE_IDLE: {
		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (call_obj == NULL) {
			err("Unable to find Call Object - Call ID: [%d]", call_id);
			return;
		}

		/* Send notification to application */
		__atmodem_call_branch_by_status(co, call_obj, state);
	}
	break;

	case TEL_CALL_STATE_DIALING: {
		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (!call_obj) {
			call_obj = tcore_call_object_new(co, call_id);
			if (!call_obj) {
				err("Unable to create Call Object");
				return;
			}
		}

		/*
		 * Make request to get current Call list.
		 * Update CallObject with <number>
		 * and send notification to application
		 */
		__atmodem_call_get_call_list(co, TRUE);
	}
	break;

	default:
		err("Unhandled Call Status: [%d]", state);
	break;
	}
}

/* Internal response operation */
static void __on_response_atmodem_call_get_call_list(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	GSList *lines = NULL;
	TelCallResult result = TEL_CALL_RESULT_FAILURE; //TODO - CME error mapping required
	gboolean *flag = ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	gint count;
	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_CALL_RESULT_SUCCESS;
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
		__atmodem_handle_call_get_call_list(co, *flag, lines);

	} else {
		err("RESPONSE NOK");
	}

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

/*internal request operation */
static TelReturn __atmodem_send_call_request(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data,
	gchar *at_cmd, gchar *func_name)
{
	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, func_name, strlen(func_name) + 1);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_atmodem_call_default, resp_cb_data,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, func_name);

	/* Free resources */
	g_free(at_cmd);
	return ret;
}

 /*
 * Operation -  Get current call list.
 *
 * Request -
 * AT-Command: AT+CLCC
 *
 * Response -
 * Success:
 *[+CLCC: <id1>, <dir>, <stat>, <mode>,<mpty>[,<number>,<type>[,<alpha>[,<priority>]]]
 *[<CR><LF> +CLCC: <id2>,<dir>,<stat>,<mode>,<mpty>[,<number>,<type>[,<alpha>[,<priority>]]][…]]]
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn __atmodem_call_get_call_list(CoreObject *co, gboolean flag)
{
	AtmodemRespCbData *resp_cb_data;
	TelReturn ret =TEL_RETURN_FAILURE;
	dbg("Entry");

	if (NULL == co) {
		err("Core Object is NULL");
		return ret;
	}
	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(NULL, NULL, &flag, sizeof(gboolean));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+CLCC","+CLCC",
		TCORE_AT_COMMAND_TYPE_MULTILINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		__on_response_atmodem_call_get_call_list, resp_cb_data,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get current call list");

	return ret;
}

/* Notification */
/*
* Operation -  call status notification from network.
* notification message format:
* %SCLCC: <call_id><direction><status><type><mpty>
* where
* <call_id>
* indicates the call identification.
* <direction>
* indicates call direction (MO or MT)
* <status>
* 0 active
* 1 hold
* 2 dialling (MO call)
* 3 alerting (MO call; ringing for the remote party)
* 4 ringing (MT call)
* 5 waiting (MT call)
* 6 connecting (MO call)
* 7 disconneted
* <type>
* call type
* <mpty>
* multiparty call
*
*/
static gboolean on_notification_atmodem_call_status(CoreObject *co,
	const void *data, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	const gchar *line = NULL;
	gchar *state = NULL, *call_handle = NULL;
	AtmodemCallStatus status;
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
	status = atoi(state);

	dbg("Call ID: [%d] Call Status: [%d]", call_id, status);

	switch (status) {
	case ATMODEM_CALL_STATUS_INCOMING:
	case ATMODEM_CALL_STATUS_WAITING:
		dbg("Incoming/Waiting Call...");
		__on_notification_atmodem_call_incoming(co, call_id, data);
	break;

	default:
		__on_notification_atmodem_call_status(co, call_id, status);
	break;
	}

out:
	/* Free tokens */
	tcore_at_tok_free(tokens);
	return TRUE;
}

/*
 * Operation -  SS network initiated notification.
 *
 * notification message format:
 * +CSSU: <code2>[<index> [,<number>,<type>]]
 * <code2>
 * (it is manufacturer specific, which of these codes are supported):
 * 0 this is a forwarded call (MT call setup)
 * 1 this is a CUG call (<index> present) (MT call setup)
 * 2 call has been put on hold (during a voice call)
 * 3 call has been retrieved (during a voice call)
 * 4 multiparty call entered (during a voice call)
 * 5 Call has been released - not a SS notification (during a voice call)
 * 6 forward check SS message received (can be received whenever)
 * 7 call is being connected (alerting) with the remote party in alerting state
 *   in explicit call transfer operation
 *   (during a voice call)
 * 8 call has been connected with the other remote party in explicit call transfer
 *   operation (during a voice call or MT call setup)
 * 9 this is a deflected call (MT call setup)
 * 10 additional incoming call forwarded
 * <index>
 * refer Closed user group +CCUG
 * <number>
 *  string type phone of format specified by <type>
 * <type>
 * type of address octet in integer format.
 */
static gboolean on_notification_atmodem_call_ss_cssu_info(CoreObject *co,
	const void *event_data, void *user_data)
{
	GSList *tokens = NULL;
	TcoreNotification command = TCORE_NOTIFICATION_UNKNOWN;
	gchar *resp = NULL;
	gchar *cmd = 0;
	gint index = 0;
	gint code2 = -1;
	gchar number[TEL_CALL_CALLING_NUMBER_LEN_MAX + 1] = {'\0',};

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
		index = atoi(resp);

	if ((resp = g_slist_nth_data(tokens, 2))) {
		resp = tcore_at_tok_extract((const gchar *)resp);
		memcpy(number, resp, strlen(resp));
		number[strlen(resp)] = '\0';;
		g_free(resp);
	}
	dbg("+CSSU: <code2>: %d <index>: %d <number>: %s ", code2, index, number);

 	/* <code2> - other values will be ignored */
	switch (code2) {
	case 0:
		command = TCORE_NOTIFICATION_CALL_INFO_MT_FORWARDED;
	break;

	case 2:
		command = TCORE_NOTIFICATION_CALL_INFO_HELD;
	break;

	case 3:
		command = TCORE_NOTIFICATION_CALL_INFO_ACTIVE;
	break;

	case 4:
		command = TCORE_NOTIFICATION_CALL_INFO_JOINED;
	break;

	case 7:
	case 8:
		command = TCORE_NOTIFICATION_CALL_INFO_TRANSFERED;
	break;

	case 9:
		command = TCORE_NOTIFICATION_CALL_INFO_MT_DEFLECTED;
	break;

	default:
		dbg("Unsupported +CSSU notification: [%d]", code2);
	break;
	}

	if (command != TCORE_NOTIFICATION_UNKNOWN)
		tcore_object_send_notification(co, command, 0, NULL);

	tcore_at_tok_free(tokens);
	return TRUE;
}

/* Response */
static void on_response_atmodem_call_default(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;

	TelCallResult result;
	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_CALL_RESULT_SUCCESS;
	} else {
		err("ERROR: [%s]", at_resp->final_response);
		result = TEL_CALL_RESULT_FAILURE;
		/*
		 * TODO -
		 * need to map CME error and final response
		 * error to TelCallResult
		 */
	}
	dbg("%s: [%s]", ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data),
		 (result == TEL_CALL_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

 /* Request */
 /*
 * Operation - dial
 *
 * Request -
 * AT-Command: ATD <num> [I] [G] [;]
 * <num> - dialed number
 * [I][i] - CLI presentation(supression or invocation)
 * [G] - control the CUG supplementary service information for this call.
 *
 * Response -
 * Success:
 * OK or CONNECT
 * Failure:
 * "ERROR"
 * "NO ANSWER"
 * "NO CARRIER"
 * "BUSY"
 * "NO DIALTONE"
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_dial(CoreObject *co, const TelCallDial *dial_info,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	const gchar *clir;
	gchar *num;
	dbg("Entry");

	if (dial_info->call_type == TEL_CALL_TYPE_VIDEO) {
		err("Video call is not supported in atmodem");
		return TEL_RETURN_OPERATION_NOT_SUPPORTED;
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

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_answer");
}

/*
 * Operation - Answer/Reject/Replace/hold(current call) & accept incoming call.
 *
 * Request -
 *
 * 1. AT-Command: ATA
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 *
 * 2. AT-Command: AT+CHLD=[<n>]
 * <n>
 * 0 - (deafult)release all held calls or set User Determined User Busy for a waiting/incoming
 * call; if both exists then only the waiting call will be rejected.
 * 1 -  release all active calls and accepts the other (held or waiting)
 * Note: In the scenario: An active call, a waiting call and held call, when the active call is
 * terminated, we will make the Waiting call as active.
 * 2 - 	place all active calls (if exist) on hold and accepts the other call (held or waiting/in-coming).
 * If only one call exists which is active, place it on hold and if only held call exists make it active call.
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 * For more informatiion refer 3GPP TS 27.007.
 */
static TelReturn atmodem_call_answer(CoreObject *co, TelCallAnswerType ans_type,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	dbg("Entry");

	if (ans_type == TEL_CALL_ANSWER_ACCEPT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "ATA");
	}else if (ans_type == TEL_CALL_ANSWER_REJECT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=0");
	} else if (ans_type == TEL_CALL_ANSWER_REPLACE) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=1");
	} else if (ans_type == TEL_CALL_ANSWER_HOLD_AND_ACCEPT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	}else {
		err("Unsupported call answer type");
		return TEL_RETURN_FAILURE;
	}

	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_answer");
}

/*
 * Operation - release all calls/release specific call/release all active call/release all held calls.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * <n>
 * 0  - (defualt)release all held calls or set User Determined User Busy for a waiting/incoming.
 * call; if both exists then only the waiting call will be rejected.
 * 1  - release all active calls and accepts the other (held or waiting).
 * 1x - release a specific call (x specific call number as indicated by call id).
 * 8  -	release all calls.
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_end(CoreObject *co, const TelCallEnd *end_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	dbg("Entry");

	if (end_info->end_type == TEL_CALL_END_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=8");
	}else if (end_info->end_type == TEL_CALL_END) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s%d", "AT+CHLD=1",end_info->call_id);
	} else if (end_info->end_type == TEL_CALL_END_ACTIVE_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=1");
	} else if (end_info->end_type == TEL_CALL_END_HOLD_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=0");
	}else {
		err("Unsupported call end type");
		return TEL_RETURN_FAILURE;
	}

	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_end");
}

/*
 * Operation - call hold.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 2 - place all active calls (if exist) on hold and accepts the other call (held or waiting/incoming).
 * If only one call exists which is active, place it on hold and if only held call exists
 * make it active call
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_hold(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)

{
	gchar *at_cmd;
	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_hold");
}

/*
 * Operation - call active.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 2 - place all active calls (if exist) on hold and accepts the other call (held or waiting/incoming).
 * If only one call exists which is active, place it on hold and if only held call exists
 * make it active call
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_active(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	gchar *at_cmd;
	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_active");
}

/*
 * Operation - call swap.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 2 - place all active calls (if exist) on hold and accepts the other call (held or waiting/incoming).
 * If only one call exists which is active, place it on hold and if only held call exists
 * make it active call
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_swap(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	gchar *at_cmd;
	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_swap");
}

/*
 * Operation - call join.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 3 - adds a held call to the conversation
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_join(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	gchar *at_cmd;
	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=3");
	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_join");
}

/*
 * Operation - call split.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 2x - place all active calls on hold except call x with which communication is supported
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_split(CoreObject *co, guint call_id,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	dbg("Entry");

	at_cmd = g_strdup_printf("%s%d", "AT+CHLD=2", call_id);
	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_split");
}

/*
 * Operation - call transfer.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 4 connects the two calls and disconnects the subscriber from both calls (Explicit Call Transfer)
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_transfer(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	gchar *at_cmd;
	dbg("Entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=4");
	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_transfer");
}

/*
 * Operation - call transfer.
 *
 * Request -
 * 1. AT-Command: AT+CTFR= <number>[,<type>]
 * Where
 * number>
 * string type phone number
 * <type>
 * type of address octet in integer format. It is optional parameter.
 *
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn atmodem_call_deflect(CoreObject *co, const gchar *deflect_to,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	dbg("Entry");

	at_cmd = g_strdup_printf("AT+CTFR=%s", deflect_to);
	dbg("at command : %s", at_cmd);

	return __atmodem_send_call_request(co, cb, cb_data, at_cmd, "atmodem_call_deflect");
}

/* Call Operations */
static TcoreCallOps atmodem_call_ops = {
	.dial = atmodem_call_dial,
	.answer = atmodem_call_answer,
	.end = atmodem_call_end,
	.send_dtmf = NULL,
	.hold = atmodem_call_hold,
	.active = atmodem_call_active,
	.swap = atmodem_call_swap,
	.join = atmodem_call_join,
	.split = atmodem_call_split,
	.transfer = atmodem_call_transfer,
	.deflect = atmodem_call_deflect,
	.set_active_line = NULL,
	.get_active_line = NULL,
	.set_volume_info = NULL,
	.get_volume_info = NULL,
	.set_sound_path = NULL,
	.set_mute = NULL,
	.get_mute_status = NULL,
	.set_sound_recording = NULL,
	.set_sound_equalization = NULL,
};

gboolean atmodem_call_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Entry");

	/* Set operations */
	tcore_call_set_ops(co, &atmodem_call_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co,
		"%SCLCC:",
		on_notification_atmodem_call_status, NULL);
	tcore_object_add_callback(co,
		"+CSSU:",
		on_notification_atmodem_call_ss_cssu_info, NULL);

	return TRUE;
}

void atmodem_call_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}
