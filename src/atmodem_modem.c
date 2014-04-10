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

#include <co_modem.h>

#include "atmodem_modem.h"
#include "atmodem_common.h"

typedef enum {
	ATMODEM_CP_STATE_OFFLINE,
	ATMODEM_CP_STATE_CRASH_RESET,
	ATMODEM_CP_STATE_CRASH_EXIT,
	ATMODEM_CP_STATE_BOOTING,
	ATMODEM_CP_STATE_ONLINE,
	ATMODEM_CP_STATE_NV_REBUILDING,
	ATMODEM_CP_STATE_LOADER_DONE,
} AtmodemCpState;

/* Notifications */
#if 0	/* To be supported later */
static gboolean on_event_atmodem_cp_power(CoreObject *co, const void *event_info, void *user_data)
{
	GSList *lines = (GSList *)event_info;
	const gchar *line;

	dbg("Modem Power notification - SIM status: [\%SCSIM]");

	if (g_slist_length(lines) != 1) {
		err("\%SCSIM unsolicited message expected to be "
			"Single line but received multiple lines");
		return TRUE;
	}

	line = (const gchar *)lines->data;
	if (line != NULL) {
		GSList *tokens;
		AtmodemCpState cp_state;
		TelModemPowerStatus power_status;

		tokens = tcore_at_tok_new(line);

		/* <CP state> */
		cp_state = atoi(g_slist_nth_data(tokens, 0));
		dbg("CP state: [0x%x]", cp_state);
		switch (cp_state) {
		case ATMODEM_CP_STATE_OFFLINE:
			power_status = TEL_MODEM_POWER_OFF;
		break;

		case ATMODEM_CP_STATE_CRASH_RESET:
			power_status = TEL_MODEM_POWER_ERROR;
		break;

		default:
			dbg("Unhandled State : [0x%x]", cp_state);
			goto out;
		}

		/* Set Power */
		tcore_modem_set_powered(co, FALSE);

		/* Send notification */
		tcore_object_send_notification(co,
			TCORE_NOTIFICATION_MODEM_POWER,
			sizeof(TelModemPowerStatus), &power_status);

out:
		tcore_at_tok_free(tokens);
	}

	return TRUE;
}
#endif	/* To be supported later */

static gboolean on_event_atmodem_phone_state(CoreObject *co, const void *event_info, void *user_data)
{
	GSList *lines = (GSList *)event_info;
	const gchar *line;

	dbg("Modem Power notification - SIM status: [\%SCFUN]");

	if (g_slist_length(lines) != 1) {
		err("\%SCFUN unsolicited message expected to be "
			"Single line but received multiple lines");
		return TRUE;
	}

	line = (const gchar *)lines->data;
	if (line != NULL) {
		GSList *tokens;
		guint state;

		tokens = tcore_at_tok_new(line);

		/* <CP state> */
		state = atoi(g_slist_nth_data(tokens, 0));
		dbg("Flight mdoe State: [%s]", (state ? "OFF" : "ON"));

		/* Set Flight mode */
		tcore_modem_set_flight_mode_state(co, !state);

		tcore_at_tok_free(tokens);

		/*
		 * TODO:
		 *	Handle Notification as response to Request
		 */
	}

	return TRUE;
}

/* System function responses */
static void on_response_modem_set_flight_mode_internal(TcorePlugin *plugin,
	gint result, const void *response, void *user_data)
{
	CoreObject *co;
	gboolean flight_mode;
	dbg("Enter");

	co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM);
	tcore_check_return_assert(co != NULL);

	tcore_check_return(result == TEL_MODEM_RESULT_SUCCESS);

	/* Get Flight mode state */
	(void)tcore_modem_get_flight_mode_state(co, &flight_mode);

	dbg("Setting Modem Fiight mode (internal) - [%s] - [SUCCESS]",
		(flight_mode ? "ON": "OFF"));

	/*
	 * Send notification
	 *
	 * This is an internal request to set Flight mode, which is sent during
	 * boot-up based on AP-side configuration (VCONF).
	 *
	 * Need to notify TAPI through Notiifcation -
	 *	TCORE_NOTIFICATION_MODEM_FLIGHT_MODE
	 */
	(void)tcore_object_send_notification(co,
		TCORE_NOTIFICATION_MODEM_FLIGHT_MODE,
		sizeof(gboolean), &flight_mode);
}

/* System functions */
gboolean atmodem_modem_power_on_modem(TcorePlugin *plugin)
{
	CoreObject *co;
	TcoreStorage *strg;
	gboolean flight_mode;
	TelModemPowerStatus power_status;

	co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM);
	tcore_check_return_value_assert(co != NULL, FALSE);

	/* Set Modem Power State to 'ON' */
	tcore_modem_set_powered(co, TRUE);

	/*
	 * Set Flight mode (as per AP settings -VCONF)
	 */
	/* Get Flight mode from VCONFKEY */
	strg = tcore_server_find_storage(tcore_plugin_ref_server(plugin), "vconf");
	tcore_check_return_value_assert(strg != NULL, FALSE);

	flight_mode = tcore_storage_get_bool(strg, STORAGE_KEY_FLIGHT_MODE);

	/*
	 * Set Flight mode request is dispatched to Core Object (Modem)
	 * to ensure that 'Request Hooks' get executed.
	 */
	(void)tcore_object_dispatch_request(co, TRUE,
		TCORE_COMMAND_MODEM_SET_FLIGHTMODE,
		&flight_mode, sizeof(gboolean),
		on_response_modem_set_flight_mode_internal, NULL);

	/*
	 * Send notification
	 *
	 * Need to notify Modem is Powered UP through Notiifcation -
	 *	TCORE_NOTIFICATION_MODEM_POWER
	 */
	power_status = TEL_MODEM_POWER_ON;
	(void)tcore_object_send_notification(co,
		TCORE_NOTIFICATION_MODEM_POWER,
		sizeof(TelModemPowerStatus), &power_status);
	dbg("Modem Powered ON");

	return FALSE;
}

/* Modem Responses */
static void on_response_atmodem_modem_set_flight_mode(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	gboolean *enable;

	TelModemResult result = TEL_MODEM_RESULT_FAILURE;
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success)
		result = TEL_MODEM_RESULT_SUCCESS;

	enable = (gboolean *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Setting Modem Flight mode - [%s] - [%s]",
		(*enable ? "ON": "OFF"),
		(result == TEL_MODEM_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Update Core Object */
	(void)tcore_modem_set_flight_mode_state(co, *enable);

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);

	/*
	 * In case Flight mode is set to OFF, we need to trigger
	 * Network Registration.
	 *
	 * This is taken care by Network module which hooks on
	 * Set Flight mode Request of Modem module.
	 */
}

static void on_response_atmodem_modem_get_version(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	TelModemVersion version = {{0}, {0}, {0}, {0}};

	TelModemResult result = TEL_MODEM_RESULT_FAILURE;
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp) {
		if (at_resp->lines) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const gchar *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) > 0) {
				if (at_resp->success) {
					gchar *sw_ver = NULL, *hw_ver = NULL;
					gchar *calib_date = NULL, *p_code = NULL;

					sw_ver = g_slist_nth_data(tokens, 0);
					hw_ver = g_slist_nth_data(tokens, 1);
					calib_date = g_slist_nth_data(tokens, 2);
					p_code = g_slist_nth_data(tokens, 3);

					g_strlcpy(version.software_version,
						sw_ver,
						TEL_MODEM_VERSION_LENGTH_MAX + 1);
					g_strlcpy(version.hardware_version,
						hw_ver,
						TEL_MODEM_VERSION_LENGTH_MAX + 1);
					g_strlcpy(version.calibration_date,
						calib_date,
						TEL_MODEM_VERSION_LENGTH_MAX + 1);
					g_strlcpy(version.product_code,
						p_code,
						TEL_MODEM_VERSION_LENGTH_MAX + 1);

					dbg("Version - Software: [%s] Hardware: [%s] "
						"Calibration date: [%s] Product "
						"Code: [%s]", sw_ver, hw_ver,
						calib_date, p_code);

					result = TEL_MODEM_RESULT_SUCCESS;
				} else {
					err("RESPONSE - [NOK]");
					err("[%s]", g_slist_nth_data(tokens, 0));
				}
			} else {
				err("Invalid response message");
				result = TEL_MODEM_RESULT_UNKNOWN_FAILURE;
			}
			tcore_at_tok_free(tokens);
		}
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &version, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_modem_get_imei(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	gchar imei[TEL_MODEM_IMEI_LENGTH_MAX +1] = {0};

	TelModemResult result = TEL_MODEM_RESULT_FAILURE;
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp) {
		if (at_resp->lines) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const gchar *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) == 1) {
				if (at_resp->success) {
					dbg("RESPONSE - [OK]");
					g_strlcpy(imei,
						(const gchar *)g_slist_nth_data(tokens, 0),
						TEL_MODEM_IMEI_LENGTH_MAX+1);
					dbg("IMEI: [%s]", imei);

					result = TEL_MODEM_RESULT_SUCCESS;
				} else {
					err("RESPONSE - [NOK]");
					err("[%s]", g_slist_nth_data(tokens, 0));
				}
			}  else {
				err("Invalid response message");
				result = TEL_MODEM_RESULT_UNKNOWN_FAILURE;
			}
			tcore_at_tok_free(tokens);
		}
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, imei, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

/* Modem Operations */
/*
 * Operation - set_flight_mode
 *
 * Request -
 * AT-Command: AT+CFUN=<fun>
 * where,
 * <fun>
 * 0	ENABLE Flight Mode
 * 1	DISABLE Flight Mode
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_modem_set_flight_mode(CoreObject *co, gboolean enable,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	guint power_mode;

	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;

	if (enable) {
		dbg("Flight mode - [ON]");
		power_mode = 0;
	} else {
		dbg("Flight mode - [OFF]");
		power_mode = 1;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CFUN=%d", power_mode);

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
				&enable, sizeof(gboolean));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_atmodem_modem_set_flight_mode, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Flight mode");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get_flight_mode
 *
 * Request -
 * AT-Command: None
 *	Fetch information from Core Object
 *
 * Response - flight_mode (gboolean)
 */
static TelReturn atmodem_modem_get_flight_mode(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gboolean flight_mode;

	/* Fetch Flight mode from Core Object */
	(void)tcore_modem_get_flight_mode_state(co, &flight_mode);
	dbg("Modem Flight mode - [%s]", (flight_mode ? "ON": "OFF"));

	/* Invoke response callback */
	if (cb)
		cb(co, (gint)TEL_MODEM_RESULT_SUCCESS, &flight_mode, cb_data);

	return TEL_RETURN_SUCCESS;
}

/*
 * Operation - get_version
 *
 * Request -
 * AT-Command: AT+CGMR
 *
 * Response - version (TelModemVersion)
 * Success: (Single line) -
 *	<sw_ver>, <hw_ver>, <calib_date>, <p_code>
 *	OK
 * Note:
 *	Success Response is different from standard 3GPP AT-Command (+CGMR)
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_modem_get_version(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+CGMR", NULL,
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_atmodem_modem_get_version, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Version");

	return ret;
}

/*
 * Operation - get_imei
 *
 * Request -
 * AT-Command: AT+CGSN
 *
 * Response - imei (gchar array of length 20+'\0' bytes)
 * Success: (Single line)
 *	<IMEI>
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn atmodem_modem_get_imei(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+CGSN", NULL,
		TCORE_AT_COMMAND_TYPE_NUMERIC,
		NULL,
		on_response_atmodem_modem_get_imei, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get IMEI");

	return ret;
}

/* Modem Operations */
static TcoreModemOps atmodem_modem_ops = {
	.set_power_status = NULL,
	.set_flight_mode = atmodem_modem_set_flight_mode,
	.get_flight_mode = atmodem_modem_get_flight_mode,
	.get_version = atmodem_modem_get_version,
	.get_imei = atmodem_modem_get_imei
};

gboolean atmodem_modem_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Enter");

	/* Set operations */
	tcore_modem_set_ops(co, &atmodem_modem_ops);

	/* Add Callbacks */
#if 0	/* To be supported later */
	tcore_object_add_callback(co, "\%SCSIM:",
		on_event_atmodem_cp_power, NULL);
#endif	/* To be supported later */
	tcore_object_add_callback(co, "\%SCFUN:",
		on_event_atmodem_phone_state, NULL);

	dbg("Exit");
	return TRUE;
}

void atmodem_modem_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}
