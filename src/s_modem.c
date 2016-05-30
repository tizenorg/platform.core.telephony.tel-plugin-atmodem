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
#include <unistd.h>
#include <glib.h>

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_modem.h>
#include <storage.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
#include "s_modem.h"

#if 0
enum cp_state {
	CP_STATE_OFFLINE,
	CP_STATE_CRASH_RESET,
	CP_STATE_CRASH_EXIT,
	CP_STATE_BOOTING,
	CP_STATE_ONLINE,
	CP_STATE_NV_REBUILDING,
	CP_STATE_LOADER_DONE,
};

static gboolean on_sys_event_modem_power(CoreObject *co_modem, const void *event_info, void *user_data)
{
	struct tnoti_modem_power modem_power;
	enum cp_state *state;

	state = (enum cp_state *)event_info;
	dbg("state : (0x%x)", *state);

	if (*state == CP_STATE_OFFLINE || *state == CP_STATE_CRASH_RESET) {

		tcore_modem_set_powered(co_modem, FALSE);

		if (*state == CP_STATE_OFFLINE)
			modem_power.state = MODEM_STATE_OFFLINE;
		else
			modem_power.state = MODEM_STATE_ERROR;

	} else {
		dbg("useless state : (0x%x)", *state);
		return TRUE;
	}

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_modem)), co_modem, TNOTI_MODEM_POWER,
			sizeof(struct tnoti_modem_power), &modem_power);

	return TRUE;
}
#endif

static gboolean on_event_modem_power(CoreObject *co_modem,
	const void *event_info, void *user_data)
{
	struct treq_modem_set_flightmode flight_mode_set;
	struct tnoti_modem_power modem_power;
	UserRequest *ur;
	TcoreHal *h;
	Storage *strg;

	strg = tcore_server_find_storage(tcore_plugin_ref_server(tcore_object_ref_plugin(co_modem)), "vconf");
	flight_mode_set.enable = tcore_storage_get_bool(strg, STORAGE_KEY_FLIGHT_MODE_BOOL);

	h = tcore_object_get_hal(co_modem);

	tcore_hal_set_power_state(h, TRUE);

	ur = tcore_user_request_new(NULL, NULL);
	tcore_user_request_set_data(ur, sizeof(struct treq_modem_set_flightmode), &flight_mode_set);
	tcore_user_request_set_command(ur, TREQ_MODEM_SET_FLIGHTMODE);
	tcore_object_dispatch_request(co_modem, ur);

#if 0	/* To be opened later */
	ur = tcore_user_request_new(NULL, NULL);
	tcore_user_request_set_command(ur, TREQ_MODEM_GET_IMEI);
	tcore_object_dispatch_request(co_modem, ur);

	ur = tcore_user_request_new(NULL, NULL);
	tcore_user_request_set_command(ur, TREQ_MODEM_GET_VERSION);
	tcore_object_dispatch_request(co_modem, ur);
#endif
	tcore_modem_set_powered(co_modem, TRUE);

	modem_power.state = MODEM_STATE_ONLINE;

	/* Send notification */
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_modem)),
		co_modem,
		TNOTI_MODEM_POWER,
		sizeof(struct tnoti_modem_power), &modem_power);

	return TRUE;
}

static gboolean on_event_modem_phone_state(CoreObject *co_modem,
	const void *event_info, void *user_data)
{
	GSList *lines = (GSList *)event_info;
	const gchar *line;

	dbg("Modem Power notification - [+SCFUN]");

	if (g_slist_length((GSList *)lines) != 1) {
		err("+SCFUN unsolicited message expected to be "
			"Single line but received multiple lines");
		return TRUE;
	}

	line = (const gchar *)lines->data;
	if (line != NULL) {
		GSList *tokens;
		char *resp;
		guint state = 0;

		tokens = tcore_at_tok_new(line);
		resp = g_slist_nth_data(tokens, 0);
		dbg("resp: [%s]", resp);

		/* <CP state> */
		if (resp)
			state = atoi(resp);
		dbg("Flight mode State: [%s]", (state ? "OFF" : "ON"));

		/* Set Flight mode */
		tcore_modem_set_flight_mode_state(co_modem, !state);

		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

/* Modem Responses */
static void on_response_poweron(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;

	if (at_resp && at_resp->success > 0) {
		dbg("RESPONSE OK");
		on_event_modem_power(tcore_pending_ref_core_object(p), NULL, NULL);
	} else {
		dbg("RESPONSE NOK");
		s_modem_send_poweron(tcore_pending_ref_plugin(p));
	}
}

static void on_response_modem_set_flight_mode(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	CoreObject *co_modem = NULL;
	UserRequest *ur = NULL;
	struct tresp_modem_set_flightmode flight_resp = {0, };
	const struct treq_modem_set_flightmode *flight_req;

	dbg("Enter");

	co_modem = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	flight_req = tcore_user_request_ref_data(ur, NULL);
	dbg("req_data->enable: [%d]", flight_req->enable);

	if (at_resp && at_resp->success) {
		Storage *strg;
		gboolean flight_mode_state = FALSE;

		if (flight_req->enable == 1)
			flight_mode_state = TRUE;

		strg = tcore_server_find_storage(tcore_plugin_ref_server(tcore_object_ref_plugin(co_modem)), "vconf");
		tcore_storage_set_bool(strg, STORAGE_KEY_FLIGHT_MODE_BOOL, flight_mode_state);

		flight_resp.result = TCORE_RETURN_SUCCESS;

		/* Update Core Object */
		(void)tcore_modem_set_flight_mode_state(co_modem, flight_mode_state);
	} else
		flight_resp.result = TCORE_RETURN_FAILURE;

	dbg("Setting Modem Flight mode - [%s] - [%s]",
		((flight_req->enable == 1) ? "ON" : "OFF"),
		(flight_resp.result == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));

	if (ur) {
		if (tcore_user_request_ref_communicator(ur) != NULL) {
			/* Send Response */
			tcore_user_request_send_response(ur,
				TRESP_MODEM_SET_FLIGHTMODE,
				sizeof(struct tresp_modem_set_flightmode), &flight_resp);
		} else if (flight_resp.result == TCORE_RETURN_SUCCESS) {
			struct tnoti_modem_flight_mode flight_mode;

			/* Boot-up Request */
			err("ur is NULL");

			memset(&flight_mode, 0x0, sizeof(struct tnoti_modem_flight_mode));

			flight_mode.enable = flight_req->enable;
			dbg("Boot-up: Modem Flight mode - [%s]",
				(flight_req->enable ? "ON" : "OFF"));

			/* Send notification */
			tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_modem)),
				co_modem,
				TNOTI_MODEM_FLIGHT_MODE,
				sizeof(struct tnoti_modem_flight_mode), &flight_mode);
		}
	} else {
		err("ur is NULL");
	}
}

static void on_response_modem_get_imei(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;
	struct tresp_modem_get_imei imei_resp = {0, };

	dbg("Enter");

	if (at_resp) {
		if (at_resp->lines) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const gchar *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) == 1) {
				if (at_resp->success) {
					dbg("RESPONSE - [OK]");
					g_strlcpy(imei_resp.imei,
						(const gchar *)g_slist_nth_data(tokens, 0),
						16+1);
					dbg("IMEI: [%s]", imei_resp.imei);

					imei_resp.result = TCORE_RETURN_SUCCESS;
				} else {
					err("RESPONSE - [NOK]");
					err("[%s]", g_slist_nth_data(tokens, 0));
				}
			}  else {
				err("Invalid response message");
				imei_resp.result = TCORE_RETURN_FAILURE;
			}
			tcore_at_tok_free(tokens);
		}
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_MODEM_GET_IMEI,
			sizeof(struct tresp_modem_get_imei),
			&imei_resp);
	} else {
		err("ur is NULL");
	}

}

static void on_response_modem_get_version(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	UserRequest *ur = NULL;
	struct tresp_modem_get_version version_resp = {0, };

	dbg("Enter");

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

					g_strlcpy(version_resp.software,
						sw_ver, 32 + 1);
					g_strlcpy(version_resp.hardware,
						hw_ver, 32 + 1);
					g_strlcpy(version_resp.calibration,
						calib_date, 32 + 1);
					g_strlcpy(version_resp.product_code,
						p_code, 32 + 1);

					dbg("Version - Software: [%s] Hardware: [%s] "
						"Calibration date: [%s] Product Code: [%s]",
						sw_ver, hw_ver, calib_date, p_code);

					version_resp.result = TCORE_RETURN_SUCCESS;
				} else {
					err("RESPONSE - [NOK]");
					err("[%s]", g_slist_nth_data(tokens, 0));
				}
			} else {
				err("Invalid response message");
					version_resp.result = TCORE_RETURN_FAILURE;
			}

			/* Free resources */
			tcore_at_tok_free(tokens);
		}
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_MODEM_GET_VERSION,
			sizeof(struct tresp_modem_get_version), &version_resp);
	} else {
		err("ur is NULL");
	}
}

/*  Requests  */
static TReturn power_on(CoreObject *co_modem, UserRequest *ur)
{
	dbg("Modem Power ON request: NOT supported!!!");

	return TCORE_RETURN_ENOSYS;
}

static TReturn power_off(CoreObject *co_modem, UserRequest *ur)
{
	struct tnoti_modem_power modem_power;
	modem_power.state = MODEM_STATE_OFFLINE;

	tcore_modem_set_powered(co_modem, FALSE);

	/* Send notification */
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_modem)),
		co_modem,
		TNOTI_MODEM_POWER,
		sizeof(struct tnoti_modem_power), &modem_power);

	return TCORE_RETURN_SUCCESS;
}

static TReturn power_reset(CoreObject *co_modem, UserRequest *ur)
{
	dbg("Modem Power RESET request: NOT supported!!!");

	return TCORE_RETURN_ENOSYS;
}

static TReturn get_imei(CoreObject *co_modem, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;

	ret = tcore_prepare_and_send_at_request(co_modem,
		"AT+CGSN", NULL,
		TCORE_AT_NUMERIC,
		ur,
		on_response_modem_get_imei, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	return ret;
}

static TReturn get_version(CoreObject *co_modem, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;

	ret = tcore_prepare_and_send_at_request(co_modem, "AT+CGMR", NULL,
		TCORE_AT_SINGLELINE,
		ur,
		on_response_modem_get_version, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	return ret;
}

static TReturn get_sn(CoreObject *co_modem, UserRequest *ur)
{
	struct tresp_modem_get_sn sn_resp = {0, };
	TReturn ret;

	sn_resp.result = TCORE_RETURN_SUCCESS;
	g_strlcpy(sn_resp.meid, "123456789ABCDE", MODEM_DEVICE_MEID_LEN_MAX);

	ret = tcore_user_request_send_response(ur,
		TRESP_MODEM_GET_SN,
		sizeof(struct tresp_modem_get_sn), &sn_resp);

	return ret;
}

static TReturn set_flight_mode(CoreObject *co_modem, UserRequest *ur)
{
	gchar *at_cmd;
	guint power_mode;
	const struct treq_modem_set_flightmode *req_data;
	TReturn ret = TCORE_RETURN_FAILURE;

	req_data = tcore_user_request_ref_data(ur, NULL);

	dbg("req_data->enable: [%d]", req_data->enable);
	if (req_data->enable) {
		dbg("Flight mode - [ON]");
		power_mode = 0;
	} else {
		dbg("Flight mode - [OFF]");
		power_mode = 1;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CFUN=%d", power_mode);

	ret = tcore_prepare_and_send_at_request(co_modem, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_modem_set_flight_mode, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn get_flight_mode(CoreObject *co_modem, UserRequest *ur)
{
	struct tresp_modem_get_flightmode resp_data;
	TReturn ret;

	memset(&resp_data, 0x0, sizeof(struct tresp_modem_get_flightmode));

	resp_data.enable = tcore_modem_get_flight_mode_state(co_modem);
	resp_data.result = TCORE_RETURN_SUCCESS;
	dbg("Get Flight mode: Flight mdoe: [%s]", (resp_data.enable ? "ON" : "OFF"));

	ret = tcore_user_request_send_response(ur,
		TRESP_MODEM_GET_FLIGHTMODE,
		sizeof(struct tresp_modem_get_flightmode), &resp_data);
	dbg("ret: [0x%x]", ret);

	return ret;
}

/** Modem operations */
static struct tcore_modem_operations modem_ops = {
	.power_on = power_on,
	.power_off = power_off,
	.power_reset = power_reset,
	.set_flight_mode = set_flight_mode,
	.get_imei = get_imei,
	.get_version = get_version,
	.get_sn = get_sn,
	.get_flight_mode = get_flight_mode,
};

gboolean s_modem_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *co_modem;

	co_modem = tcore_modem_new(p, "modem", &modem_ops, h);
	if (!co_modem) {
		err("Core object is NULL");
		return FALSE;
	}

#if 0
	tcore_object_add_callback(co_modem, EVENT_SYS_NOTI_MODEM_POWER, on_sys_event_modem_power, NULL);
#endif

	tcore_object_add_callback(co_modem,
		"+SCFUN:",
		on_event_modem_phone_state, NULL);

	return TRUE;
}

void s_modem_exit(TcorePlugin *p)
{
	CoreObject *co_modem;

	if (!p) {
		err("Plugin is NULL");
		return;
	}

	co_modem = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_MODEM);

	tcore_modem_free(co_modem);
}

gboolean s_modem_send_poweron(TcorePlugin *p)
{
	CoreObject *co_modem = NULL;
	UserRequest *ur = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	co_modem = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_MODEM);
	ur = tcore_user_request_new(NULL, NULL);

	ret = tcore_prepare_and_send_at_request(co_modem,
		"AT+CPAS", "+CPAS",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_poweron, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS)
		tcore_user_request_unref(ur);

	dbg("ret: [0x%x]", ret);

	/* Free resources */
	return TRUE;
}
