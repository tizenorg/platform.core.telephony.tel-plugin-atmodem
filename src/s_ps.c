/**
 * tel-plugin-atmodem
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Kyoungyoup Park <gynaru.park@samsung.com>
 *          Hayoon Ko       <hayoon.ko@samsung.com>
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
#include <arpa/inet.h>

#include <fcntl.h>

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_ps.h>
#include <co_context.h>
#include <user_request.h>
#include <server.h>
#include <util.h>
#include <type/ps.h>
#include <at.h>

#include "s_common.h"
#include "s_ps.h"

static void __notify_context_status_changed(CoreObject *co_ps, guchar context_id, gint status)
{
	Server *server;
	struct tnoti_ps_call_status ps_call_status;

	dbg("Entry");

	ps_call_status.context_id = (guint)context_id;
	ps_call_status.state = status;
	ps_call_status.result = TCORE_RETURN_SUCCESS;

	dbg("Sending PS Call Status Notification - Context ID: [%d] Context State: [%d]",
					ps_call_status.context_id, ps_call_status.state);

	/* Send PS CALL Status Notification */
	server = tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps));
	tcore_server_send_notification(server, co_ps,
			TNOTI_PS_CALL_STATUS,
			sizeof(struct tnoti_ps_call_status),
			&ps_call_status);

	dbg("Exit");
}

static void on_response_undefine_context_cmd(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;

	dbg("Entered");

	if (resp && resp->success) {
		dbg("Response Ok");
		return;
	}
	dbg("Response NOk");
}

static void __send_undefine_context_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	char *at_cmd;
	int context_id = 0;
	TReturn ret;

	dbg("Entered");

	/*Getting Context ID from Core Object*/
	context_id = tcore_context_get_id(ps_context);

	at_cmd = g_strdup_printf("AT+CGDCONT=0,%d", context_id);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		NULL,
		on_response_undefine_context_cmd, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resource */
	g_free(at_cmd);

	return;
}

static void __ps_setup_pdp(CoreObject *co_ps, gint result,
	const gchar *netif_name, void *user_data)
{
	CoreObject *ps_context = user_data;
	guchar context_id;

	CHECK_AND_RETURN(ps_context != NULL);

	dbg("Enter");

	if (result < 0) {
		err("Failed to setup PDP");

		/* Deactivate PDP context */
		__send_undefine_context_cmd(co_ps, ps_context);

		return;
	}

	dbg("devname = [%s]", netif_name);

	context_id = tcore_context_get_id(ps_context);
	dbg("Context ID : %d", context_id);

	__notify_context_status_changed(co_ps, context_id, 1);

	dbg("Exit");
}

static void __on_response_get_ipconfiguration(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	const TcoreATResponse *at_resp = data;
	guchar context_id;
	GSList *p_cur = NULL;

	context_id = tcore_context_get_id(ps_context);
	dbg("Context ID : %d", context_id);

	if (at_resp && at_resp->success) {
		for (p_cur = at_resp->lines; p_cur != NULL; p_cur = p_cur->next) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const char *) p_cur->data;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) >= 2) {
				gchar *pdp_type = NULL, *apn = NULL;
				gchar *ip = NULL, *pdp_address = NULL, *p_cid = NULL;

				p_cid = g_slist_nth_data(tokens, 0);
				dbg("cid: %d", p_cid);

				/* Send IP Configuration noti only on the requested CID. */
				if (atoi(p_cid) && (context_id == (unsigned int)atoi(p_cid))) {
					TcoreHal *hal = tcore_object_get_hal(co_ps);

					pdp_type = g_slist_nth_data(tokens, 1);
					dbg("PDP type: %s", pdp_type);

					if (pdp_type != NULL)	{
						apn = g_slist_nth_data(tokens, 2);
						dbg("APN: %s", apn);
					}
					if (apn != NULL) {
						ip = g_slist_nth_data(tokens, 3);
						pdp_address = tcore_at_tok_extract(ip);
						dbg("IP address: %s", ip);
					}

					(void)tcore_context_set_address(ps_context, (const char *)pdp_address);
					g_free(pdp_address);

					dbg("Adding default DNS pri: 8.8.8.8 sec: 8.8.4.4");

					tcore_context_set_dns1(ps_context, "8.8.8.8");
					tcore_context_set_dns2(ps_context, "8.8.4.4");

					/* Mount network interface */
					if (tcore_hal_setup_netif(hal, co_ps, __ps_setup_pdp, ps_context, context_id, TRUE)
							!= TCORE_RETURN_SUCCESS) {
						err("Setup network interface failed");
						return;
					}
				} else {
					err("No matched response with CID: %d", atoi(p_cid));
				}
			}
		}
	} else {
		err("Response NOK");

		context_id = tcore_context_get_id(ps_context);
		dbg("Context ID : %d", context_id);

		__notify_context_status_changed(co_ps, context_id, 3);
	}
}

static void __get_ipconfiguration(CoreObject *co_ps, CoreObject *ps_context)
{
	TReturn ret;

	dbg("Enter");

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_ps,
		"AT+CGDCONT?", NULL,
		TCORE_AT_NO_RESULT,
		NULL,
		__on_response_get_ipconfiguration,
		ps_context,
		on_send_at_request, NULL,
		0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS) {
		err("Failed to prepare and send AT request");

		/* Deactivate PDP context */
		__send_undefine_context_cmd(co_ps, ps_context);
	}

	dbg("Exit");
}

static void __on_response_attach_ps(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	const TcoreATResponse *at_resp = data;
	guchar context_id;

	CHECK_AND_RETURN(at_resp != NULL);
	CHECK_AND_RETURN(ps_context != NULL);

	if (at_resp && at_resp->success) {
		__get_ipconfiguration(co_ps, ps_context);
		return;
	}

	err("Response NOK");

	context_id = tcore_context_get_id(ps_context);
	dbg("Context ID : %d", context_id);

	__notify_context_status_changed(co_ps, context_id, 3);

	dbg("Exit");
}

static void __attach_ps(CoreObject *co_ps, CoreObject *ps_context)
{
	TReturn ret;

	dbg("Enter");

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_ps,
		"ATD*99***1#", NULL,
		TCORE_AT_NO_RESULT,
		NULL,
		__on_response_attach_ps, ps_context,
		on_send_at_request, NULL,
		0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS) {
		err("Failed to prepare and send AT request");

		/* Deactivate PDP context */
		__send_undefine_context_cmd(co_ps, ps_context);
	}

	dbg("Exit");
}

static void on_response_ps_activate_context(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	const TcoreATResponse *at_resp = data;
	CoreObject *ps_context = user_data;

	dbg("Enter");

	CHECK_AND_RETURN(at_resp != NULL);
	CHECK_AND_RETURN(ps_context != NULL);

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		__attach_ps(co_ps, ps_context);
	} else {
		guchar context_id;

		err("Response NOK");

		context_id = tcore_context_get_id(ps_context);
		dbg("Context ID : %d", context_id);

		__notify_context_status_changed(co_ps, context_id, 3);
	}

	dbg("Exit");
}

static void on_response_ps_deactivate_context(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	TcoreHal *hal = tcore_object_get_hal(co_ps);
	const TcoreATResponse *at_resp = data;
	CoreObject *ps_context = user_data;
	guchar context_id;

	dbg("Enter");

	CHECK_AND_RETURN(at_resp != NULL);
	CHECK_AND_RETURN(ps_context != NULL);

	context_id = tcore_context_get_id(ps_context);
	dbg("Context ID : %d", context_id);

	/*
	 * AT+CGACT = 0 is returning NO CARRIER or an error. Just test if the
	 * response contains NO CARRIER else decode CME error.
	 */
	if (at_resp && at_resp->success) {
		const gchar *line;

		line = (const gchar *)at_resp->lines->data;
		if (g_strcmp0(line, "NO CARRIER") != 0) {
			err("%s", line);
			err("Context %d has not been deactivated", context_id);

			goto out;
		}
	}

	__notify_context_status_changed(co_ps, context_id, 3);

	if (tcore_hal_setup_netif(hal, co_ps, NULL, NULL, context_id, FALSE) != TCORE_RETURN_SUCCESS)
		err("Failed to disable network interface");

out:
	dbg("Exit");
}

static void on_response_ps_define_context(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	CoreObject *ps_context = (CoreObject *) user_data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	guchar context_id;
	gint curr_call_status;

	dbg("entry");

	CHECK_AND_RETURN(at_resp != NULL);
	CHECK_AND_RETURN(ps_context != NULL);

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		curr_call_status = 0;
		tcore_context_set_state(co_ps, CONTEXT_STATE_ACTIVATED);
	} else {
		err("ERROR[%s]", at_resp->final_response);
		curr_call_status = 3;
	}

	context_id = tcore_context_get_id(ps_context);
	dbg("Context ID : %d", context_id);

	__notify_context_status_changed(co_ps, context_id, curr_call_status);
}

/*
 * Operation - PDP Context Activate
 *
 * Request -
 * AT-Command: AT+CGACT= [<state> [, <cid> [, <cid> [,...]]]]
 *
 * where,
 * <state>
 * indicates the state of PDP context activation
 *
 * 1 activated
 *
 * <cid>
 * It is a numeric parameter which specifies a particular PDP context definition
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn activate_ps_context(CoreObject *o, CoreObject *ps_context, void* user_data)
{
	gchar *at_cmd = NULL;
	TReturn ret;
	guchar context_id;

	dbg("Entry");

	context_id = tcore_context_get_id(ps_context);
	dbg("Context ID : %d", context_id);

	at_cmd = g_strdup_printf("AT+CGACT=1,%d", context_id);
	dbg(" at command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o,
		at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		NULL,
		on_response_ps_activate_context, ps_context,
		on_send_at_request, NULL,
		0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS) {
		err("AT request failed. Send notification for call status [DISCONNECTED]");

		__notify_context_status_changed(o, context_id, 3);
	}
	g_free(at_cmd);
	dbg("Exit");

	return ret;
}

/*
 * Operation - PDP Context Deactivate
 *
 * Request -
 * AT-Command: AT+CGACT= [<state> [, <cid> [, <cid> [,...]]]]
 *
 * where,
 * <state>
 * indicates the state of PDP context activation
 *
 * 0 deactivated
 *
 * <cid>
 * It is a numeric parameter which specifies a particular PDP context definition
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn deactivate_ps_context(CoreObject *o, CoreObject *ps_context, void* user_data)
{
	gchar *at_cmd = NULL;
	TReturn ret;
	guchar context_id;

	dbg("Entry");

	context_id = tcore_context_get_id(ps_context);
	dbg("Context ID : %d", context_id);

	at_cmd = g_strdup_printf("AT+CGACT=0,%d", context_id);
	dbg(" at command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o,
		at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		NULL,
		on_response_ps_deactivate_context, ps_context,
		on_send_at_request, NULL,
		0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS) {
		err("AT request failed. Send notification for call status [DISCONNECTED]");
		__notify_context_status_changed(o, context_id, 3);
	}
	g_free(at_cmd);
	dbg("Exit");

	return ret;
}

/*
 * Operation - Define PDP Context
 *
 * Request -
 * AT-Command: AT+CGDCONT= [<cid> [, <PDP_type> [, <APN> [, <PDP_addr> [,
 * <d_comp> [, <h_comp> [, <pd1> [... [, pdN]]]]]]]]]
 * where,
 * <cid>
 * It is a numeric parameter, which specifies a particular PDP context definition
 *
 * <PDP_type>
 * "IP" Internet Protocol (IETF STD 5)
 * "IPV6" Internet Protocol, version 6 (IETF RFC 2460)
 * "IPV4V6" Virtual <PDP_type>introduced to handle dual IP stack UE capability (see 3GPP
 *  TS 24.301[83])
 *
 * <APN>
 * Access Point Name
 *
 * <PDP_address>
 * It is the string parameter that identifies the MT in the address space applicable to the PDP
 * The allocated address may be read using the command +CGPADDR command
 *
 * <d_comp>
 * A numeric parameter that controls PDP data compression
 * 0 off
 * 1 on
 * 2 V.42 bis
 *
 * <h_comp>
 * A numeric parameter that controls PDP header compression
 * 0 off
 * 1 on
 * 2 RFC1144
 * 3 RFC2507
 * 4 RFC3095
 *
 * <pd1>...<pdN>
 * zero to N string parameters whose meanings are specific to the <PDP_type>
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn define_ps_context(CoreObject *o, CoreObject *ps_context, void *user_data)
{
	guchar context_id = 0;
	gchar *at_cmd = NULL;
	gchar *apn = NULL;
	gchar *pdp_type_str = NULL;
	gint pdp_type;
	gint d_comp;
	gint h_comp;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	context_id = tcore_context_get_id(ps_context);
	dbg("Context ID : %d", context_id);
	pdp_type = tcore_context_get_type(ps_context);
	dbg("PDP Type : %d", pdp_type);

	switch (pdp_type) {
	case CONTEXT_TYPE_X25:
		dbg("CONTEXT_TYPE_X25");
		pdp_type_str = g_strdup("X.25");
	break;

	case CONTEXT_TYPE_IP:
		dbg("CONTEXT_TYPE_IP");
		pdp_type_str = g_strdup("IP");
	break;

	case CONTEXT_TYPE_PPP:
		dbg("CONTEXT_TYPE_PPP");
		pdp_type_str = g_strdup("PPP");
	break;

	case CONTEXT_TYPE_IPV6:
		dbg("CONTEXT_TYPE_IPV6");
		pdp_type_str = g_strdup("IPV6");
	break;

	default:
		/*PDP Type not supported*/
		dbg("Unsupported PDP type: %d", pdp_type);
		goto error;
	}

	d_comp = tcore_context_get_data_compression(ps_context);
	h_comp = tcore_context_get_header_compression(ps_context);
	apn = tcore_context_get_apn(ps_context);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CGDCONT=%d,\"%s\",\"%s\",,%d,%d",
		context_id, pdp_type_str, apn, d_comp, h_comp);
	dbg("AT-Command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(o,
		at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		NULL,
		on_response_ps_define_context, ps_context,
		on_send_at_request, NULL,
		0, NULL, NULL);

	g_free(pdp_type_str);
	g_free(at_cmd);
	g_free(apn);

	if (ret == TCORE_RETURN_SUCCESS)
		goto out;

error:
	err("Failed to prepare and send AT request");
	__notify_context_status_changed(o, context_id, 3);

out:
	dbg("Exit");
	return ret;
}

/* PS Operations */
static struct tcore_ps_operations ps_ops = {
	.define_context = define_ps_context,
	.activate_context = activate_ps_context,
	.deactivate_context = deactivate_ps_context
};


gboolean s_ps_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *o;

	dbg("Entry");
	o = tcore_ps_new(p, "umts_ps", &ps_ops, h);
	if (!o)
		return FALSE;

	dbg("Exit");
	return TRUE;
}

void s_ps_exit(TcorePlugin *p)
{
	CoreObject *o;

	o = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_PS);
	CHECK_AND_RETURN(o != NULL);

	tcore_ps_free(o);
	dbg("Exit");
}
