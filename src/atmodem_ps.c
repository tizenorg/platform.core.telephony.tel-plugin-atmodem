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

#include <co_ps.h>
#include <co_context.h>

#include "atmodem_ps.h"
#include "atmodem_common.h"

typedef struct {
	TcorePsCallState ps_call_status;
} PrivateInfo;

static void __notify_context_status_changed(CoreObject *co_ps, guint context_id,
						TcorePsCallState status)
{
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	TcorePsCallStatusInfo data_resp = {0,};
	tcore_check_return_assert(private_info != NULL);

	dbg("Entry");

	private_info->ps_call_status = status;
	data_resp.context_id = context_id;
	data_resp.state = status;
	dbg("Sending PS Call Status Notification - Context ID: [%d] Context State: [%d]",
					data_resp.context_id, data_resp.state);

	/* Send PS CALL Status Notification */
	(void)tcore_object_send_notification(co_ps,
			TCORE_NOTIFICATION_PS_CALL_STATUS,
			sizeof(TcorePsCallStatusInfo),
			&data_resp);

	dbg("Exit");
}

static void __atmodem_ps_setup_pdp(CoreObject *co_ps, gint result, const gchar *netif_name,
				void *user_data)
{
	CoreObject *ps_context = user_data;
	guint context_id;

	tcore_check_return_assert(ps_context != NULL);

	dbg("Enter");

	if (result < 0) {
		/* Deactivate PDP context */
		(void)tcore_object_dispatch_request(co_ps, TRUE,
				TCORE_COMMAND_PS_DEACTIVATE_CONTEXT,
				NULL, 0,
				NULL, NULL);

		return;
	}

	dbg("devname = [%s]", netif_name);

	tcore_context_set_ipv4_devname(ps_context, netif_name);

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	__notify_context_status_changed(co_ps, context_id, TCORE_PS_CALL_STATE_CONNECTED);

	dbg("Exit");
}

static void __on_response_atmodem_get_ipconfiguration(TcorePending *p, guint data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	const TcoreAtResponse *at_resp = data;
	TcoreHal *hal = tcore_object_get_hal(co_ps);
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	guint context_id;
	TcorePsCallState curr_call_status;
	GSList *p_cur = NULL;

	(void)tcore_context_get_id(ps_context, &context_id);

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
				if (atoi(p_cid) && (context_id == (unsigned int)atoi(p_cid)))	{
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

					(void)tcore_context_set_ipv4_addr(ps_context, (const char*)pdp_address);
					tcore_free(pdp_address);

					dbg("Adding default DNS pri: 8.8.8.8 sec: 8.8.4.4");

					tcore_context_set_ipv4_dns(ps_context, "8.8.8.8", "8.8.4.4");

					/* Mount network interface */
					if (tcore_hal_setup_netif(hal, co_ps, __atmodem_ps_setup_pdp, ps_context, context_id, TRUE)
							!= TEL_RETURN_SUCCESS) {
						err("Setup network interface failed");
						return;
					}
				} else {
					err("No matched response with CID: %d", atoi(p_cid));
				}
			}
		}
	}else {
		err("Response NOK");

		(void)tcore_context_get_id(ps_context, &context_id);

		curr_call_status = private_info->ps_call_status;

		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
}

static void __atmodem_get_ipconfiguration(CoreObject *co_ps, CoreObject *ps_context)
{
	TelReturn ret;

	dbg("Enter");

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		"AT+CGDCONT?", NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		__on_response_atmodem_get_ipconfiguration,
		ps_context,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);

	if (ret != TEL_RETURN_SUCCESS){
		err("Failed to prepare and send AT request");
		/* Deactivate PDP context */
		(void)tcore_object_dispatch_request(co_ps, TRUE,
				TCORE_COMMAND_PS_DEACTIVATE_CONTEXT,
				NULL, 0,
				NULL, NULL);
	}

	dbg("Exit");
}

static void __on_response_atmodem_attach_ps(TcorePending *p, guint data_len,
					const void *data, void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	const TcoreAtResponse *at_resp = data;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	guint context_id;
	TcorePsCallState curr_call_status;

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);

	if (at_resp && at_resp->success) {
		__atmodem_get_ipconfiguration(co_ps, ps_context);
		return;
	}

	err("Response NOK");

	(void)tcore_context_get_id(ps_context, &context_id);

	curr_call_status = private_info->ps_call_status;

	__notify_context_status_changed(co_ps, context_id, curr_call_status);

	dbg("Exit");
}

static void __atmodem_attach_ps(CoreObject *co_ps, CoreObject *ps_context)
{
	TelReturn ret;

	dbg("Enter");

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		"ATD*99***1#", NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		__on_response_atmodem_attach_ps,
		ps_context,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);

	if (ret != TEL_RETURN_SUCCESS){
		err("Failed to prepare and send AT request");
		/* Deactivate PDP context */
		(void)tcore_object_dispatch_request(co_ps, TRUE,
				TCORE_COMMAND_PS_DEACTIVATE_CONTEXT,
				NULL, 0,
				NULL, NULL);
	}

	dbg("Exit");
}

static void on_response_atmodem_ps_activate_context(TcorePending *p, guint data_len,
							const void *data,
							void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	const TcoreAtResponse *at_resp = data;
	CoreObject *ps_context = user_data;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	tcore_check_return_assert(private_info != NULL);

	dbg("Enter");

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		__atmodem_attach_ps(co_ps, ps_context);
	} else {
		guint context_id;
		TcorePsCallState curr_call_status;

		(void)tcore_context_get_id(ps_context, &context_id);

		err("Response NOK");
		curr_call_status = private_info->ps_call_status;
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}

	dbg("Exit");
}

static void on_response_atmodem_ps_deactivate_context(TcorePending *p, guint data_len,
							const void *data,
							void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	TcoreHal *hal = tcore_object_get_hal(co_ps);
	const TcoreAtResponse *at_resp = data;
	CoreObject *ps_context = user_data;
	guint context_id;

	dbg("Enter");

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);

	(void)tcore_context_get_id(ps_context, &context_id);
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

	__notify_context_status_changed(co_ps, context_id, TCORE_PS_CALL_STATE_NOT_CONNECTED);

	if (tcore_hal_setup_netif(hal, co_ps, NULL, NULL, context_id, FALSE) != TEL_RETURN_SUCCESS)
		err("Failed to disable network interface");

out:
	dbg("Exit");
}

static void on_response_atmodem_ps_define_context(TcorePending *p,
				guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *ps_context = (CoreObject *) user_data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	guint context_id;
	TcorePsCallState curr_call_status;

	dbg("entry");

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);
	tcore_check_return_assert(private_info != NULL);

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		curr_call_status = TCORE_PS_CALL_STATE_CTX_DEFINED;
		tcore_context_set_state(co_ps, curr_call_status);
	}else {
		err("ERROR[%s]",at_resp->final_response);
		curr_call_status =private_info->ps_call_status;
	}
	(void)tcore_context_get_id(ps_context, &context_id);
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

static TelReturn atmodem_ps_activate_context(CoreObject *co_ps, CoreObject *ps_context,
				TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	TelReturn ret;
	guint context_id;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	tcore_check_return_value_assert(private_info != NULL, TEL_RETURN_INVALID_PARAMETER);

	dbg("Entry");

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	at_cmd = g_strdup_printf("AT+CGACT=1,%d", context_id);
	dbg(" at command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_atmodem_ps_activate_context,
		ps_context,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);

	if (ret != TEL_RETURN_SUCCESS){
		TcorePsCallState curr_call_status;

		curr_call_status = private_info->ps_call_status;
		err("AT request failed. Send notification for call status [%d]", curr_call_status);
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
	tcore_free(at_cmd);
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
static TelReturn atmodem_ps_deactivate_context(CoreObject *co_ps, CoreObject *ps_context,
				TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd = NULL;
	TelReturn ret;
	guint context_id;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	tcore_check_return_value_assert(private_info != NULL, TEL_RETURN_INVALID_PARAMETER);

	dbg("Entry");

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	at_cmd = g_strdup_printf("AT+CGACT=0,%d", context_id);
	dbg(" at command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_atmodem_ps_deactivate_context,
		ps_context,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);

	if (ret != TEL_RETURN_SUCCESS){
		TcorePsCallState curr_call_status;

		curr_call_status = private_info->ps_call_status;
		err("AT request failed. Send notification for call status [%d]", curr_call_status);
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
	tcore_free(at_cmd);
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
static TelReturn atmodem_ps_define_context(CoreObject *co_ps, CoreObject *ps_context,
				TcoreObjectResponseCallback cb, void *cb_data)
{
	guint context_id = 0;
	gchar *at_cmd = NULL;
	gchar *apn = NULL;
	gchar *pdp_type_str = NULL;
	TcoreContextType pdp_type;
	TcoreContextDComp d_comp;
	TcoreContextHComp h_comp;
	TelReturn ret = TEL_RETURN_FAILURE;
	TcorePsCallState curr_call_status;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	tcore_check_return_value_assert(private_info != NULL, TEL_RETURN_INVALID_PARAMETER);

	dbg("Entry");

	(void)tcore_context_get_id(ps_context, &context_id);
	(void)tcore_context_get_type(ps_context, &pdp_type);

	switch (pdp_type) {
	case TCORE_CONTEXT_TYPE_X25:
		dbg("CONTEXT_TYPE_X25");
		pdp_type_str = g_strdup("X.25");
	break;

	case TCORE_CONTEXT_TYPE_IP:
		dbg("CONTEXT_TYPE_IP");
		pdp_type_str = g_strdup("IP");
	break;

	case TCORE_CONTEXT_TYPE_PPP:
		dbg("CONTEXT_TYPE_PPP");
		pdp_type_str = g_strdup("PPP");
	break;

	case TCORE_CONTEXT_TYPE_IPV6:
		dbg("CONTEXT_TYPE_IPV6");
		pdp_type_str = g_strdup("IPV6");
		break;

	default:
		/*PDP Type not supported*/
		dbg("Unsupported PDP type: %d", pdp_type);
		goto error;
	}

	(void)tcore_context_get_data_compression(ps_context, &d_comp);
	(void)tcore_context_get_header_compression(ps_context, &h_comp);
	(void) tcore_context_get_apn(ps_context, &apn);

	dbg("Define context for CID: %d", context_id);
	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CGDCONT=%d,\"%s\",\"%s\",,%d,%d", context_id, pdp_type_str, apn, d_comp, h_comp);
	dbg(" at command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_atmodem_ps_define_context,
		ps_context,
		on_send_atmodem_request, NULL,
		0, NULL, NULL);

	tcore_free(pdp_type_str);
	tcore_free(at_cmd);
	tcore_free(apn);

	if (ret == TEL_RETURN_SUCCESS)
		goto out;

error:
	err("Failed to prepare and send AT request");

	curr_call_status = private_info->ps_call_status;
	__notify_context_status_changed(co_ps, context_id, curr_call_status);

out:
	dbg("Exit");
	return ret;
}

/* PS Operations */
static TcorePsOps atmodem_ps_ops = {
	.define_context = atmodem_ps_define_context,
	.activate_context = atmodem_ps_activate_context,
	.deactivate_context = atmodem_ps_deactivate_context
};


gboolean atmodem_ps_init(TcorePlugin *p, CoreObject *co)
{
	PrivateInfo *private_info;

	dbg("Entry");

	/* Set PrivateInfo */
	private_info = tcore_malloc0(sizeof(PrivateInfo));
	tcore_object_link_user_data(co, private_info);

	/* Set operations */
	tcore_ps_set_ops(co, &atmodem_ps_ops);

	dbg("Exit");
	return TRUE;
}

void atmodem_ps_exit(TcorePlugin *p, CoreObject *co)
{
	PrivateInfo *private_info;

	private_info = tcore_object_ref_user_data(co);
	tcore_check_return_assert(private_info != NULL);

	tcore_free(private_info);

	dbg("Exit");
}
