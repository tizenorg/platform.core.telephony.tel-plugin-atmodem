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

#include "s_common.h"
#include "s_ps.h"

#include "atchannel.h"
#include "at_tok.h"

extern struct ATResponse *sp_response;
extern char *s_responsePrefix;
extern enum ATCommandType s_type;

static void on_confirmation_ps_message_send( TcorePending *p, gboolean result, void *user_data )
{
	UserRequest* ur = NULL;
	struct ATReqMetaInfo* metainfo = NULL;
	unsigned int info_len =0;
	dbg("on_confirmation_ps_message_send - msg out from queue. alloc ATRsp buffer & write rspPrefix if needed\n");

	ReleaseResponse(); // release leftover
    //alloc new sp_response
	sp_response = at_response_new();

	ur = tcore_pending_ref_user_request(p);
	metainfo = (struct ATReqMetaInfo*)tcore_user_request_ref_metainfo(ur,&info_len);

	if ((metainfo->type == SINGLELINE)||(metainfo->type == MULTILINE))	{
		//cp rsp prefix
		s_responsePrefix = strdup(metainfo->responsePrefix);
		dbg("duplicating responsePrefix : %s\n", s_responsePrefix);
	}
	else {
		s_responsePrefix = NULL;
	}

	//set atcmd type into s_type
	s_type = metainfo->type;

	if (result == FALSE) {
		/* Fail */
		dbg("SEND FAIL");
	}
	else {
		dbg("SEND OK");
	}
}

static void on_setup_pdp(CoreObject *co_ps, int result,
			const char *netif_name, void *user_data)
{
	CoreObject *ps_context = user_data;
	struct tnoti_ps_call_status data_status = {0};
	Server *server;

	dbg("Entry");

	if (result < 0) {
		/* Deactivate PDP context */
		tcore_ps_deactivate_context(co_ps, ps_context, NULL);
		return;
	}

	dbg("Device name: [%s]", netif_name);

	/* Set Device name */
	tcore_context_set_ipv4_devname(ps_context, netif_name);

	/* Set State - CONNECTED */
	data_status.context_id = tcore_context_get_id(ps_context);
	data_status.state = PS_DATA_CALL_CONNECTED;
	dbg("Sending Call Status Notification - Context ID: [%d] Context State: [CONNECTED]", data_status.context_id);

	/* Send Notification */
	server = tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps));
	tcore_server_send_notification(server, co_ps,
					TNOTI_PS_CALL_STATUS,
					sizeof(struct tnoti_ps_call_status),
					&data_status);

	dbg("Exit");
}

static void on_event_ps_ipconfiguration(CoreObject *o, const void *event_info, void *user_data)
{
	/* Parsing the response line and map into noti. */
	CoreObject *ps_context = (CoreObject *)user_data;
	unsigned int cid = tcore_context_get_id(ps_context);
	struct ATLine *p_cur = NULL;
	const struct ATResponse *p_response = event_info;
	int err, p_cid = 0, d_comp = -1, h_comp = -1;
	char *pdp_type = NULL, *apn = NULL;
	char *line = NULL, *ip = NULL;
	TcoreHal *h = tcore_object_get_hal(o);

	for (p_cur = p_response->p_intermediates; p_cur != NULL;
			p_cur = p_cur->p_next) {
		line = p_response->p_intermediates->line;

		err = at_tok_start(&line);
		err = at_tok_nextint(&line,&p_cid);
		dbg("cid: %d", p_cid);

		/* Send IP Configuration noti only on the requested CID. */
		if (p_cid && (cid == (unsigned int)p_cid))	{
			err = at_tok_nextstr(&line,&pdp_type);
			dbg("PDP type: %s", pdp_type);

			if (pdp_type != NULL)	{
				err = at_tok_nextstr(&line,&apn);
				dbg("APN: %s", apn);
			}
			if (apn != NULL) {
				err = at_tok_nextstr(&line,&ip);
				dbg("IP address: %s", ip);
			}
			if (ip != NULL) {
				err = at_tok_nextint(&line,&d_comp);
				dbg("d_comp: %d", d_comp);
			}
			if (d_comp != -1) {
				err = at_tok_nextint(&line,&h_comp);
				dbg("h_comp: %d", h_comp);
			}

			(void)tcore_context_set_ipv4_addr(ps_context, (const char *)ip);

			dbg("ip = [%s]", ip);

			(void)tcore_context_set_ipv4_addr(ps_context, (const char *)ip);

			dbg("Adding default DNS pri: 8.8.8.8 sec: 8.8.4.4")

			tcore_context_set_ipv4_dns(ps_context, "8.8.8.8", "8.8.4.4");

			/* Mount network interface */
			if (tcore_hal_setup_netif(h, o, on_setup_pdp, ps_context, cid, TRUE)
					!= TCORE_RETURN_SUCCESS) {
				err("Setup network interface failed");
				return;
			}
		} else {
			dbg("No matched response with CID: %d", cid);
			tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
		}
	}
}

static void on_response_get_ipconfiguration(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	struct ATLine *p_cur;
	CoreObject *ps_context = (CoreObject *)user_data;
	char *line = NULL;

	printResponse();

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");

		for (p_cur = sp_response->p_intermediates
				; p_cur != NULL
				; p_cur = p_cur->p_next) {
			line = sp_response->p_intermediates->line;
			dbg("%s\n", line);
		}

		dbg("Call on_ipc_event_ps_ipconfiguration");
		on_event_ps_ipconfiguration(tcore_pending_ref_core_object(pending), sp_response, ps_context);
	}
	else {
		dbg("RESPONSE NOK");
		tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
	}

	ReleaseResponse();
}

static void on_response_ps_attached(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcorePlugin *pl = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	CoreObject *o = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = (CoreObject *)user_data;
	UserRequest *ur;

	char* cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;
	char* line = NULL;

	printResponse();

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");
		line = sp_response->p_intermediates->line;
		dbg("on_response_ps_attached: %s", line);

		ur = tcore_user_request_new(NULL, NULL);
		memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
		memcpy(metainfo.responsePrefix,"+CGDCONT:",strlen("+CGDCONT:"));
		metainfo.type = MULTILINE;
		info_len = sizeof(struct ATReqMetaInfo);

		tcore_user_request_set_metainfo(ur, info_len, &metainfo);

		dbg(" Send: AT+CGDCONT?\r ");
		cmd_str = g_strdup("AT+CGDCONT?\r");

		pl = tcore_object_ref_plugin(o);
		h = tcore_object_get_hal(o);
		pending = tcore_pending_new(o, ID_RESERVED_AT);
		tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
		free(cmd_str);

		tcore_pending_set_timeout(pending, 0);
		tcore_pending_set_response_callback(pending, on_response_get_ipconfiguration, ps_context);
		tcore_pending_link_user_request(pending, ur);
		tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
		tcore_pending_set_send_callback(pending, on_confirmation_ps_message_send, NULL);
		tcore_hal_send_request(h, pending);
	}
	else {
		dbg("RESPONSE NOK");
		tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
	}

	ReleaseResponse();
}

static void on_response_active_set(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcorePlugin *pl = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	CoreObject *o = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = (CoreObject *)user_data;
	UserRequest *ur;

	char* cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	printResponse();

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");

		ur = tcore_user_request_new(NULL, NULL);
		memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
		metainfo.type = SINGLELINE;
		info_len = sizeof(struct ATReqMetaInfo);

		tcore_user_request_set_metainfo(ur, info_len, &metainfo);

		dbg(" Send: ATD*99***1#\r ");
		cmd_str = g_strdup("ATD*99***1#\r");

		pl = tcore_object_ref_plugin(o);
		h = tcore_object_get_hal(o);
		pending = tcore_pending_new(o, ID_RESERVED_AT);

		tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
		free(cmd_str);

		tcore_pending_set_timeout(pending, 0);
		tcore_pending_set_response_callback(pending, on_response_ps_attached, ps_context);
		tcore_pending_link_user_request(pending, ur);
		tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
		tcore_pending_set_send_callback(pending, on_confirmation_ps_message_send, NULL);
		tcore_hal_send_request(h, pending);
	}
	else {
		dbg("RESPONSE NOK");
		tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
	}

	ReleaseResponse();
}

static void on_response_deactive_set(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *ps_context = user_data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	TcoreHal *h = tcore_object_get_hal(co_ps);
	unsigned int cid = tcore_context_get_id(ps_context);

	printResponse();

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");
		if (tcore_hal_setup_netif(h, co_ps, NULL, ps_context, cid,
				FALSE) != TCORE_RETURN_SUCCESS)
			err("Failed to disable network interface");

		tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
	}
	else {
		dbg("RESPONSE NOK");
	}

	ReleaseResponse();
}

static TReturn activate_ps_context(CoreObject *o, CoreObject *ps_context, void* user_data)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	UserRequest *ur;

	unsigned int cid;
	char* cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	if ( !o )
		return TCORE_RETURN_FAILURE;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);


	ur = tcore_user_request_new(NULL, NULL);
	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cid = tcore_context_get_id(ps_context);

	dbg("Example: AT+CGACT=1,0");
	cmd_str = g_strdup_printf("%s=%d,%d%s","AT+CGACT", 1, cid, "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	free(cmd_str);

	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_active_set, ps_context);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_send_callback(pending, on_confirmation_ps_message_send, NULL);
	tcore_hal_send_request(h, pending);

	return TRUE;
}

static void on_response_define_pdp(TcorePending *p, int data_len, const void *data, void *user_data)
{
	//CoreObject *ps_context = user_data;

	printResponse();

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");
		//pdp_active_set(tcore_pending_ref_core_object(p), ps_context);
	}
	else {
		dbg("RESPONSE NOK");
		tcore_context_set_state(tcore_pending_ref_core_object(p), CONTEXT_STATE_DEACTIVATED);
	}

	ReleaseResponse();
}

static TReturn define_ps_context(CoreObject *o, CoreObject *ps_context, void *user_data)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	UserRequest *ur;

	char *apn=NULL, *addr=NULL;

	unsigned int cid;
	enum co_context_type pdp_type;
	enum co_context_d_comp d_comp;
	enum co_context_h_comp h_comp;
	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	if ( !o )
		return TCORE_RETURN_FAILURE;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);
    ur = tcore_user_request_new(NULL, NULL);
	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cid = tcore_context_get_id(ps_context);
	pdp_type = tcore_context_get_type(ps_context);
	d_comp = tcore_context_get_data_compression(ps_context);
	h_comp = tcore_context_get_header_compression(ps_context);

	dbg("Example: AT+CGDCONT=1,\"IP\",\"www.example.co.kr\",,0,0");
	cmd_str = g_strdup_printf("AT+CGDCONT=%d,\"%d\",\"%s\",%s,%d,%d%s",
			cid, pdp_type, apn, addr, d_comp, h_comp, "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	free(cmd_str);

	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_define_pdp, ps_context);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_send_callback(pending, on_confirmation_ps_message_send, NULL);
	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn deactivate_ps_context(CoreObject *o, CoreObject *ps_context, void *user_data)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	UserRequest *ur;

	unsigned int cid;
	char* cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	if ( !o )
		return TCORE_RETURN_FAILURE;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);
	ur = tcore_user_request_new(NULL, NULL);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	info_len = sizeof(struct ATReqMetaInfo);

	cid = tcore_context_get_id(ps_context);

	dbg("Example: AT+CGACT=0,1");
	cmd_str = g_strdup_printf("%s=%d,%d%s","AT+CGACT", 0, cid, "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	free(cmd_str);

	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_deactive_set, ps_context);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_send_callback(pending, on_confirmation_ps_message_send, NULL);
	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static struct tcore_ps_operations ps_ops =
{
	.define_context = define_ps_context,
	.activate_context = activate_ps_context,
	.deactivate_context = deactivate_ps_context
};

gboolean s_ps_init(TcorePlugin *cp, CoreObject *co)
{
	GQueue *work_queue;

	dbg("Entry");

	tcore_ps_override_ops(co, &ps_ops);

	work_queue = g_queue_new();
	tcore_object_link_user_data(co, work_queue);

	dbg("Exit");

	return TRUE;
}

void s_ps_exit(TcorePlugin *cp, CoreObject *co)
{
	GQueue *work_queue;

	work_queue = tcore_object_ref_user_data(co);
	if (work_queue)
		g_queue_free(work_queue);

	dbg("Exit");
}
