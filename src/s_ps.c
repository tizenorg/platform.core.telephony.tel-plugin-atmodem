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


static TReturn _pdp_device_control(gboolean flag, unsigned int context_id)
{
	int size = 0;
	int fd = 0;
	char buf[32];
	char *control = NULL;

	if (context_id > 3)
		return TCORE_RETURN_EINVAL;

	if (flag)
		control = "/sys/class/net/svnet0/pdp/activate";
	else
		control = "/sys/class/net/svnet0/pdp/deactivate";

	fd = open(control, O_WRONLY);
	if (fd < 0) {
		return TCORE_RETURN_FAILURE;
	}

	snprintf(buf, sizeof(buf), "%d", context_id);
	size = write(fd, buf, strlen(buf));

	close(fd);
	return TCORE_RETURN_SUCCESS;
}

static void on_event_ps_ipconfiguration(CoreObject *o, const void *event_info, void *user_data)
{
	/* Parsing the response line and map into noti. */
	CoreObject *ps_context = (CoreObject *)user_data;
	unsigned int pdpContextCnt, cid = tcore_context_get_id(ps_context);
	struct ATLine *p_cur = NULL;
	const struct ATResponse *p_response = event_info;
	int err, ret, p_cid=0, d_comp = -1, h_comp = -1;
	struct tnoti_ps_pdp_ipconfiguration noti;
	char devname[10] = {0,};
	char addr_buf[5][20];
	char *pdp_type = NULL, *apn = NULL;
	char *line = NULL, *ip = NULL, *gateway = NULL;//, *netmask = NULL;

	/* count the PDP contexts */
	for (pdpContextCnt = 0, p_cur = p_response->p_intermediates
			; p_cur != NULL
			; p_cur = p_cur->p_next) {
		pdpContextCnt++;
	}

	dbg("Total number of PDP contexts : %d",pdpContextCnt);

	if(pdpContextCnt == 0)
		return;

	for (p_cur = p_response->p_intermediates
			; p_cur != NULL
			; p_cur = p_cur->p_next) {
		line = p_response->p_intermediates->line;

		err = at_tok_start(&line);
		err = at_tok_nextint(&line,&p_cid);
		dbg("cid: %d", p_cid);

		/* Send IP Configuration noti only on the requested CID. */
		if (p_cid && (cid == (unsigned int)p_cid))	{
			err = at_tok_nextstr(&line,&pdp_type);
			dbg("PDP type: %s", pdp_type);

			if (pdp_type!=NULL)	{
				err = at_tok_nextstr(&line,&apn);
				dbg("APN: %s", apn);
			}
			if (apn !=NULL) {
				err = at_tok_nextstr(&line,&ip);
				dbg("IP address: %s", ip);
			}
			if (ip !=NULL) {
				err = at_tok_nextint(&line,&d_comp);
				dbg("d_comp: %d", d_comp);
			}
			if (d_comp != -1) {
				err = at_tok_nextint(&line,&h_comp);
				dbg("h_comp: %d", h_comp);
			}

			memset(&noti, 0, sizeof(struct tnoti_ps_pdp_ipconfiguration));

			noti.context_id = cid;
			noti.err = 0;

			/* Just use AF_INET here. */
			ret = inet_pton(AF_INET, ip, &noti.ip_address);
			if (ret < 1) {
				dbg("inet_pton() failed.");
				return;
			}

			snprintf(addr_buf[0], 20, "%d.%d.%d.%d", noti.ip_address[0], noti.ip_address[1],
					noti.ip_address[2], noti.ip_address[3]);
			ip = addr_buf[0];
			dbg("ip = [%s]", ip);

			noti.primary_dns[0] = 8;
			noti.primary_dns[1] = 8;
			noti.primary_dns[2] = 8;
			noti.primary_dns[3] = 8;
			dbg("primary_dns = [8.8.8.8] Public DNS server.");

			noti.secondary_dns[0] = 8;
			noti.secondary_dns[1] = 8;
			noti.secondary_dns[2] = 4;
			noti.secondary_dns[3] = 4;
			dbg("secondary_dns = [8.8.4.4] Public DNS server.");

			memcpy(&noti.gateway, &noti.ip_address, 4);
			noti.gateway[3] = 1;
			snprintf(addr_buf[3], 20, "%d.%d.%d.%d", noti.gateway[0], noti.gateway[1], noti.gateway[2],
					noti.gateway[3]);
			gateway = addr_buf[3];
			dbg("gateway = [%s]", gateway);

			/* FIX ME: use static netmask. */
			noti.subnet_mask[0] = 255;
			noti.subnet_mask[1] = 255;
			noti.subnet_mask[2] = 255;
			noti.subnet_mask[3] = 0;
			dbg("subnet_mask = [255.255.255.0]");

			if (_pdp_device_control(TRUE, cid) != TCORE_RETURN_SUCCESS) {
				dbg("_pdp_device_control() failed. errno=%d", errno);
			}

			snprintf(devname, 10, "pdp%d", cid - 1);
			memcpy(noti.devname, devname, 10);
			dbg("devname = [%s]", devname);

			if (tcore_util_netif_up(devname) != TCORE_RETURN_SUCCESS) {
				dbg("util_netif_up() failed. errno=%d", errno);
			}
			tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_PS_PDP_IPCONFIGURATION,
					sizeof(struct tnoti_ps_pdp_ipconfiguration), &noti);
		}
		else
			dbg("No matched response with CID: %d",cid);
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
	printResponse();

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");
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

gboolean s_ps_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *o;
	GQueue *work_queue;

	o = tcore_ps_new(p, "umts_ps", &ps_ops, h);
	if (!o)
		return FALSE;

	work_queue = g_queue_new();
	tcore_object_link_user_data(o, work_queue);

	return TRUE;
}

void s_ps_exit(TcorePlugin *p)
{
	CoreObject *o;
	GQueue *work_queue;

	o = tcore_plugin_ref_core_object(p, "umts_ps");
	if (!o)
		return;

	work_queue = tcore_object_ref_user_data(o);
	if (work_queue)
		g_queue_free(work_queue);

	tcore_ps_free(o);
}
