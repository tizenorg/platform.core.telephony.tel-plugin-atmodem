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

#include "s_common.h"
#include "s_modem.h"

#include "atchannel.h"
#include "at_tok.h"

#define MAX_VERSION_LEN	32
#define TAPI_MISC_ME_SN_LEN_MAX		32
#define TAPI_MISC_PRODUCT_CODE_LEN_MAX		32
#define TAPI_MISC_MODEL_ID_LEN_MAX		17
#define TAPI_MISC_PRL_ERI_VER_LEN_MAX		17

enum cp_state {
	CP_STATE_OFFLINE,
	CP_STATE_CRASH_RESET,
	CP_STATE_CRASH_EXIT,
	CP_STATE_BOOTING,
	CP_STATE_ONLINE,
	CP_STATE_NV_REBUILDING,
	CP_STATE_LOADER_DONE,
};


enum TelMiscSNIndexType_t{
	TAPI_MISC_ME_IMEI = 0x00, /**< 0x00: IMEI, GSM/UMTS device */
	TAPI_MISC_ME_ESN = 0x01, /**< 0x01: ESN(Electronic Serial Number), It`s essentially run out. CDMA device */
	TAPI_MISC_ME_MEID = 0x02, /**< 0x02: MEID, This value can have hexa decimal digits. CDMA device */
	TAPI_MISC_ME_MAX = 0xff /**< 0xff: reserved */
};

struct TelMiscSNInformation{
	enum TelMiscSNIndexType_t sn_index; /**< serial number index */
	int sn_len; /**< Length */
	unsigned char szNumber[TAPI_MISC_ME_SN_LEN_MAX]; /**< Number */
};

/**
 * Mobile Equipment Version Information
 */
struct TelMiscVersionInformation{
	unsigned char ver_mask; /**< version mask  - 0x01:SW_ver, 0x02:HW_ver, 0x04:RF_CAL_date, 0x08:Product_code, 0x10:Model_ID, 0x20:PRL, 0x04:ERI, 0xff:all */
	unsigned char szSwVersion[MAX_VERSION_LEN]; /**< Software version, null termination */
	unsigned char szHwVersion[MAX_VERSION_LEN]; /**< Hardware version, null termination */
	unsigned char szRfCalDate[MAX_VERSION_LEN]; /**< Calculation Date, null termination */
	unsigned char szProductCode[TAPI_MISC_PRODUCT_CODE_LEN_MAX]; /**< product code, null termination */
	unsigned char szModelId[TAPI_MISC_MODEL_ID_LEN_MAX]; /**< model id (only for CDMA), null termination */
	unsigned char prl_nam_num; /**< number of PRL NAM fields */
	unsigned char szPrlVersion[TAPI_MISC_PRL_ERI_VER_LEN_MAX * 3];/**< prl version (only for CDMA), null termination */
	unsigned char eri_nam_num; /**< number of PRL NAM fields */
	unsigned char szEriVersion[TAPI_MISC_PRL_ERI_VER_LEN_MAX * 3];/**< eri version (only for CDMA), null termination */
};

extern struct ATResponse *sp_response;
extern char *s_responsePrefix;
extern enum ATCommandType s_type;

static void on_confirmation_modem_message_send(TcorePending *p, gboolean result, void *user_data ); // from Kernel

static void on_confirmation_modem_message_send( TcorePending *p, gboolean result, void *user_data )
{
	UserRequest* ur = NULL;
	struct ATReqMetaInfo* metainfo = NULL;
	unsigned int info_len =0;
	dbg("on_confirmation_modem_message_send - msg out from queue. alloc ATRsp buffer & write rspPrefix if needed\n");

	ReleaseResponse(); // release leftover
//alloc new sp_response
	sp_response = at_response_new();


	ur = tcore_pending_ref_user_request(p);
	metainfo = (struct ATReqMetaInfo*)tcore_user_request_ref_metainfo(ur,&info_len);

	if((metainfo->type == SINGLELINE)||
		(metainfo->type == MULTILINE))
	{
		//cp rsp prefix
		s_responsePrefix = strdup(metainfo->responsePrefix);
		dbg("duplicating responsePrefix : %s\n", s_responsePrefix);
	}
	else
	{
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
static gboolean on_sys_event_modem_power(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_modem_power modem_power;
	enum cp_state *state;

	state = (enum cp_state*)event_info;
	dbg("state : (0x%x)", *state);

	if ( *state == CP_STATE_OFFLINE || *state == CP_STATE_CRASH_RESET ) {

		tcore_modem_set_powered(o, FALSE);

		if ( *state == CP_STATE_OFFLINE )
			modem_power.state = MODEM_STATE_OFFLINE;
		else
			modem_power.state = MODEM_STATE_ERROR;

	} else {
		dbg("useless state : (0x%x)", *state);
		return TRUE;
	}

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_MODEM_POWER,
			sizeof(struct tnoti_modem_power), &modem_power);

	return TRUE;
}

static gboolean on_event_modem_power(CoreObject *o, const void *event_info, void *user_data)
{
	struct treq_modem_set_flightmode flight_mode_set;
	struct tnoti_modem_power modem_power;
	UserRequest *ur;
	TcoreHal *h;
	Storage *strg;

	strg = tcore_server_find_storage(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), "vconf");
	flight_mode_set.enable = tcore_storage_get_bool(strg, STORAGE_KEY_FLIGHT_MODE_BOOL);

	h = tcore_object_get_hal(o);

	tcore_hal_set_power_state(h, TRUE);

	ur = tcore_user_request_new(NULL, NULL);
	tcore_user_request_set_data(ur, sizeof(struct treq_modem_set_flightmode), &flight_mode_set);
	tcore_user_request_set_command(ur, TREQ_MODEM_SET_FLIGHTMODE);
	tcore_object_dispatch_request(o, ur);

	ur = tcore_user_request_new(NULL, NULL);
	tcore_user_request_set_command(ur, TREQ_MODEM_GET_IMEI);
	tcore_object_dispatch_request(o, ur);

	ur = tcore_user_request_new(NULL, NULL);
	tcore_user_request_set_command(ur, TREQ_MODEM_GET_VERSION);
	tcore_object_dispatch_request(o, ur);

	tcore_modem_set_powered(o, TRUE);

	modem_power.state = MODEM_STATE_ONLINE;

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_MODEM_POWER,
			sizeof(struct tnoti_modem_power), &modem_power);

	return TRUE;
}

static gboolean on_event_modem_phone_state(CoreObject *o, const void *event_info, void *user_data)
{
	char* line = (char*)event_info;
	GQueue *queue;
	UserRequest *ur;
	int err, status;
	struct tresp_modem_set_flightmode res;
	struct tnoti_modem_flight_mode modem_flight_mode;
	const struct treq_modem_set_flightmode *req_data = NULL;
#define SCFUN_MIN_FUNC 0
#define SCFUN_FULL_FUNC 1

	dbg("received notification : %s", line);

	at_tok_start(&line);

	err = at_tok_nextint(&line, &status);

	switch (status) {
		case SCFUN_MIN_FUNC:
			res.result = 0x01;
			tcore_modem_set_flight_mode_state(o, TRUE);
			break;

		case SCFUN_FULL_FUNC:
			res.result = 0x02;
			tcore_modem_set_flight_mode_state(o, FALSE);
			break;
	}

	queue = tcore_object_ref_user_data(o);
	if (queue) {
		ur = util_pop_waiting_job(queue, ID_RESERVED_AT);
		if (ur) {
			req_data = tcore_user_request_ref_data(ur, NULL);

			if (TRUE == req_data->enable)
				res.result = 1;
			else
				res.result = 2;

			tcore_user_request_send_response(ur, TRESP_MODEM_SET_FLIGHTMODE, sizeof(struct tresp_modem_set_flightmode), &res);
		}
	}

	modem_flight_mode.enable = tcore_modem_get_flight_mode_state(o);

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_MODEM_FLIGHT_MODE,
			sizeof(struct tnoti_modem_flight_mode), &modem_flight_mode);

	return TRUE;
}

static void on_response_poweron(TcorePending *p, int data_len, const void *data, void *user_data)
{
	printResponse();

	if(sp_response->success > 0) {
		dbg("RESPONSE OK");
		ReleaseResponse();
		on_event_modem_power(tcore_pending_ref_core_object(p), NULL, NULL);
	} else{
		dbg("RESPONSE NOK");
		ReleaseResponse();
		s_modem_send_poweron(tcore_object_ref_plugin(tcore_pending_ref_core_object(p)));
	}
}

static void on_response_set_flight_mode(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *o = user_data;
	UserRequest *ur;
	struct tresp_modem_set_flightmode res;
	GQueue *queue;

//print sp_response - for debug
	printResponse();
	ur = tcore_pending_ref_user_request(p);

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");
		//parse response
		queue = tcore_object_ref_user_data(o);
		if (queue) {
			ur = tcore_user_request_ref(ur);
			util_add_waiting_job(queue, ID_RESERVED_AT, ur);
		}

		ReleaseResponse();
	} else {
		dbg("RESPONSE NOK");
		res.result = 3;

		ReleaseResponse();

		tcore_user_request_send_response(ur, TRESP_MODEM_SET_FLIGHTMODE, sizeof(struct tresp_modem_set_flightmode), &res);
	}
}
static void on_response_imei(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcorePlugin *plugin;
	struct tresp_modem_get_imei res;
	UserRequest *ur;
	struct TelMiscSNInformation *imei_property;
	char *line;
	int response;
	int err;

	printResponse();

	memset(&res, 0, sizeof(struct tresp_modem_get_imei));

	if(sp_response->success > 0)
	{
		dbg("RESPONSE OK");

		line = sp_response->p_intermediates->line;

		res.result = TCORE_RETURN_SUCCESS;
		strncpy(res.imei, line, 16);

		dbg("imei = [%s]", res.imei);

		plugin = tcore_pending_ref_plugin(p);
		imei_property = tcore_plugin_ref_property(plugin, "IMEI");
		if (imei_property)
		{
			imei_property->sn_index = TAPI_MISC_ME_IMEI;
			imei_property->sn_len = strlen(res.imei);
			memcpy(imei_property->szNumber, res.imei, imei_property->sn_len);
		}
	}
	else
	{
		dbg("RESPONSE NOK");
		line = sp_response->finalResponse;

		err = at_tok_start(&line);
		if (err < 0)
		{
			dbg("err cause not specified or string corrupted");
			   res.result = TCORE_RETURN_3GPP_ERROR;
		}
		else
		{
			err = at_tok_nextint(&line, &response);
			if (err < 0)
			{
				dbg("err not specified or string not contail error");
				res.result = TCORE_RETURN_3GPP_ERROR;
			}
			else
			{
				res.result = convertCMEError((enum ATCMEError)response);
			}
		}
	}

	ReleaseResponse();

	ur = tcore_pending_ref_user_request(p);
	tcore_user_request_send_response(ur, TRESP_MODEM_GET_IMEI, sizeof(struct tresp_modem_get_imei), &res);

}

static void on_response_version(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcorePlugin *plugin;
	struct TelMiscVersionInformation *vi;
	struct TelMiscVersionInformation *vi_property;
	struct tresp_modem_get_version res;
	UserRequest *ur;
	char* line=NULL;
	char *swver= NULL,*hwver=NULL, *caldate=NULL,*pcode=NULL,*id=NULL;

	int response, err;

	printResponse();

#define AT_VER_LEN 20
	if(sp_response->success > 0)
	{
		dbg("RESPONSE OK");

		line = sp_response->p_intermediates->line;
		err = at_tok_start(&line);

		err = at_tok_nextstr(&line,&swver);
		if(swver!=NULL)
			err = at_tok_nextstr(&line,&hwver);
		if(hwver!=NULL)
			err = at_tok_nextstr(&line,&caldate);
		if(caldate !=NULL)
			err = at_tok_nextstr(&line,&pcode);
		if(pcode !=NULL)
			err = at_tok_nextstr(&line,&id);

		dbg("version: sw=[%s], hw=[%s], rf_cal=[%s], product_code=[%s], model_id=[%s]", swver, hwver, caldate, pcode, id);

		vi = calloc(sizeof(struct TelMiscVersionInformation), 1);
		memcpy(vi->szSwVersion, swver, strlen(swver));
		memcpy(vi->szHwVersion, hwver, strlen(hwver));
		memcpy(vi->szRfCalDate, caldate, strlen(caldate));
		memcpy(vi->szProductCode, pcode,strlen(pcode));
		memcpy(vi->szModelId, id, strlen(id));

		memset(&res, 0, sizeof(struct tresp_modem_get_imei));
		snprintf(res.software, (AT_VER_LEN >strlen(swver) ?strlen(swver):AT_VER_LEN), "%s", swver);
		snprintf(res.hardware, (AT_VER_LEN >strlen(hwver) ?strlen(hwver):AT_VER_LEN), "%s", hwver);

		plugin = tcore_pending_ref_plugin(p);
		vi_property = tcore_plugin_ref_property(plugin, "VERSION");	
		memcpy(vi_property, vi, sizeof(struct TelMiscVersionInformation));
	}
	else
	{
		dbg("RESPONSE NOK");
		line = sp_response->finalResponse;

		memset(&res, 0, sizeof(struct tresp_modem_get_version));

		err = at_tok_start(&line);
		if (err < 0)
		{
			dbg("err cause not specified or string corrupted");
			   res.result = TCORE_RETURN_3GPP_ERROR;
		}
		else
		{
			err = at_tok_nextint(&line, &response);
			if (err < 0)
			{
				dbg("err not specified or string not contail error");
				res.result = TCORE_RETURN_3GPP_ERROR;
			}
			else
			{
				res.result = convertCMEError((enum ATCMEError)response);
			}
		}
	}

	ReleaseResponse();

	ur = tcore_pending_ref_user_request(p);
	tcore_user_request_send_response(ur, TRESP_MODEM_GET_VERSION, sizeof(struct tresp_modem_get_version), &res);

}

static TReturn power_on(CoreObject *o, UserRequest *ur)
{

	return TCORE_RETURN_SUCCESS;
}

static TReturn power_off(CoreObject *o, UserRequest *ur)
{
	struct tnoti_modem_power modem_power;
	modem_power.state = MODEM_STATE_OFFLINE;

	tcore_modem_set_powered(o, FALSE);

	tcore_server_send_notification( tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_MODEM_POWER,
			sizeof(struct tnoti_modem_power), &modem_power);

	return TCORE_RETURN_SUCCESS;
}
static TReturn power_reset(CoreObject *o, UserRequest *ur)
{

	return TCORE_RETURN_SUCCESS;
}
static TReturn get_imei(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char* cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NUMERIC;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup("AT+CGSN\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_imei, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn get_version(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = SINGLELINE;
	memcpy(metainfo.responsePrefix,"+CGMR:",strlen("+CGMR:"));
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup("AT+CGMR\r");

	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_version, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn set_flight_mode(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_modem_set_flightmode *req_data;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	req_data = tcore_user_request_ref_data(ur, NULL);

	if (req_data->enable) {
		dbg("Flight mode on/n");
		cmd_str = g_strdup("AT+CFUN=0\r");
	}
	else {
		dbg("Flight mode off/n");
		cmd_str = g_strdup("AT+CFUN=1\r");
	}

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_set_flight_mode, o);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static struct tcore_modem_operations modem_ops =
{
	.power_on = power_on,
	.power_off = power_off,
	.power_reset = power_reset,
	.set_flight_mode = set_flight_mode,
	.get_imei = get_imei,
	.get_version = get_version,
};

gboolean s_modem_init(TcorePlugin *cp, CoreObject *co)
{
	GQueue *work_queue;
	struct TelMiscVersionInformation *vi_property;
	struct TelMiscSNInformation *imei_property;

	dbg("Entry");

	tcore_modem_override_ops(co, &modem_ops);

	work_queue = g_queue_new();
	tcore_object_link_user_data(co, work_queue);

	tcore_object_override_callback(co, EVENT_SYS_NOTI_MODEM_POWER, on_sys_event_modem_power, NULL);
	tcore_object_override_callback(co, EVENT_MODEM_PHONE_STATE, on_event_modem_phone_state, NULL);

	vi_property = calloc(sizeof(struct TelMiscVersionInformation), 1);
	tcore_plugin_link_property(cp, "VERSION", vi_property);

	imei_property = calloc(sizeof(struct TelMiscSNInformation), 1);
	tcore_plugin_link_property(cp, "IMEI", imei_property);

	dbg("Exit");

	return TRUE;
}

void s_modem_exit(TcorePlugin *cp, CoreObject *co)
{
	GQueue *work_queue;
	struct TelMiscVersionInformation *vi_property;
	struct TelMiscSNInformation *imei_property;

	work_queue = tcore_object_ref_user_data(co);
	g_queue_free(work_queue);

	vi_property = tcore_plugin_ref_property(cp, "VERSION");
	if (vi_property)
		free(vi_property);

	imei_property = tcore_plugin_ref_property(cp, "IMEI");
	if (imei_property)
		free(imei_property);

	dbg("Exit");
}

gboolean s_modem_send_poweron(TcorePlugin *cp)
{
	UserRequest* ur;
	TcoreHal* hal;
	TcorePending *pending = NULL;
	CoreObject *o;

	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	o = tcore_plugin_ref_core_object(cp, CORE_OBJECT_TYPE_MODEM);
	ur = tcore_user_request_new(NULL, NULL);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = SINGLELINE;
	memcpy(metainfo.responsePrefix,"+CPAS:",strlen("+CPAS:"));
	info_len = sizeof(struct ATReqMetaInfo);
	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup("AT+CPAS\r");

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d",cmd_str, metainfo.responsePrefix, strlen(cmd_str));

	hal = tcore_object_get_hal(o);

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_poweron, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	return TRUE;

}
