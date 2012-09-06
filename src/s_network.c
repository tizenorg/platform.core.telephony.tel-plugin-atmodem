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

#define FEATURE_SAMSUNG_ONEDRAM

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_ps.h>
#include <co_network.h>
#include <server.h>
#include <storage.h>

#include "s_common.h"
#include "s_network.h"
#include "atchannel.h"
#include "at_tok.h"

extern struct ATResponse *sp_response;
extern char *s_responsePrefix;
extern enum ATCommandType s_type;

#define AT_CREG_STAT_NOT_REG	0 /* not registered, MT is not currently searching a new operator to register to */
#define AT_CREG_STAT_REG_HOME	1 /* registered, home network */
#define AT_CREG_STAT_SEARCHING	2 /* not registered, but MT is currently searching a new operator to register to */
#define AT_CREG_STAT_REG_DENIED	3 /* registration denied */
#define AT_CREG_STAT_UNKNOWN	4 /* unknown */
#define AT_CREG_STAT_REG_ROAM	5 /* registered, roaming */

static unsigned int lookup_tbl_net_status[] = {
	[AT_CREG_STAT_NOT_REG]	= NETWORK_SERVICE_DOMAIN_STATUS_NO,
	[AT_CREG_STAT_REG_HOME]	= NETWORK_SERVICE_DOMAIN_STATUS_FULL,
	[AT_CREG_STAT_SEARCHING]	= NETWORK_SERVICE_DOMAIN_STATUS_SEARCH,
	[AT_CREG_STAT_REG_DENIED]	= NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY,
	[AT_CREG_STAT_UNKNOWN]	= NETWORK_SERVICE_DOMAIN_STATUS_NO,
	[AT_CREG_STAT_REG_ROAM]	= NETWORK_SERVICE_DOMAIN_STATUS_FULL,
};

#define AT_COPS_MODE_AUTOMATIC	0 /* automatic (<oper> field is ignored) */
#define AT_COPS_MODE_MANUAL	1 /* manual (<oper> field shall be present, and <AcT> optionally) */
#define AT_COPS_MODE_DEREGISTER	2 /* deregister from network */
#define AT_COPS_MODE_SET_ONLY	3 /* set only <format> */

#define AT_COPS_FORMAT_LONG_ALPHANUMERIC	0 /* long format alphanumeric <oper> */
#define AT_COPS_FORMAT_SHORT_ALPHANUMERIC	1 /* short format alphanumeric <oper> */
#define AT_COPS_FORMAT_NUMERIC			2 /* numeric <oper> */

#define AT_COPS_ACT_GSM			0	/* GSM */
#define AT_COPS_ACT_GSM_COMPACT		1	/* GSM Compact */
#define AT_COPS_ACT_UTRAN		2	/* UTRAN */
#define AT_COPS_ACT_GSM_EGPRS		3	/* GSM w/EGPRS */
#define AT_COPS_ACT_UTRAN_HSDPA		4	/* UTRAN w/HSDPA */
#define AT_COPS_ACT_UTRAN_HSUPA		5	/* UTRAN w/HSUPA */
#define AT_COPS_ACT_UTRAN_HSDPA_HSUPA	6	/* UTRAN w/HSDPA and HSUPA */
#define AT_COPS_ACT_E_UTRAN		7	/* E-UTRAN */

static unsigned int lookup_tbl_access_technology[] = {
	[AT_COPS_ACT_GSM]		= NETWORK_ACT_GSM,
	[AT_COPS_ACT_GSM_COMPACT]	= NETWORK_ACT_GSM,
	[AT_COPS_ACT_UTRAN]		= NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_GSM_EGPRS]		= NETWORK_ACT_EGPRS,
	[AT_COPS_ACT_UTRAN_HSDPA]	= NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_UTRAN_HSUPA]	= NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_UTRAN_HSDPA_HSUPA]	= NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_E_UTRAN]		= NETWORK_ACT_GSM_UTRAN,
};
static unsigned int current_lac=0;
static gboolean get_serving_network(CoreObject *o, UserRequest *ur);
static void on_confirmation_network_message_send( TcorePending *pending, gboolean result, void *user_data );

static void __set_metainfo(UserRequest *ur, struct ATReqMetaInfo *info, enum ATCommandType type, char *prefix)
{
	if (!info || !ur)
		return;
	memset(info, 0, sizeof(struct ATReqMetaInfo));
	info->type = type;
	if (!prefix)
		info->responsePrefix[0] ='\0';
	else
		memcpy(info->responsePrefix, prefix, strlen(prefix));
	tcore_user_request_set_metainfo(ur, sizeof(struct ATReqMetaInfo), info);
}
static void __send_at_request(CoreObject *o, char* atcmd, UserRequest *ur, TcorePendingResponseCallback func)
{
	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;

	plugin = tcore_object_ref_plugin(o);
	hal = tcore_object_get_hal(o);

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(atcmd), atcmd);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, func, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_network_message_send, NULL);

	tcore_hal_send_request(hal, pending);
}

static void _insert_mcc_mnc_oper_list(TcorePlugin *plugin, CoreObject *o)
{
	Server *s;
	Storage *strg;
	void *handle;
	char query[255] = {	0, };
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *result = NULL, *row = NULL;
	struct tcore_network_operator_info *noi = NULL;
	int count = 0;

	s = tcore_plugin_ref_server(plugin);
	strg = tcore_server_find_storage(s, "database");

	handle = tcore_storage_create_handle(strg, "/opt/dbspace/.mcc_mnc_oper_list.db");
	if (!handle) {
		dbg("fail to create database handle");
		return;
	}

	snprintf(query, 255, "select country, mcc, mnc, oper from mcc_mnc_oper_list");

	result = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	tcore_storage_read_query_database(strg, handle, query, NULL, result, 4);

	g_hash_table_iter_init(&iter, result);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		row = value;

		noi = calloc(sizeof(struct tcore_network_operator_info), 1);

		snprintf(noi->mcc, 4, "%s",(const gchar *)(g_hash_table_lookup(row, "1")));
		snprintf(noi->mnc, 4, "%s",(const gchar *)(g_hash_table_lookup(row, "2")));
		snprintf(noi->name, 41, "%s",(const gchar *)(g_hash_table_lookup(row, "3")));
		snprintf(noi->country, 4, "%s",(const gchar *)(g_hash_table_lookup(row, "0")));

		tcore_network_operator_info_add(o, noi);

		count++;
	}

	dbg("count = %d", count);

	g_hash_table_destroy(result);

	tcore_storage_remove_handle(strg, handle);
}


static gboolean _is_cdma(int act)
{
	switch (act) {
		case NETWORK_ACT_IS95A:
		case NETWORK_ACT_IS95B:
		case NETWORK_ACT_CDMA_1X:
		case NETWORK_ACT_EVDO_REV0:
		case NETWORK_ACT_CDMA_1X_EVDO_REV0:
		case NETWORK_ACT_EVDO_REVA:
		case NETWORK_ACT_CDMA_1X_EVDO_REVA:
		case NETWORK_ACT_EVDV:
			return TRUE;
			break;
	}

	return FALSE;
}

static enum telephony_network_service_type _get_service_type(enum telephony_network_service_type prev_type,
		int domain, int act, int cs_status, int ps_status)
{
	enum telephony_network_service_type ret;

	ret = prev_type;

	switch (act) {
		case NETWORK_ACT_NOT_SPECIFIED:
			ret = NETWORK_SERVICE_TYPE_UNKNOWN;
			break;

		case NETWORK_ACT_GSM:
			if (prev_type == NETWORK_SERVICE_TYPE_2_5G_EDGE && domain == NETWORK_SERVICE_DOMAIN_CS)
				ret = NETWORK_SERVICE_TYPE_2_5G_EDGE;
			else
				ret = NETWORK_SERVICE_TYPE_2G;
			break;

		case NETWORK_ACT_IS95A:
		case NETWORK_ACT_IS95B:
			ret = NETWORK_SERVICE_TYPE_2G;
			break;

		case NETWORK_ACT_CDMA_1X:
		case NETWORK_ACT_GPRS:
			ret = NETWORK_SERVICE_TYPE_2_5G;
			break;

		case NETWORK_ACT_EGPRS:
			return NETWORK_SERVICE_TYPE_2_5G_EDGE;
			break;

		case NETWORK_ACT_UMTS:
			ret = NETWORK_SERVICE_TYPE_3G;
			break;

		case NETWORK_ACT_EVDO_REV0:
		case NETWORK_ACT_CDMA_1X_EVDO_REV0:
		case NETWORK_ACT_EVDO_REVA:
		case NETWORK_ACT_CDMA_1X_EVDO_REVA:
		case NETWORK_ACT_EVDV:
			ret = NETWORK_SERVICE_TYPE_3G;
			break;
	}

	if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_NO && ps_status == NETWORK_SERVICE_DOMAIN_STATUS_NO) {
		ret = NETWORK_SERVICE_TYPE_NO_SERVICE;
	}
	else if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_SEARCH || ps_status == NETWORK_SERVICE_DOMAIN_STATUS_SEARCH) {
		if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL || ps_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL) {
			/* no change */
		}
		else {
			ret = NETWORK_SERVICE_TYPE_SEARCH;
		}
	}
	else if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY || ps_status == NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY) {
		if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL || ps_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL) {
			/* no change */
		}
		else {
			ret = NETWORK_SERVICE_TYPE_EMERGENCY;
		}
	}

	return ret;
}

static void _ps_set(TcorePlugin *plugin, int status)
{
	GSList *co_list = NULL;

	co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PS);
	do {
		CoreObject *o = NULL;
		o = (CoreObject *) co_list->data;
		if (!o)
			break;

		if (status == NETWORK_SERVICE_DOMAIN_STATUS_FULL) {
			tcore_ps_set_online(o, TRUE);
		}
		else {
			tcore_ps_set_online(o, FALSE);
		}
	} while ((co_list = g_slist_next(co_list)));

	g_slist_free(co_list);
}

static TReturn _network_general_response_result(void)
{
	if (sp_response->success > 0) {
		ReleaseResponse();
		return TCORE_RETURN_SUCCESS;
	}
	else {
		int ret, error;
		char* line=NULL;
		line = sp_response->finalResponse;
		ret = at_tok_start(&line);
		if (ret < 0) {
			err("err cause not specified or string corrupted");
			ReleaseResponse();
			return TCORE_RETURN_3GPP_ERROR;
		}
		else {
			ret = at_tok_nextint(&line, &error);
			if (ret < 0) {
				err("err not specified or string not contail error");
				ReleaseResponse();
				return TCORE_RETURN_3GPP_ERROR;

			}
			else {
				ReleaseResponse();
				return convertCMEError((enum ATCMEError)error);
			}
		}
	}
}

static void on_confirmation_network_message_send( TcorePending *pending, gboolean result, void *user_data )
{
	UserRequest* ur = NULL;
	struct ATReqMetaInfo* metainfo = NULL;
	unsigned int info_len =0;
	dbg("AT msg goes out from queue. Allocate ATRsp buffer and write rspPrefix\n");

	ReleaseResponse();
	sp_response = at_response_new();

	ur = tcore_pending_ref_user_request(pending);
	metainfo = (struct ATReqMetaInfo*)tcore_user_request_ref_metainfo(ur,&info_len);

	if ((metainfo->type == SINGLELINE) || (metainfo->type == MULTILINE)) {
		s_responsePrefix = strdup(metainfo->responsePrefix);
		dbg("duplicating responsePrefix : %s\n", s_responsePrefix);
	}
	else {
		s_responsePrefix = NULL;
	}

	s_type = metainfo->type;

	if (result == FALSE) {
		dbg("SEND FAIL");
	}
	else {
		dbg("SEND OK");
	}
}

static void on_response_set_plmn_selection_mode(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_network_set_plmn_selection_mode resp;

	dbg("RESPONSE OK");

	resp.result = _network_general_response_result();

	ur = tcore_pending_ref_user_request(pending);
	if (ur) {
		tcore_user_request_send_response(ur, TRESP_NETWORK_SET_PLMN_SELECTION_MODE, sizeof(struct tresp_network_set_plmn_selection_mode), &resp);
	}
}

static void on_response_get_plmn_selection_mode(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_network_get_plmn_selection_mode resp = {0};
	char* line=NULL;
	int mode=0;
	int ret;

	printResponse();

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");
		line = sp_response->p_intermediates->line;
		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&mode);
		if (ret < 0)
			AT_TOK_ERROR(line);

		dbg("mode = %d", mode);
		switch(mode) {
			case AT_COPS_MODE_AUTOMATIC:
				resp.mode = NETWORK_SELECT_MODE_GLOBAL_AUTOMATIC;
			break;
			case AT_COPS_MODE_MANUAL:
				resp.mode = NETWORK_SELECT_MODE_GSM_MANUAL;
			break;
		}
	}
	else {
		err("RESPONSE NOK");
	}
	ReleaseResponse();

	dbg("resp.mode = %d", resp.mode);
	ur = tcore_pending_ref_user_request(pending);
	if (ur) {
		tcore_user_request_send_response(ur, TRESP_NETWORK_GET_PLMN_SELECTION_MODE, sizeof(struct tresp_network_get_plmn_selection_mode), &resp);
	}
}

static void on_response_search_network(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_network_search resp;
	int i = 0, ret=0;
	char* line=NULL;

	memset(&resp, 0, sizeof(struct tresp_network_search));

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");
		line = sp_response->p_intermediates->line;
		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);
		while(at_tok_hasmore(&line))
		{
		/*
		 *	+COPS: [list of supported (<stat>,long alphanumeric <oper>,short alphanumeric <oper>,numeric <oper>[,<AcT>])s]
		 *	       [,,(list of supported <mode>s),(list of supported <format>s)]
		 */
			int stat=0, AcT=0;
			char* oper=NULL, *p;
			int commas = 0;

			dbg("line0 %s", line);
			at_tok_skip_bracket(&line);
			for (p = line ; *p != ')' ;p++) {
				if (*p == ',')
					commas++;
			}

			/* <stat>: integer type */
			ret = at_tok_nextint(&line,&stat);
			if (ret < 0)
				AT_TOK_ERROR(line);

			/* long alphanumeric <oper> */
			ret = at_tok_nextstr(&line,&oper);
			if (ret < 0)
				AT_TOK_ERROR(line);

			/* short alphanumeric <oper> */
			ret = at_tok_nextstr(&line,&oper);
			if (ret < 0)
				AT_TOK_ERROR(line);

			/* numeric <oper> */
			/* [NOTICE] struct "tresp_network_search" only supports numeric type */
			ret = at_tok_nextstr(&line,&oper);
			if (ret < 0)
				AT_TOK_ERROR(line);

			if (commas == 4) {
				/* [,<AcT>]: integer type; access technology selected */
				ret = at_tok_nextint(&line,&AcT);
				if (ret < 0)
					AT_TOK_ERROR(line);
			}

			dbg("mode = %d, oper=%s, AcT=%d", stat, oper?oper:"null", AcT);
			resp.list[i].status = stat;
			resp.list[i].act = lookup_tbl_access_technology[AcT];
			memcpy(resp.list[i].plmn, oper, 6);
			if (resp.list[i].plmn[5] == '#')
				resp.list[i].plmn[5] = '\0';

			dbg("resp.list[%d].act = 0x%x, resp.list[%d].plmn=%s", i, resp.list[i].act, i, resp.list[i].plmn);
			i++;
		}
		resp.list_count = i;
		dbg("resp.list_count=%d", resp.list_count);
		ur = tcore_pending_ref_user_request(pending);
		if (ur) {
			tcore_user_request_send_response(ur, TRESP_NETWORK_SEARCH, sizeof(struct tresp_network_search), &resp);
		}

	}
	else {
		err("RESPONSE NOK");
	}
	ReleaseResponse();
}

static void on_response_get_serving_network(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_network_get_serving_network resp;
	CoreObject *o;
	char plmn[7];
	enum telephony_network_access_technology act = NETWORK_ACT_UNKNOWN;
	int ret;

	/* AT parsing variable */
	char* line=NULL;
	int mode=0, format=0, AcT=0;
	char* oper=NULL;

	if (sp_response->success > 0) {
		dbg("RESPONSE OK");
		line = sp_response->p_intermediates->line;
		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&mode);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&format);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextstr(&line,&oper);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&AcT);
		if (ret < 0)
			AT_TOK_ERROR(line);

		dbg("mode = %d, format=%d, oper=%s, AcT=%d\n", mode, format, oper, AcT);

		memset(plmn, 0, 7);
		memcpy(plmn, oper, 6);
		if (plmn[5] == '#')
			plmn[5] = '\0';

		o = tcore_pending_ref_core_object(pending);

		tcore_network_set_plmn(o, plmn);
		tcore_network_get_access_technology(o, &act);
		dbg("prev_act = 0x%x, new_act = 0x%x", act,lookup_tbl_access_technology[AcT]);
		act = lookup_tbl_access_technology[AcT];
		tcore_network_set_access_technology(o, act);

		if (_is_cdma(act) == FALSE) {
			tcore_network_set_lac(o, current_lac);
		}

		memcpy(resp.plmn, plmn, 6);
		resp.act = act;
		resp.gsm.lac = current_lac;
		ur = tcore_pending_ref_user_request(pending);
		if (ur) {
			tcore_user_request_send_response(ur, TRESP_NETWORK_GET_SERVING_NETWORK, sizeof(struct tresp_network_get_serving_network), &resp);
		}
		else {
			struct tnoti_network_change network_change;

			memset(&network_change, 0, sizeof(struct tnoti_network_change));
			memcpy(network_change.plmn, plmn, 6);

			network_change.act = act;
			network_change.gsm.lac = current_lac;

			tcore_server_send_notification(tcore_plugin_ref_server(tcore_pending_ref_plugin(pending)), tcore_pending_ref_core_object(pending),
					TNOTI_NETWORK_CHANGE, sizeof(struct tnoti_network_change), &network_change);
		}
	}
	else {
		err("RESPONSE NOK");
	}
	ReleaseResponse();
	return;
}

static gboolean on_event_network_regist(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_network_registration_status regist_status;
	enum telephony_network_service_domain_status cs_status;
	enum telephony_network_service_domain_status ps_status;
	enum telephony_network_service_type service_type;
	enum telephony_network_access_technology act = NETWORK_ACT_UNKNOWN;

	char *line = (char *)event_info;
	int ret;
	unsigned char svc_domain;
	int stat=0, AcT=0;
	unsigned int lac=0, ci=0, rac=0;

	dbg("NOTI RECEIVED");

	/* CS domain */
	if (strStartsWith(line,"+CREG:"))
		svc_domain = NETWORK_SERVICE_DOMAIN_CS;
	/* PS domain */
	else if (strStartsWith(line,"+CGREG:"))
		svc_domain = NETWORK_SERVICE_DOMAIN_PS;
	else
		return TRUE;

	dbg("svc_domain = 0x%x", svc_domain);

	ret = at_tok_start(&line);
	if (ret < 0)
		AT_NOTI_TOK_ERROR(line);

	ret = at_tok_nextint(&line, &stat);
	if (ret < 0)
		goto process;

	ret = at_tok_nexthexint(&line, (int *)&lac);
	if (ret < 0)
		goto process;
	else {
		dbg("Found lac=0x%x",lac);
		/* <stat> 1 : registered, home network */
		/*        5 : registered, roaming      */
		if ( stat==1 || stat==5 )
			current_lac = lac;
	}

	ret = at_tok_nexthexint(&line, (int *)&ci);
	if (ret < 0)
		goto process;
	else
		dbg("Found ci=0x%x", ci);

	ret = at_tok_nextint(&line, (int *)&AcT);
	if (ret < 0)
		goto process;

	if (svc_domain == NETWORK_SERVICE_DOMAIN_PS) {
		ret = at_tok_nexthexint(&line, (int *)&rac);
		if (ret < 0)
			goto process;
		else
			dbg("Found rac=0x%x", rac);
	}
	/*
	 *	<lac>: string type; two byte location area code or tracking area code in hexadecimal format
	 *	<tac>: string type; two byte tracking area code in hexadecimal format (for +CEREG:)
	 *	<ci>:  string type; four byte GERAN/UTRAN/E-UTRAN cell ID in hexadecimal format
	 *  <rac>: string type; one byte routing area code in hexadecimal format
	*/

process:
	dbg("stat=%d, lac=0x%lx, ci=0x%lx, Act=%d, rac=0x%lx", stat, lac, ci, AcT, rac);

	switch (svc_domain) {
		case NETWORK_SERVICE_DOMAIN_CS:
			cs_status = lookup_tbl_net_status[stat];
			tcore_network_set_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, cs_status);
			break;

		case NETWORK_SERVICE_DOMAIN_PS:
			ps_status = lookup_tbl_net_status[stat];
			tcore_network_set_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, ps_status);

			_ps_set(tcore_object_ref_plugin(o), ps_status);
			break;
	}

	tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, &cs_status);
	tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, &ps_status);

	act = lookup_tbl_access_technology[AcT];
	tcore_network_set_access_technology(o, act);

	if (stat == AT_CREG_STAT_REG_ROAM)
		tcore_network_set_roaming_state(o, TRUE);
	else
		tcore_network_set_roaming_state(o, FALSE);

	tcore_network_get_service_type(o, &service_type);
	dbg("prev_service_type = 0x%x", service_type);
	service_type = _get_service_type(service_type, svc_domain, act, cs_status, ps_status);
	dbg("new_service_type = 0x%x", service_type);
	tcore_network_set_service_type(o, service_type);

	tcore_network_set_lac(o, lac);
	tcore_network_set_rac(o, rac);
	tcore_network_set_cell_id(o, ci);

	if (_is_cdma(act) == FALSE) {
		struct tnoti_network_location_cellinfo net_lac_cell_info;
		net_lac_cell_info.lac = lac;
		net_lac_cell_info.cell_id = ci;

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_NETWORK_LOCATION_CELLINFO,
				sizeof(struct tnoti_network_location_cellinfo), &net_lac_cell_info);
	}

	regist_status.cs_domain_status = cs_status;
	regist_status.ps_domain_status = ps_status;
	regist_status.service_type = service_type;
	regist_status.roaming_status = tcore_network_get_roaming_state(o);

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
			TNOTI_NETWORK_REGISTRATION_STATUS, sizeof(struct tnoti_network_registration_status), &regist_status);

	get_serving_network(o, NULL);

	return TRUE;
}

static gboolean on_event_network_icon_info(CoreObject *o, const void *event_info, void *user_data)
{
	char *line = (char *)event_info;
	static struct tnoti_network_icon_info net_icon_info = {0xff,0,0,0};
	int ret;
	int descr=0, ind=0;

#define CIND_NOTI_RSSI		10
#define CIND_NOTI_BATTERY	15

	ret = at_tok_start(&line);
	if (ret < 0)
		AT_NOTI_TOK_ERROR(line);

	ret = at_tok_nextint(&line, &descr);
	if (ret < 0)
		AT_NOTI_TOK_ERROR(line);

	ret = at_tok_nextint(&line, &ind);
	if (ret < 0)
		AT_NOTI_TOK_ERROR(line);

	switch(descr) {
		case CIND_NOTI_RSSI:
			dbg("CIND_NOTI_RSSI. ind=%d",ind);
			net_icon_info.rssi = ind;
			break;
		case CIND_NOTI_BATTERY:
			dbg("CIND_NOTI_BATTERY. ind=%d",ind);
			net_icon_info.battery = ind;
			break;

		default:
			err("This event is not handled val=%d",descr);
			return TRUE;
	}

	dbg("type=%d, rssi=%d, battery=%d, hdr_rssi=%d",
			net_icon_info.type, net_icon_info.rssi, net_icon_info.battery, net_icon_info.hdr_rssi);

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_NETWORK_ICON_INFO,
			sizeof(struct tnoti_network_icon_info), &net_icon_info);

	return TRUE;
}

static void on_sim_resp_hook_get_netname(UserRequest *ur, enum tcore_response_command command, unsigned int data_len,
		const void *data, void *user_data)
{
	const struct tresp_sim_read *resp = data;
	CoreObject *o = user_data;
	struct tnoti_network_registration_status regist_status;

	if (command == TRESP_SIM_GET_SPN) {
		dbg("OK SPN GETTING!!");
		dbg("resp->result = 0x%x", resp->result);
		dbg("resp->data.spn.display_condition = 0x%x", resp->data.spn.display_condition);
		dbg("resp->data.spn.spn = [%s]", resp->data.spn.spn);

		tcore_network_set_network_name(o, TCORE_NETWORK_NAME_TYPE_SPN, (const char *)resp->data.spn.spn);

		/**
		 * display condition
		 *  bit[0]: 0 = display of registered PLMN name not required when registered PLMN is either HPLMN or a PLMN in the service provider PLMN list
		 *          1 = display of registered PLMN name required when registered PLMN is either HPLMN or a PLMN in the service provider PLMN list
		 *  bit[1]: 0 = display of the service provider name is required when registered PLMN is neither HPLMN nor a PLMN in the service provider PLMN list
		 *          1 = display of the service provider name is not required when registered PLMN is neither HPLMN nor a PLMN in the service provider PLMN list
		 */
		if (resp->data.spn.display_condition & 0x01) {
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_NETWORK);
		}
		if ((resp->data.spn.display_condition & 0x02) == 0) {
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_SPN);
		}
		if ((resp->data.spn.display_condition & 0x03) == 0x01) {
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_ANY);
		}
	}

	tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, &regist_status.cs_domain_status);
	tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, &regist_status.ps_domain_status);
	tcore_network_get_service_type(o, &regist_status.service_type);
	regist_status.roaming_status = tcore_network_get_roaming_state(o);

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
			TNOTI_NETWORK_REGISTRATION_STATUS, sizeof(struct tnoti_network_registration_status), &regist_status);
}

static enum tcore_hook_return on_hook_sim_init(Server *s, CoreObject *source, enum tcore_notification_command command,
		unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_sim_status *sim = data;
	UserRequest *ur = NULL;

	if (sim->sim_status == SIM_STATUS_INIT_COMPLETED) {
		ur = tcore_user_request_new(NULL, NULL);
		tcore_user_request_set_command(ur, TREQ_SIM_GET_SPN);
		tcore_user_request_set_response_hook(ur, on_sim_resp_hook_get_netname, user_data);
		tcore_object_dispatch_request(source, ur);
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

static TReturn search_network(CoreObject *o, UserRequest *ur)
{
	/* AT command variable*/
	struct ATReqMetaInfo metainfo;
	char* atcmd = NULL;

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	__set_metainfo(ur, &metainfo, SINGLELINE,"+COPS:");

	atcmd = g_strdup("AT+COPS=?\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",atcmd, "N/A", strlen(atcmd));

	__send_at_request(o, atcmd, ur, on_response_search_network);
	free(atcmd);

	return TCORE_RETURN_SUCCESS;
}

static TReturn set_plmn_selection_mode(CoreObject *o, UserRequest *ur)
{
	const struct treq_network_set_plmn_selection_mode *req_data;

	/* AT command variable*/
	struct ATReqMetaInfo metainfo;
	char* atcmd = NULL;
	char plmn[7];

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	req_data = tcore_user_request_ref_data(ur, NULL);
	__set_metainfo(ur, &metainfo, NO_RESULT, NULL);

	if (req_data->mode != NETWORK_SELECT_MODE_GSM_MANUAL) {
		/* AT_COPS_MODE_AUTOMATIC 0*/
		atcmd = g_strdup("AT+COPS=0\r");
	}
	else {
		memset(plmn, 0, 7);
		memcpy(plmn, req_data->plmn, 6);

		if (strlen(req_data->plmn) == 5) {
			plmn[5] = '#';
		}
		/* AT_COPS_MODE_MANUAL 1*/
		/* AT_COPS_FORMAT_NUMERIC 2*/
		atcmd = g_strdup_printf("AT+COPS=0%s\r", plmn);
	}
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",atcmd, "N/A", strlen(atcmd));

	__send_at_request(o, atcmd, ur, on_response_set_plmn_selection_mode);
	free(atcmd);

	return TCORE_RETURN_SUCCESS;
}


static TReturn get_plmn_selection_mode(CoreObject *o, UserRequest *ur)
{
	/* AT command variable*/
	struct ATReqMetaInfo metainfo;
	char* atcmd = NULL;

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	__set_metainfo(ur, &metainfo, SINGLELINE,"+COPS:");

	atcmd = g_strdup("AT+COPS?\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",atcmd, "N/A", strlen(atcmd));

	__send_at_request(o, atcmd, ur, on_response_get_plmn_selection_mode);
	free(atcmd);

	return TCORE_RETURN_SUCCESS;
}

static TReturn set_service_domain(CoreObject *o, UserRequest *ur)
{
	dbg("set_service_domain is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_service_domain(CoreObject *o, UserRequest *ur)
{
	dbg("get_service_domain is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_band(CoreObject *o, UserRequest *ur)
{
	dbg("set_band is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_band(CoreObject *o, UserRequest *ur)
{
	dbg("get_band is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_preferred_plmn(CoreObject *o, UserRequest *ur)
{
	dbg("set_preferred_plmn is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_preferred_plmn(CoreObject *o, UserRequest *ur)
{
	dbg("get_preferred_plmn is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_order(CoreObject *o, UserRequest *ur)
{
	dbg("set_order is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_order(CoreObject *o, UserRequest *ur)
{
	dbg("get_order is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_power_on_attach(CoreObject *o, UserRequest *ur)
{
	dbg("set_power_on_attach is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_power_on_attach(CoreObject *o, UserRequest *ur)
{
	dbg("get_power_on_attach is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_cancel_manual_search(CoreObject *o, UserRequest *ur)
{
	dbg("set_cancel_manual_search is not supported!");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_serving_network(CoreObject *o, UserRequest *ur)
{
	/* AT command variable*/
	struct ATReqMetaInfo metainfo;
	char* atcmd = NULL;

	if (!o)
		return TCORE_RETURN_EINVAL;

	if (!ur)
		ur = tcore_user_request_new(NULL, NULL);

	__set_metainfo(ur, &metainfo, SINGLELINE,"+COPS:");

	atcmd = g_strdup("AT+COPS?\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",atcmd, "N/A", strlen(atcmd));

	__send_at_request(o, atcmd, ur, on_response_get_serving_network);
	free(atcmd);
	return TCORE_RETURN_SUCCESS;
}



static struct tcore_network_operations network_ops = {
	.search = search_network,
	.set_plmn_selection_mode = set_plmn_selection_mode,
	.get_plmn_selection_mode = get_plmn_selection_mode,
	.set_service_domain = set_service_domain,
	.get_service_domain = get_service_domain,
	.set_band = set_band,
	.get_band = get_band,
	.set_preferred_plmn = set_preferred_plmn,
	.get_preferred_plmn = get_preferred_plmn,
	.set_order = set_order,
	.get_order = get_order,
	.set_power_on_attach = set_power_on_attach,
	.get_power_on_attach = get_power_on_attach,
	.set_cancel_manual_search = set_cancel_manual_search,
	.get_serving_network = get_serving_network,
};

gboolean s_network_init(TcorePlugin *plugin, TcoreHal *h)
{
	CoreObject *o;

	o = tcore_network_new(plugin, "umts_network", &network_ops, h);
	if (!o)
		return FALSE;

	tcore_object_add_callback(o, EVENT_NETWORK_REGISTRATION, on_event_network_regist, NULL);
	tcore_object_add_callback(o, EVENT_NETWORK_ICON_INFO, on_event_network_icon_info, NULL);

	tcore_server_add_notification_hook(tcore_plugin_ref_server(plugin), TNOTI_SIM_STATUS, on_hook_sim_init, o);

	_insert_mcc_mnc_oper_list(plugin, o);

	return TRUE;
}

void s_network_exit(TcorePlugin *plugin)
{
	CoreObject *o;

	o = tcore_plugin_ref_core_object(plugin, "umts_network");

	tcore_network_free(o);
}
