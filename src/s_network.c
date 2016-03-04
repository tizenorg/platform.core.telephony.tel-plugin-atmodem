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

#include <tzplatform_config.h>
#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_ps.h>
#include <co_network.h>
#include <server.h>
#include <storage.h>
#include <at.h>

#include "s_common.h"
#include "s_network.h"

#define ATMODEM_NETWORK_BASE_16	16
#define MCC_MNC_OPER_LIST_DB	tzplatform_mkpath(TZ_SYS_DB, ".mcc_mnc_oper_list.db")

typedef enum {
	ATMDOEM_NETWORK_ACT_GSM, /* GSM */
	ATMDOEM_NETWORK_ACT_GSM_COMPACT, /* GSM Compact */
	ATMDOEM_NETWORK_ACT_UTRAN, /* UTRAN */
	ATMDOEM_NETWORK_ACT_GSM_EGPRS, /* GSM w/EGPRS */
	ATMDOEM_NETWORK_ACT_UTRAN_HSDPA, /* UTRAN w/HSDPA */
	ATMDOEM_NETWORK_ACT_UTRAN_HSUPA, /* UTRAN w/HSUPA */
	ATMDOEM_NETWORK_ACT_UTRAN_HSDPA_HSUPA, /* UTRAN w/HSDPA and HSUPA */
	ATMDOEM_NETWORK_ACT_E_UTRAN, /* E-UTRAN */
} AtmodemNetworkAct;

#define AT_CREG_STAT_NOT_REG		0 /* not registered, MT is not currently searching a new operator to register to */
#define AT_CREG_STAT_REG_HOME	1 /* registered, home network */
#define AT_CREG_STAT_SEARCHING	2 /* not registered, but MT is currently searching a new operator to register to */
#define AT_CREG_STAT_REG_DENIED	3 /* registration denied */
#define AT_CREG_STAT_UNKNOWN		4 /* unknown */
#define AT_CREG_STAT_REG_ROAM	5 /* registered, roaming */

#if 0
static unsigned int lookup_tbl_net_status[] = {
	[AT_CREG_STAT_NOT_REG] = NETWORK_SERVICE_DOMAIN_STATUS_NO,
	[AT_CREG_STAT_REG_HOME] = NETWORK_SERVICE_DOMAIN_STATUS_FULL,
	[AT_CREG_STAT_SEARCHING] = NETWORK_SERVICE_DOMAIN_STATUS_SEARCH,
	[AT_CREG_STAT_REG_DENIED] = NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY,
	[AT_CREG_STAT_UNKNOWN] = NETWORK_SERVICE_DOMAIN_STATUS_NO,
	[AT_CREG_STAT_REG_ROAM] = NETWORK_SERVICE_DOMAIN_STATUS_FULL,
};
#endif

#define AT_COPS_MODE_AUTOMATIC	0 /* automatic (<oper> field is ignored) */
#define AT_COPS_MODE_MANUAL		1 /* manual (<oper> field shall be present, and <AcT> optionally) */
#define AT_COPS_MODE_DEREGISTER	2 /* deregister from network */
#define AT_COPS_MODE_SET_ONLY		3 /* set only <format> */

#define AT_COPS_FORMAT_LONG_ALPHANUMERIC	0 /* long format alphanumeric <oper> */
#define AT_COPS_FORMAT_SHORT_ALPHANUMERIC	1 /* short format alphanumeric <oper> */
#define AT_COPS_FORMAT_NUMERIC		2 /* numeric <oper> */

#define AT_COPS_ACT_GSM			0 /* GSM */
#define AT_COPS_ACT_GSM_COMPACT		1 /* GSM Compact */
#define AT_COPS_ACT_UTRAN			2 /* UTRAN */
#define AT_COPS_ACT_GSM_EGPRS			3 /* GSM w/EGPRS */
#define AT_COPS_ACT_UTRAN_HSDPA		4 /* UTRAN w/HSDPA */
#define AT_COPS_ACT_UTRAN_HSUPA		5 /* UTRAN w/HSUPA */
#define AT_COPS_ACT_UTRAN_HSDPA_HSUPA	6 /* UTRAN w/HSDPA and HSUPA */
#define AT_COPS_ACT_E_UTRAN			7 /* E-UTRAN */
#define AT_COPS_ACT_MAX				8

static unsigned int lookup_tbl_access_technology[] = {
	[AT_COPS_ACT_GSM] = NETWORK_ACT_GSM,
	[AT_COPS_ACT_GSM_COMPACT] = NETWORK_ACT_GSM,
	[AT_COPS_ACT_UTRAN] = NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_GSM_EGPRS] = NETWORK_ACT_EGPRS,
	[AT_COPS_ACT_UTRAN_HSDPA] = NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_UTRAN_HSUPA] = NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_UTRAN_HSDPA_HSUPA] = NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_E_UTRAN] = NETWORK_ACT_GSM_UTRAN,
};

static gboolean get_serving_network(CoreObject *o, UserRequest *ur);

static void _insert_mcc_mnc_oper_list(TcorePlugin *p, CoreObject *co_network)
{
	Server *s;
	Storage *strg;
	void *handle;
	char query[255] = {0, };
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *result = NULL, *row = NULL;
	struct tcore_network_operator_info *noi = NULL;
	int count = 0;

	s = tcore_plugin_ref_server(p);
	strg = tcore_server_find_storage(s, "database");

	handle = tcore_storage_create_handle(strg, MCC_MNC_OPER_LIST_DB);
	if (!handle) {
		err("fail to create database handle");
		return;
	}

	snprintf(query, 255, "select country, mcc, mnc, oper from mcc_mnc_oper_list");

	result = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	tcore_storage_read_query_database(strg, handle, query, NULL, result, 4);

	g_hash_table_iter_init(&iter, result);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		row = value;
		noi = g_try_malloc0(sizeof(struct tcore_network_operator_info));
		if (noi == NULL) {
			err("Memory allocation failed!!");
			continue;
		}
		snprintf(noi->mcc, 4, "%s", (const char *)(g_hash_table_lookup(row, "1")));
		snprintf(noi->mnc, 4, "%s", (const char *)(g_hash_table_lookup(row, "2")));
		snprintf(noi->name, 41, "%s", (const char *)(g_hash_table_lookup(row, "3")));
		snprintf(noi->country, 4, "%s", (const char *)(g_hash_table_lookup(row, "0")));

		tcore_network_operator_info_add(co_network, noi);
		g_free(noi);
		noi = NULL;

		count++;
	}

	dbg("count = %d", count);

	g_hash_table_destroy(result);

	tcore_storage_remove_handle(strg, handle);
}

static enum telephony_network_service_domain_status __atmodem_network_map_stat(guint stat)
{
	switch (stat) {
	case 0:
		return NETWORK_SERVICE_DOMAIN_STATUS_NO;
	case 1:
		return NETWORK_SERVICE_DOMAIN_STATUS_FULL;
	case 2:
		return NETWORK_SERVICE_DOMAIN_STATUS_SEARCH;
	case 3:
		return NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY;
	case 4:
		return NETWORK_SERVICE_DOMAIN_STATUS_NO;
	case 5:
		return NETWORK_SERVICE_DOMAIN_STATUS_FULL;
	default:
		return NETWORK_SERVICE_DOMAIN_STATUS_NO;
	}
}

static enum telephony_network_service_type _get_service_type(enum telephony_network_service_type prev_type,
	int act, int cs_status, int ps_status)
{
	enum telephony_network_service_type ret;

	ret = prev_type;

	switch (act) {
	case NETWORK_ACT_NOT_SPECIFIED:
		ret = NETWORK_SERVICE_TYPE_UNKNOWN;
	break;

	case NETWORK_ACT_GSM:
		if (prev_type == NETWORK_SERVICE_TYPE_2_5G_EDGE)
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

	default:
		/*Do Nothing*/
		dbg("Default Case executed.");
	break;
	}

	if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_NO
			&& ps_status == NETWORK_SERVICE_DOMAIN_STATUS_NO) {
		ret = NETWORK_SERVICE_TYPE_NO_SERVICE;
	} else if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_SEARCH
			|| ps_status == NETWORK_SERVICE_DOMAIN_STATUS_SEARCH) {
		if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL
				|| ps_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL) {
			/* no change */
		} else {
			ret = NETWORK_SERVICE_TYPE_SEARCH;
		}
	} else if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY
			|| ps_status == NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY) {
		if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL
				|| ps_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL) {
			/* no change */
		} else {
			ret = NETWORK_SERVICE_TYPE_EMERGENCY;
		}
	}

	return ret;
}

/* Notifications */
static gboolean on_notification_atmodem_cs_network_info(CoreObject *co_network,
	const void *event_info, void *user_data)
{
	GSList *lines = NULL;
	gchar *line = NULL;

	dbg("Network notification - CS network info: [+CREG]");

	lines = (GSList *)event_info;
	if (g_slist_length(lines) != 1) {
		err("+CREG unsolicited message expected to be Single line "
			"but received multiple lines");
		return TRUE;
	}

	line = (char *) (lines->data);
	if (line != NULL) {
		struct tnoti_network_registration_status registration_status = {0, };
		struct tnoti_network_location_cellinfo cell_info = {0, };
		GSList *tokens = NULL;
		gchar *token_str;
		guint stat = 0, act = 0, lac = 0, ci = 0;

		/*
		 * Tokenize
		 *
		 * +CREG: <stat>[, <lac>, <ci>[, <AcT>]]
		 */
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("Invalid notification message");
			goto out;
		}

		/* <stat> */
		if ((token_str = g_slist_nth_data(tokens, 0)) == NULL) {
			err("No <stat> in +CREG");
			goto out;
		}
		stat = __atmodem_network_map_stat(atoi(token_str)); /*TODO : Confirm*/
		(void)tcore_network_set_service_status(co_network, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, stat);

		/* <lac> */
		if ((token_str = g_slist_nth_data(tokens, 1))) {
			token_str = tcore_at_tok_extract((const char *)token_str);
			if (token_str != NULL) {
				lac = (guint)strtol(token_str, NULL, ATMODEM_NETWORK_BASE_16);

				/* Update Location Area Code (lac) information */
				(void)tcore_network_set_lac(co_network, lac);
				g_free(token_str);
			} else {
				err("No <lac>");
			}
		} else {
			dbg("No <lac> in +CREG");
			(void)tcore_network_get_lac(co_network, &lac);
		}

		/* <ci> */
		if ((token_str = g_slist_nth_data(tokens, 2))) {
			token_str = tcore_at_tok_extract((const char *)token_str);
			if (token_str != NULL) {
				ci = (guint)strtol(token_str, NULL, ATMODEM_NETWORK_BASE_16);
				/* Update Cell ID (ci) information */
				(void)tcore_network_set_cell_id(co_network, ci);
				g_free(token_str);
			} else {
				err("No <ci>");
			}
		} else {
			dbg("No <ci> in +CREG");
			(void)tcore_network_get_cell_id(co_network, &ci);
		}

		/* <AcT> */
		if ((token_str = g_slist_nth_data(tokens, 3))) {
			gint idx = atoi(token_str);
			if (idx >= 0 && idx < AT_COPS_ACT_MAX)
				act = lookup_tbl_access_technology[idx];
			else
				act = NETWORK_ACT_UNKNOWN;
			(void)tcore_network_set_access_technology(co_network, act);
		} else {
			dbg("No <AcT> in +CREG");
			(void)tcore_network_get_access_technology(co_network, &act);
		}
		dbg("<stat>: %d <lac>: 0x%x <ci>: 0x%x <AcT>: %d", stat, lac, ci, act);

		/* Send Notification - Network (CS) Registration status */
		registration_status.cs_domain_status = stat;

		tcore_network_get_service_status(co_network,
			TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, &registration_status.ps_domain_status);

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_network)),
			co_network,
			TNOTI_NETWORK_REGISTRATION_STATUS,
			sizeof(struct tnoti_network_registration_status), &registration_status);

#if 0 /* TODO : Implement Roaming State */
		switch (stat) {
		case TEL_NETWORK_REG_STATUS_ROAMING:
			roam_state = TRUE; /* no break */
		case TEL_NETWORK_REG_STATUS_REGISTERED:
			 Fetch Network name - Internal request
			(void)__atmodem_network_fetch_nw_name(co_network,
				__on_response_atmodem_network_fetch_nw_name_internal, NULL);
		break;

		default:
		break;
		}

		tcore_network_set_roaming_state(co_network, roam_state);
#endif

		/* Send Notification - Cell info */
		cell_info.lac = (gint)lac;
		cell_info.cell_id = (gint)ci;

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_network)),
			co_network,
			TNOTI_NETWORK_LOCATION_CELLINFO,
			sizeof(struct tnoti_network_location_cellinfo), &cell_info);

out:
		/* Free resource */
		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

static gboolean on_notification_atmodem_ps_network_info(CoreObject *co_network,
	const void *event_info, void *user_data)
{
	GSList *lines = NULL;
	gchar *line = NULL;

	dbg("Network notification - PS network info: [+CGREG]");

	lines = (GSList *)event_info;
	if (g_slist_length(lines) != 1) {
		err("+CGREG unsolicited message expected to be Single line "
			"but received multiple lines");
		return TRUE;
	}

	line = (char *) (lines->data);
	if (line != NULL) {
		struct tnoti_network_registration_status registration_status = {0, };
		struct tnoti_network_location_cellinfo cell_info = {0, };
		enum telephony_network_service_type service_type = 0;
		GSList *tokens = NULL;
		gchar *token_str;
		guint act = 0, lac = 0, ci = 0, rac = 0;
		enum telephony_network_service_domain_status cs_status;
		enum telephony_network_service_domain_status ps_status;

		/*
		 * Tokenize
		 *
		 * +CGREG: <stat>[, <lac>, <ci>[, <AcT>, <rac>]]
		 */
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("Invalid notification message");
			goto out;
		}

		/* <stat> */
		if ((token_str = g_slist_nth_data(tokens, 0)) == NULL) {
			err("No <stat> in +CGREG");
			goto out;
		}
		ps_status = __atmodem_network_map_stat(atoi(token_str));
		(void)tcore_network_set_service_status(co_network, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, ps_status);

		/* <lac> */
		if ((token_str = g_slist_nth_data(tokens, 1))) {
			token_str = tcore_at_tok_extract((const char *)token_str);
			if (token_str != NULL) {
				lac = (guint)strtol(token_str, NULL, ATMODEM_NETWORK_BASE_16);
				/* Update Location Area Code (lac) information */
				(void)tcore_network_set_lac(co_network, lac);
				g_free(token_str);
			} else {
				err("No <lac>");
			}
		} else {
			dbg("No <lac> in +CGREG");
			(void)tcore_network_get_lac(co_network, &lac);
		}

		/* <ci> */
		if ((token_str = g_slist_nth_data(tokens, 2))) {
			token_str = tcore_at_tok_extract((const char *)token_str);
			if (token_str != NULL) {
				ci = (guint)strtol(token_str, NULL, ATMODEM_NETWORK_BASE_16);
				/* Update Cell ID (ci) information */
				(void)tcore_network_set_cell_id(co_network, ci);
				g_free(token_str);
			} else {
				err("No <ci>");
			}
		} else {
			dbg("No <ci> in +CGREG");
			(void)tcore_network_get_cell_id(co_network, &ci);
		}

		/* <AcT> */
		if ((token_str = g_slist_nth_data(tokens, 3))) {
			gint idx = atoi(token_str);
			if (idx >= 0 && idx < AT_COPS_ACT_MAX)
				act = lookup_tbl_access_technology[idx];
			else
				act = NETWORK_ACT_UNKNOWN;
			(void)tcore_network_set_access_technology(co_network, act);
		} else {
			dbg("No <AcT> in +CGREG");
			(void)tcore_network_get_access_technology(co_network, &act);
		}

		/* <rac> */
		if ((token_str = g_slist_nth_data(tokens, 4))) {
			token_str = tcore_at_tok_extract((const char *)token_str);
			if (token_str != NULL) {
				rac = (guint)strtol(token_str, NULL, ATMODEM_NETWORK_BASE_16);
				/* Update Routing Area Code (rac) information */
				(void)tcore_network_set_rac(co_network, rac);
				g_free(token_str);
			} else {
				err("No <rac>");
			}
		} else {
			err("No <rac> in +CGREG");
			(void)tcore_network_get_rac(co_network, &rac);
		}
		dbg("<stat>: %d <lac>: 0x%x <ci>: 0x%x <AcT>: %d <rac>: 0x%x", ps_status, lac, ci, act, rac);

		/* Send Notification - Network (PS) Registration status */
		registration_status.ps_domain_status = ps_status;

		(void)tcore_network_get_service_status(co_network, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, &cs_status);

		service_type = _get_service_type(service_type, act, cs_status, ps_status);
		dbg("service_type = %d", service_type);
		registration_status.service_type = service_type;
		tcore_network_set_service_type(co_network, service_type);

		(void)tcore_network_get_service_status(co_network, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT,  &registration_status.cs_domain_status);

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_network)),
			co_network,
			TNOTI_NETWORK_REGISTRATION_STATUS,
			sizeof(struct tnoti_network_registration_status), &registration_status);

#if 0 /* TODO : Implement roaming state */
		 Set Roaming state
		if (registration_status.ps_status == TEL_NETWORK_REG_STATUS_ROAMING)
			roam_state = TRUE;

		tcore_network_set_roaming_state(co_network, roam_state);
#endif

		/* Send Notification - Cell info */
		cell_info.lac = lac;
		cell_info.cell_id = ci;

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_network)),
			co_network,
			TNOTI_NETWORK_LOCATION_CELLINFO,
			sizeof(struct tnoti_network_location_cellinfo), &cell_info);

		get_serving_network(co_network, NULL);

out:
		/* Free resource */
		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

static gboolean on_notification_atmodem_network_rssi(CoreObject *co_network,
	const void *event_info, void *user_data)
{
	GSList *lines;
	const gchar *line = NULL;

	dbg("Network notification - Icon (rssi) info: [+CIEV]");

	lines = (GSList *)event_info;
	if (g_slist_length(lines) != 1) {
		err("+CIEV unsolicited message expected to be "
			"Single line but received multiple lines");
		return TRUE;
	}

	line = (const char *)lines->data;
	if (line != NULL) {
		GSList *tokens;
		guint descriptor;
		guint value;
		static struct tnoti_network_icon_info net_icon_info = {0xff, 0, 0, 0};

		tokens = tcore_at_tok_new(line);

		/* <desc> */
		descriptor = atoi(g_slist_nth_data(tokens, 0));
		dbg("Descriptor: [%s]", (descriptor == 10 ? "RSSI"
			: (descriptor == 15 ? "Battery" : "Unknown")));

		/* <value> */
		value = atoi(g_slist_nth_data(tokens, 1));

		switch (descriptor) {
		case 10:
			dbg("RSSI Level: [%d]", value);
			net_icon_info.type = NETWORK_ICON_INFO_RSSI;
			net_icon_info.rssi = value;

			/* Send Notification - Network Rssi */
			tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_network)),
				co_network,
				TNOTI_NETWORK_ICON_INFO,
				sizeof(struct tnoti_network_icon_info),
				&net_icon_info);
			break;
		case 15:
			dbg("Battery Level: [%d]", value);
			break;
		default:
			warn("Unknown descriptor: [%d]", descriptor);
			break;
		}

		/* Free resource */
		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

static void __on_response_atmodem_network_registration(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	dbg("Entry");

	if (at_resp && at_resp->success)
		dbg("Network Registration - [OK]");
	else
		err("Network Registration - [NOK]");
}

static void __atmodem_network_register_to_network(CoreObject *co_network)
{
	TReturn ret;

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_network,
		"AT+COPS=0", NULL,
		TCORE_AT_NO_RESULT,
		NULL,
		__on_response_atmodem_network_registration, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("Sending Network Registration request: [%s]",
		(ret == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));
}

static void on_sim_resp_hook_get_netname(UserRequest *ur, enum tcore_response_command command, unsigned int data_len,
		const void *data, void *user_data)
{
	const struct tresp_sim_read *resp = data;
	CoreObject *o = user_data;
	struct tnoti_network_registration_status regist_status;
	struct tnoti_network_identity network_identity;
	gchar *plmn = NULL;

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
		if (resp->data.spn.display_condition & 0x01)
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_NETWORK);

		if ((resp->data.spn.display_condition & 0x02) == 0)
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_SPN);

		if ((resp->data.spn.display_condition & 0x03) == 0x01)
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_ANY);
	}

	tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, &regist_status.cs_domain_status);
	tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, &regist_status.ps_domain_status);
	tcore_network_get_service_type(o, &regist_status.service_type);
	regist_status.roaming_status = tcore_network_get_roaming_state(o);

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
			TNOTI_NETWORK_REGISTRATION_STATUS, sizeof(struct tnoti_network_registration_status), &regist_status);

	memset(&network_identity, 0x00, sizeof(struct tnoti_network_identity));

	plmn = tcore_network_get_plmn(o);
	if (plmn) {
		dbg("plmn = %s", plmn);
		g_strlcpy(network_identity.plmn, plmn, sizeof(network_identity.plmn));
		g_free(plmn);
	}
	g_strlcpy(network_identity.short_name, "SDK", sizeof(network_identity.short_name));
	g_strlcpy(network_identity.full_name, "SDK", sizeof(network_identity.full_name));

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)),
								o,
								TNOTI_NETWORK_IDENTITY,
								sizeof(struct tnoti_network_identity), &network_identity);
}

/* Hooks */
static enum tcore_hook_return on_hook_sim_init(Server *s, CoreObject *source,
	enum tcore_notification_command command,
	unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_sim_status *sim = data;
	UserRequest *ur = NULL;

	if (sim->sim_status == SIM_STATUS_INIT_COMPLETED) {
		CoreObject *co_network = (CoreObject *)user_data;
		dbg("SIM Initialized!!! Attach to Network");

		/*
		 * TODO - Check for selection_mode
		 *	Need to check if it is Manual or Automatic and based on
		 *	that need to initiate Network Registration accordingly.
		 */
		__atmodem_network_register_to_network(co_network);

		/* Need to get SPN when sim initialization complete */
		ur = tcore_user_request_new(NULL, NULL);
		tcore_user_request_set_command(ur, TREQ_SIM_GET_SPN);
		tcore_user_request_set_response_hook(ur, on_sim_resp_hook_get_netname, user_data);
		tcore_object_dispatch_request(source, ur);
	}
	return TCORE_HOOK_RETURN_CONTINUE;
}

/* Network Responses */
static void on_response_network_search(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	struct tresp_network_search nw_resp;
	UserRequest *ur = NULL;
	int count;
	GSList *tokens = NULL;

	dbg("Enter");

	memset(&nw_resp, 0x0, sizeof(struct tresp_network_search));
	nw_resp.result = TCORE_RETURN_FAILURE;

	if (at_resp && at_resp->success) {
		const gchar *line;
		GSList *net_token = NULL;
		gchar *resp;

		if (!at_resp->lines) {
			err("invalid response received");
			goto END;
		}

		line = (char *) at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		nw_resp.list_count = g_slist_length(tokens);
		if (nw_resp.list_count < 1) {
			err("invalid message");
			goto END;
		}

		dbg("RESPONSE OK");
		count = 0;
		for (count = 0; count < nw_resp.list_count; count++) {
			net_token = tcore_at_tok_new(g_slist_nth_data(tokens, count));
			if (NULL == net_token)
				continue;

			/* Status */
			resp = tcore_at_tok_nth(net_token, 0);
			if (resp != NULL) {
				nw_resp.list[count].status = atoi(resp);
				dbg("Status: [%d]", nw_resp.list[count].status);
			}

			/* Name */
			if ((resp = tcore_at_tok_nth(net_token, 1))) {
				gchar *name = NULL;

				name = tcore_at_tok_extract(resp);
				dbg("name: [%s]", resp);

				g_strlcpy(nw_resp.list[count].name, name, 41);
				/* Emulator gives network name as # terminated string*/
				if (nw_resp.list[count].name[5] == '#')
					nw_resp.list[count].name[5] = '\0';

				g_free(name);
			}

			/* Short Alpha name */
			if ((resp = tcore_at_tok_nth(net_token, 2))) {
				/* Short Alpha name
				dbg("Short Alpha name[%s]", resp);
				plmn_list.network_list[count].network_identity.short_name =
					tcore_at_tok_extract(resp); */
			}

			/* PLMN ID */
			if ((resp = tcore_at_tok_nth(net_token, 3))) {
				char *plmn = NULL;

				plmn = tcore_at_tok_extract(resp);
				dbg("PLMN ID: [%s]", resp);

				g_strlcpy(nw_resp.list[count].plmn, plmn, 6);

				g_free(plmn);
			}

			/* Parse Access Technology */
			if ((resp = tcore_at_tok_nth(tokens, 4))) {
				if (strlen(resp) > 0) {
					gint act = atoi(resp);
					dbg("AcT: [%d]", act);
					if (act >= 0 && act < AT_COPS_ACT_MAX)
						nw_resp.list[count].act = lookup_tbl_access_technology[act];
					else
						nw_resp.list[count].act = NETWORK_ACT_UNKNOWN;
				}
			} else {
					nw_resp.list[count].act = NETWORK_ACT_UMTS;
			}

			dbg("[%d] Status: [%d] name: [%s] PLMN: [%s] AcT: [%d]",
					count,
					nw_resp.list[count].status,
					nw_resp.list[count].name,
					nw_resp.list[count].plmn,
					nw_resp.list[count].act);

			tcore_at_tok_free(net_token);
		}

		nw_resp.result = TCORE_RETURN_SUCCESS;
	} else {
		err("RESPONSE NOK");
		if (at_resp)
			err("CME Error[%s]", (char *)(at_resp->lines ? at_resp->lines->data : "Unknown"));
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_NETWORK_SEARCH,
			sizeof(struct tresp_network_search), &nw_resp);
	} else {
		err("ur is NULL");
	}

END:
	dbg("Network search : [%s]",
		(nw_resp.result == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));

	tcore_at_tok_free(tokens);
}

static void on_response_network_get_plmn_selection_mode(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	struct tresp_network_get_plmn_selection_mode nw_resp = {0, };
	UserRequest *ur = NULL;
	GSList *tokens = NULL;

	dbg("Enter");

	nw_resp.result = TCORE_RETURN_FAILURE; /* TODO - CME Error mapping required. */

	if (at_resp && at_resp->success) {
		const gchar *line;
		gint mode;

		if (!at_resp->lines) {
			err("invalid response received");
			goto END;
		}

		line = (char *) at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			msg("invalid message");
			goto END;
		}
		dbg("RESPONSE OK");

		mode = atoi(tcore_at_tok_nth(tokens, 0));
		if (mode == 0)
			nw_resp.mode = NETWORK_SELECT_MODE_AUTOMATIC;
		else if (mode == 1)
			nw_resp.mode  = NETWORK_SELECT_MODE_MANUAL;

		dbg("selection mode[%d]", nw_resp.mode);
		nw_resp.result = TCORE_RETURN_SUCCESS;
	} else {
		err("RESPONSE NOK");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_NETWORK_GET_PLMN_SELECTION_MODE,
			sizeof(struct tresp_network_get_plmn_selection_mode), &nw_resp);
	} else {
		err("ur is NULL");
	}

END:
	dbg("Get selection mode : [%s]",
			(nw_resp.result == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Free resource*/
	tcore_at_tok_free(tokens);
}

static void on_response_network_set_plmn_selection_mode(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	struct tresp_network_set_plmn_selection_mode nw_resp;
	UserRequest *ur = NULL;

	dbg("Enter");

	if (at_resp) {
		if (at_resp->success) {
			dbg("RESPONSE OK");
			nw_resp.result = TCORE_RETURN_SUCCESS;
		} else {
			err("RESPONSE NOK");
			if (at_resp->lines)
				err("CME Error[%s]", (char *)at_resp->lines->data);
				nw_resp.result = TCORE_RETURN_FAILURE;
		}
	} else {
		err("Response: [NOK]");
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_NETWORK_SET_PLMN_SELECTION_MODE,
			sizeof(struct tresp_network_set_plmn_selection_mode), &nw_resp);
	} else {
		err("ur is NULL");
	}
}

static void on_response_network_get_serving_network(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	struct tresp_network_get_serving_network nw_resp = {0, };
	enum telephony_network_access_technology act = NETWORK_ACT_UNKNOWN;
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	char *plmn = NULL;
	CoreObject *co_network = tcore_pending_ref_core_object(p);
	guint lac = 0;

	dbg("Enter");

	if (at_resp && at_resp->success) {
		const gchar *line;
		int num_lines, count;
		char *local_data = NULL;

		if (!at_resp->lines) {
			err("invalid response received");
			nw_resp.result = TCORE_RETURN_FAILURE;
			goto END;
		}

		dbg("RESPONSE OK");
		nw_resp.result = TCORE_RETURN_SUCCESS;

		num_lines = g_slist_length(at_resp->lines);
		dbg("number of lines: %d", num_lines);

		for (count = 0; count < num_lines; count++) {
			line = g_slist_nth_data(at_resp->lines, count);
			tokens = tcore_at_tok_new(line);
			/* mode */
			if ((local_data = tcore_at_tok_nth(tokens, 0)))
				dbg("mode  : %s", local_data);

			/* format */
			if ((local_data = tcore_at_tok_nth(tokens, 1)))
				dbg("format  : %s", local_data);

			/*plmn */
			if ((plmn = tcore_at_tok_nth(tokens, 2))) {
				dbg("plmn  : %s", plmn);
				g_strlcpy(nw_resp.plmn, plmn, 6);
				tcore_network_set_plmn(co_network, nw_resp.plmn);
				if (!g_strcmp0(nw_resp.plmn, "11111")) {
					/* In case of emulator, need to show "SDK" on indicator instead of "11111" */
					tcore_network_set_network_name(co_network, TCORE_NETWORK_NAME_TYPE_FULL, "SDK");
				}
			}

			/* act */
			if ((local_data = tcore_at_tok_nth(tokens, 3))) {
				gint idx = atoi(local_data);
				dbg("AcT  : %s", local_data);
				if (idx >= 0 && idx < AT_COPS_ACT_MAX)
					act = lookup_tbl_access_technology[idx];
				else
					act = NETWORK_ACT_UNKNOWN;
			}
			nw_resp.act = act;

			(void)tcore_network_get_lac(co_network, &lac);
			dbg("lac  : %x", lac);

			nw_resp.gsm.lac = lac;

			tcore_at_tok_free(tokens);
		}
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_NETWORK_GET_SERVING_NETWORK,
			sizeof(struct tresp_network_get_serving_network), &nw_resp);
	} else {
		struct tnoti_network_change network_change;

		memset(&network_change, 0, sizeof(struct tnoti_network_change));
		memcpy(network_change.plmn, nw_resp.plmn, 6);
		network_change.act = act;
		network_change.gsm.lac = lac;

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_pending_ref_plugin(p)),
									tcore_pending_ref_core_object(p),
									TNOTI_NETWORK_CHANGE,
									sizeof(struct tnoti_network_change), &network_change);
		}

END:
	dbg("Get serving network : [%s]",
			(nw_resp.result == TCORE_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));
}

/* Requests */
static TReturn search_network(CoreObject *co_network, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_network,
		"AT+COPS=?", "+COPS",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_network_search, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	return ret;
}


static TReturn set_plmn_selection_mode(CoreObject *co_network, UserRequest *ur)
{
	gchar *at_cmd;
	struct treq_network_set_plmn_selection_mode *mode_info = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	mode_info = (struct treq_network_set_plmn_selection_mode *)tcore_user_request_ref_data(ur, 0);

	if (mode_info->mode == NETWORK_SELECT_MODE_AUTOMATIC) {
		at_cmd = g_strdup_printf("AT+COPS=0");
		dbg(" Mode - Automatic: -- %s", at_cmd);
	} else {
		gint act;

		switch (mode_info->act) {
		case NETWORK_ACT_GSM:
		case NETWORK_ACT_GPRS:
		case NETWORK_ACT_EGPRS:
			act = 0;
		break;

		case NETWORK_ACT_UMTS:
		case NETWORK_ACT_GSM_UTRAN:
			act = 2;
		break;

		default:
			err("Unsupported AcT: [%d]", mode_info->act);
			return ret;
		}
		at_cmd = g_strdup_printf("AT+COPS=1, 2, \"%s\", %d", mode_info->plmn, act);
	}

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_network, at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_network_set_plmn_selection_mode, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

static TReturn get_plmn_selection_mode(CoreObject *co_network, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_network,
		"AT+COPS?", "+COPS",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_network_get_plmn_selection_mode, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	return ret;
}

static TReturn get_serving_network(CoreObject *co_network, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_network,
		"AT+COPS?", "+COPS",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_network_get_serving_network, NULL,
		on_send_at_request, NULL, 0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	return ret;
}

static TReturn get_default_subscription(CoreObject *co, UserRequest *ur)
{
	struct tresp_network_get_default_subs resp_data = {0, };
	TReturn ret = TCORE_RETURN_FAILURE;
	Server *server;
	Storage *strg = NULL;
	TcorePlugin *plugin = tcore_object_ref_plugin(co);

	dbg("Enter");

	server = tcore_plugin_ref_server(plugin);
	strg = tcore_server_find_storage(server, "vconf");

	/* VCONFKEY is aligned to req_data->current_network type */
	resp_data.default_subs = tcore_storage_get_int(strg,
			STORAGE_KEY_TELEPHONY_DUALSIM_DEFAULT_SERVICE_INT);

	resp_data.result = TCORE_RETURN_SUCCESS;

	/* Send Response */
	ret = tcore_user_request_send_response(ur,
		TRESP_NETWORK_GET_DEFAULT_SUBSCRIPTION,
		sizeof(struct tresp_network_get_default_subs), &resp_data);

	dbg("ret: [0x%x]", ret);
	return ret;
}

static TReturn get_default_data_subscription(CoreObject *co, UserRequest *ur)
{
	struct tresp_network_get_default_data_subs resp = {0, };
	Server *server;
	Storage *strg = NULL;
	TcorePlugin *plugin = tcore_object_ref_plugin(co);
	TReturn ret;

	dbg("Enter");

	server = tcore_plugin_ref_server(plugin);
	strg = tcore_server_find_storage(server, "vconf");

	resp.default_subs = tcore_storage_get_int(strg, STORAGE_KEY_TELEPHONY_DUALSIM_DEFAULT_DATA_SERVICE_INT);
	dbg("Defualt data Subscription: [%d]", resp.default_subs);

	resp.result = TCORE_RETURN_SUCCESS;

	ret = tcore_user_request_send_response(ur,
		TRESP_NETWORK_GET_DEFAULT_DATA_SUBSCRIPTION,
		sizeof(struct tresp_network_get_default_data_subs), &resp);
	if (TCORE_RETURN_SUCCESS ==  ret)
		tcore_user_request_unref(ur);

	return ret;
}

/** Network operations */
static struct tcore_network_operations network_ops = {
	.search = search_network,
	.set_plmn_selection_mode = set_plmn_selection_mode,
	.get_plmn_selection_mode = get_plmn_selection_mode,
	.set_service_domain = NULL,
	.get_service_domain = NULL,
	.set_band = NULL,
	.get_band = NULL,
	.set_preferred_plmn = NULL,
	.get_preferred_plmn = NULL,
	.set_order = NULL,
	.get_order = NULL,
	.set_power_on_attach = NULL,
	.get_power_on_attach = NULL,
	.set_cancel_manual_search = NULL,
	.get_serving_network = get_serving_network,
	.get_default_subscription = get_default_subscription,
	.get_default_data_subscription = get_default_data_subscription,
};

gboolean s_network_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *co_network;

	co_network = tcore_network_new(p, "umts_network", &network_ops, h);
	if (!co_network) {
		err("Core object is NULL");
		return FALSE;
	}

	/* Add Callbacks */
	tcore_object_add_callback(co_network,
		"+CREG:",
		on_notification_atmodem_cs_network_info, NULL);
	tcore_object_add_callback(co_network,
		"+CGREG:",
		on_notification_atmodem_ps_network_info, NULL);
	tcore_object_add_callback(co_network,
		"+CIEV:",
		on_notification_atmodem_network_rssi, NULL);

	/* Add notification hook */
	tcore_server_add_notification_hook(tcore_plugin_ref_server(p),
		TNOTI_SIM_STATUS,
		on_hook_sim_init, co_network);

	_insert_mcc_mnc_oper_list(p, co_network);

	return TRUE;
}

void s_network_exit(TcorePlugin *p)
{
	CoreObject *co_network;

	if (!p) {
		err("Plugin is NULL");
		return;
	}

	co_network = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_NETWORK);

	tcore_network_free(co_network);
}

