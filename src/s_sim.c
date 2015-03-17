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

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <server.h>
#include <queue.h>
#include <co_sim.h>
#include <storage.h>
#include <user_request.h>
#include <at.h>

#include "s_common.h"
#include "s_sim.h"

#define SIM_ACCESS_READ_BINARY		176
#define SIM_ACCESS_READ_RECORD		178
#define SIM_ACCESS_GET_RESPONSE		192
#define SIM_ACCESS_UPDATE_BINARY		214
#define SIM_ACCESS_UPDATE_RECORD		220

#define SIM_ICCID		"89914500020137312178"


#define ALLOC_METAINFO()	do { \
	file_meta = g_malloc0(sizeof(sim_meta_info_t)); \
	dbg("Allocated - file_meta: [%p]", file_meta); \
} while (0)

#define FREE_METAINFO()	do { \
	dbg("Freeing - file_meta: [%p]", file_meta); \
} while (0)

#define SWAP_BYTES_16(x) \
{ \
	unsigned short int local_data = *(unsigned short int *)&(x);	\
	local_data = ((local_data & 0xff00) >> 8) |	  \
		   ((local_data & 0x00ff) << 8);	  \
	*(unsigned short int *)&(x) = local_data;	 \
}

typedef enum {
	SIM_FILE_TYPE_DEDICATED = 0x00,	/**< Dedicated */
	SIM_FILE_TYPE_TRANSPARENT = 0x01,	/**< Transparent -binary type*/
	SIM_FILE_TYPE_LINEAR_FIXED = 0x02,	/**< Linear fixed - record type*/
	SIM_FILE_TYPE_CYCLIC = 0x04,	/**< Cyclic - record type*/
	SIM_FILE_TYPE_INVALID_TYPE = 0xFF	/**< Invalid type */
} sim_file_type_t;

typedef enum {
	SIM_CURR_SEC_OP_PIN1_VERIFY,
	SIM_CURR_SEC_OP_PIN2_VERIFY,
	SIM_CURR_SEC_OP_PUK1_VERIFY,
	SIM_CURR_SEC_OP_PUK2_VERIFY,
	SIM_CURR_SEC_OP_SIM_VERIFY,
	SIM_CURR_SEC_OP_ADM_VERIFY,
	SIM_CURR_SEC_OP_PIN1_CHANGE,
	SIM_CURR_SEC_OP_PIN2_CHANGE,
	SIM_CURR_SEC_OP_PIN1_ENABLE,
	SIM_CURR_SEC_OP_PIN1_DISABLE,
	SIM_CURR_SEC_OP_PIN2_ENABLE,
	SIM_CURR_SEC_OP_PIN2_DISABLE, // 10
	SIM_CURR_SEC_OP_SIM_ENABLE,
	SIM_CURR_SEC_OP_SIM_DISABLE,
	SIM_CURR_SEC_OP_NET_ENABLE,
	SIM_CURR_SEC_OP_NET_DISABLE,
	SIM_CURR_SEC_OP_NS_ENABLE,
	SIM_CURR_SEC_OP_NS_DISABLE,
	SIM_CURR_SEC_OP_SP_ENABLE,
	SIM_CURR_SEC_OP_SP_DISABLE,
	SIM_CURR_SEC_OP_CP_ENABLE,
	SIM_CURR_SEC_OP_CP_DISABLE, // 20
	SIM_CURR_SEC_OP_FDN_ENABLE,
	SIM_CURR_SEC_OP_FDN_DISABLE,
	SIM_CURR_SEC_OP_PIN1_STATUS,
	SIM_CURR_SEC_OP_PIN2_STATUS,
	SIM_CURR_SEC_OP_FDN_STATUS,
	SIM_CURR_SEC_OP_NET_STATUS,
	SIM_CURR_SEC_OP_NS_STATUS,
	SIM_CURR_SEC_OP_SP_STATUS,
	SIM_CURR_SEC_OP_CP_STATUS,
	SIM_CURR_SEC_OP_SIM_STATUS,
	SIM_CURR_SEC_OP_SIM_UNKNOWN = 0xff
} sim_sec_op_t;

typedef enum {
	SEC_LOCK_TYPE_NONE =0,
	SEC_LOCK_TYPE_READY,	/*  ME is not locked */
	SEC_LOCK_TYPE_PS,		/* PH-SIM, Lock Phone to SIM/UICC card(MT asks password when other than current SIM/UICC card inserted; MT may remember certain amount of
                                                         previously used cards thus not requiring password when they are inserted ) */
	SEC_LOCK_TYPE_PF,	/*  PH-FSIM, Lock Phone to the very First  inserted SIM/UICC card ( MT asks password when other than the first SIM/UICC card is inserted ) */
	SEC_LOCK_TYPE_SC,	/*Lock SIM/UICC card ( SIM asks password in ME power-up and when this command is issued ) */
	SEC_LOCK_TYPE_FD,	/* SIM card or active application in the UICC(GSM or USIM) fixed dialing memory feature */
	SEC_LOCK_TYPE_PN,		/*  Network Personalization */
	SEC_LOCK_TYPE_PU,	/*  Network subset Personalization */
	SEC_LOCK_TYPE_PP,	/*  Service Provider Personalization */
	SEC_LOCK_TYPE_PC,	/*  Corporate Personalization */
	SEC_LOCK_TYPE_SC2,	/*  Lock PIN2 ( ... ) */
	SEC_LOCK_TYPE_PUK2,	/*  Lock PUK2 (... ) */
	SEC_LOCK_TYPE_ACL,	/* ACL */

	SEC_LOCK_TYPE_NO_SIM,		/* SIM is not inserted */
	SEC_LOCK_TYPE_UNAVAIL,	/*  SIM is inserted but can not communicate with SIM ( SIM interface error ) */
	SEC_SIM_INIT_COMPLETED,	/*  SIM Initialize Completed */
	SEC_PB_INIT_COMPLETED,	/*  Phonebook Initialize Completed*/
	SEC_SIM_INIT_CRASH,		/*  SIM Crash request from SMC lab*/

	SEC_LOCK_TYPE_MAX
} sim_sec_lock_type_t;

typedef enum {
	SEC_LOCK_KEY_NONE,
	SEC_LOCK_KEY_UNLOCKED,		/* Not necessary */
	SEC_LOCK_KEY_PIN,		/* PIN required as a password */
	SEC_LOCK_KEY_PUK,		/* 0PUK required as a password */
	SEC_LOCK_KEY_PIN2,		/* PIN2 required as a password */
	SEC_LOCK_KEY_PUK2,		/*  PUK2 required as a password */
	SEC_LOCK_KEY_PERM_BLOCKED,    /* PIN Permanent Blocked */
	SEC_LOCK_KEY_PIN2_DISABLE,     /* PIN2 Lock Disabled*/
	SEC_LOCK_KEY_MAX
} sim_sec_lock_key_t;

typedef struct {
	guint smsp_count;					/**< SMSP record count */
	guint smsp_rec_len;					/**< SMSP record length */
} sim_private_info_t;

typedef struct {
	gboolean b_valid;					/**< Valid or not */
	guint rec_length;					/**< Length of one record in file */
	guint rec_count;					/**< Number of records in file */
	guint data_size;					/**< File size */
	guint current_index;					/**< Current index to read */
	sim_file_type_t file_type;				/**< File type and structure */
//	sim_sec_op_t sec_op;					/**< Current index to read */
	struct tel_sim_mbi_list mbi_list;				/**< Mailbox List */
	struct tel_sim_mb_number mb_list[SIM_MSP_CNT_MAX*5];	/**< Mailbox number */
	enum tel_sim_file_id file_id;					/**< Current file id */
	TReturn file_result;				/**< File access result */
	struct tresp_sim_read files;					/**< File read data */
	enum tcore_request_command req_command;				/**< Request command Id */
	struct tel_sim_imsi imsi;					/**< Stored locally as of now,
								          Need to store in secure storage*/
} sim_meta_info_t;

/* Request Function Declaration */
//static TReturn __sim_get_imsi(CoreObject *co_sim, UserRequest *ur);
static TReturn __sim_get_ecc(CoreObject *co_sim, UserRequest *ur);
static TReturn __sim_get_spdi(CoreObject *co_sim, UserRequest *ur);
static TReturn __sim_get_spn(CoreObject *co_sim, UserRequest *ur);
static TReturn __sim_get_language(CoreObject *co_sim, UserRequest *ur);
static TReturn __sim_get_cfis(CoreObject *co_sim, UserRequest *ur);

static TReturn s_sim_verify_pins(CoreObject *co_sim, UserRequest *ur);
static TReturn s_sim_verify_puks(CoreObject *co_sim, UserRequest *ur);
static TReturn s_sim_change_pins(CoreObject *co_sim, UserRequest *ur);
static TReturn s_sim_disable_facility(CoreObject *co_sim, UserRequest *ur);
static TReturn s_sim_enable_facility(CoreObject *co_sim, UserRequest *ur);
static TReturn s_sim_get_facility(CoreObject *co_sim, UserRequest *ur);
static TReturn s_sim_read_file(CoreObject *co_sim, UserRequest *ur);

/* Utility Function Declaration */
static TReturn __sim_decode_status_word(unsigned short status_word1, unsigned short status_word2);
static void __sim_update_sim_status(CoreObject *co_sim, enum tel_sim_status sim_status);
static void __sim_get_sim_type(CoreObject *co_sim);
static const char *__sim_get_fac_from_lock_type(enum tel_sim_facility_type lock_type);
//static int __sim_get_lock_type(sim_sec_op_t sec_op);
static gboolean __convert_scpin_str_to_enum(char* line,
	sim_sec_lock_type_t* lock_type, sim_sec_lock_key_t* lock_key);

/* Internal Response Functions*/
static void __sim_next_from_read_data(CoreObject *co_sim, UserRequest *ur,
	sim_meta_info_t *file_meta, enum tel_sim_access_result sim_result, gboolean decode_ret);
static void __sim_next_from_get_response(CoreObject *co_sim, UserRequest *ur,
	sim_meta_info_t *file_meta, enum tel_sim_access_result sim_result, gboolean decode_ret);
static void __sim_read_record(CoreObject *co_sim, UserRequest *ur, sim_meta_info_t *file_meta);
static void __sim_read_binary(CoreObject *co_sim, UserRequest *ur, sim_meta_info_t *file_meta);
static TReturn __sim_get_response(CoreObject *co_sim, UserRequest *ur, sim_meta_info_t *file_meta);
static void __on_response_sim_get_sim_type(TcorePending *p,
	gint data_len, const void *data, void *user_data);

static enum tcore_response_command __find_resp_command(UserRequest *ur);
static gchar __util_hexchar_to_int(gchar c);
static gboolean __util_hexstring_to_bytes(gchar *hex_str,
	gchar **bytes, guint *bytes_len);

#define SIM_READ_FILE(co_sim, cb, cb_data, fileId, ret)	do { \
	sim_meta_info_t *file_meta = {0, }; \
	\
	ALLOC_METAINFO(); \
	file_meta->file_id = fileId; \
	file_meta->file_result = SIM_ACCESS_FAILED; \
	\
	ret = __sim_get_response(co_sim, NULL, file_meta); \
} while (0)

static gchar __util_hexchar_to_int(gchar c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	else if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	else if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	else {
		err("Invalid charater!!");
		return -1;
	}
}

static gboolean __util_hexstring_to_bytes(gchar *hex_str,
	gchar **bytes, guint *bytes_len)
{
	gchar *byte_str;
	guint hex_str_len;
	guint i;

	if (hex_str == NULL)
		return FALSE;

	hex_str_len = strlen(hex_str);

	byte_str = g_malloc0((hex_str_len / 2) + 1);

	dbg("Convert String to Binary!!!");
	for (i = 0; i < hex_str_len; i += 2) {
		byte_str[i / 2] = (gchar)((__util_hexchar_to_int(hex_str[i]) << 4)
				| __util_hexchar_to_int(hex_str[i + 1]));
		msg("		[%02x]", byte_str[i / 2]);
	}

	*bytes_len = (hex_str_len / 2);
	*bytes = byte_str;

	return TRUE;
}
static enum tcore_response_command __find_resp_command(UserRequest *ur)
{
	enum tcore_request_command command;

	command = tcore_user_request_get_command(ur);
	switch (command) {
	case TREQ_SIM_VERIFY_PINS:
		return TRESP_SIM_VERIFY_PINS;

	case TREQ_SIM_VERIFY_PUKS:
		return TRESP_SIM_VERIFY_PUKS;

	case TREQ_SIM_CHANGE_PINS:
		return TRESP_SIM_CHANGE_PINS;

	case TREQ_SIM_GET_FACILITY_STATUS:
		return TRESP_SIM_GET_FACILITY_STATUS;

	case TREQ_SIM_DISABLE_FACILITY:
		return TRESP_SIM_DISABLE_FACILITY;

	case TREQ_SIM_ENABLE_FACILITY:
		return TRESP_SIM_ENABLE_FACILITY;

	case TREQ_SIM_GET_LOCK_INFO:
		return TRESP_SIM_GET_LOCK_INFO;

	case TREQ_SIM_TRANSMIT_APDU:
		return TRESP_SIM_TRANSMIT_APDU;

	case TREQ_SIM_GET_ATR:
		return TRESP_SIM_GET_ATR;

	case TREQ_SIM_GET_ECC:
		return TRESP_SIM_GET_ECC;

	case TREQ_SIM_GET_LANGUAGE:
		return TRESP_SIM_GET_LANGUAGE;

	case TREQ_SIM_SET_LANGUAGE:
		return TRESP_SIM_SET_LANGUAGE;

	case TREQ_SIM_GET_ICCID:
		return TRESP_SIM_GET_ICCID;

	case TREQ_SIM_GET_MAILBOX:
		return TRESP_SIM_GET_MAILBOX;

	case TREQ_SIM_SET_MAILBOX:
		return TRESP_SIM_SET_MAILBOX;

	case TREQ_SIM_GET_CALLFORWARDING:
		return TRESP_SIM_GET_CALLFORWARDING;

	case TREQ_SIM_SET_CALLFORWARDING:
		return TRESP_SIM_SET_CALLFORWARDING;

	case TREQ_SIM_GET_MESSAGEWAITING:
		return TRESP_SIM_GET_MESSAGEWAITING;

	case TREQ_SIM_SET_MESSAGEWAITING:
		return TRESP_SIM_SET_MESSAGEWAITING;

	case TREQ_SIM_GET_CPHS_INFO:
		return TRESP_SIM_GET_CPHS_INFO;

	case TREQ_SIM_GET_MSISDN:
		return TRESP_SIM_GET_MSISDN;

	case TREQ_SIM_GET_SPN:
		return TRESP_SIM_GET_SPN;

	case TREQ_SIM_GET_SPDI:
		return TRESP_SIM_GET_SPDI;

	case TREQ_SIM_GET_OPL:
		return TRESP_SIM_GET_OPL;

	case TREQ_SIM_GET_PNN:
		return TRESP_SIM_GET_PNN;

	case TREQ_SIM_GET_CPHS_NETNAME:
		return TRESP_SIM_GET_CPHS_NETNAME;

	case TREQ_SIM_GET_OPLMNWACT:
		return TRESP_SIM_GET_OPLMNWACT;

	case TREQ_SIM_REQ_AUTHENTICATION:
		return TRESP_SIM_REQ_AUTHENTICATION;

	case TREQ_SIM_GET_SERVICE_TABLE:
		return TRESP_SIM_GET_SERVICE_TABLE;

	case TREQ_SIM_SET_POWERSTATE:
		return TRESP_SIM_SET_POWERSTATE;

	default:
		err("Unknown/Unmapped Request command: [0x%x]", command);
		break;
	}
	return TRESP_UNKNOWN;
}

#if 0
static void __sim_set_identity(CoreObject *co_sim, struct tel_sim_imsi *imsi)
{
	gchar new_imsi[15 + 1] = {0, };
	gchar *old_imsi;

	memcpy(&new_imsi, imsi->mcc, strlen(imsi->mcc));
	memcpy(&new_imsi[strlen(imsi->mcc)], imsi->mnc, strlen(imsi->mnc));
	memcpy(&new_imsi[strlen(imsi->mcc) + strlen(imsi->mnc)], imsi->msin, strlen(imsi->msin));

	/* TODO: This is temporary code, we should use secure storage instead of vconf */
	old_imsi = vconf_get_str("db/telephony/imsi");
	if (old_imsi) {
		if (g_strcmp0(old_imsi, new_imsi) != 0) {
			dbg("New SIM");
			vconf_set_str("db/telephony/imsi", new_imsi);
			tcore_sim_set_identification(co_sim, TRUE);
		} else {
			dbg("Same SIM");
			tcore_sim_set_identification(co_sim, FALSE);
		}
	} else {
		dbg("Old IMSI value is NULL, set IMSI");
		vconf_set_str("db/telephony/imsi", new_imsi);
		tcore_sim_set_identification(co_sim, TRUE);
	}
}
#endif

/* Utility Functions */
static TReturn __sim_decode_status_word(unsigned short status_word1,
	unsigned short status_word2)
{
	TReturn rst = SIM_ACCESS_FAILED;

	if (status_word1 == 0x93 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg("error - SIM application toolkit busy [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg("error - No EF Selected [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x02) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg("error - Out of Range - Invalid address or record number[%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x04) {
		rst = SIM_ACCESS_FILE_NOT_FOUND;
		/*Failed SIM request command*/
		dbg("error - File ID not found [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x08) {
		rst = SIM_ACCESS_FAILED; /* MOdem not support */
		/*Failed SIM request command*/
		dbg("error - File is inconsistent with command - "\
			"Modem not support or USE IPC [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x02) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error - CHV not initialized [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x04) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error - Access condition not fullfilled [%x][%x]",
			status_word1, status_word2);
		dbg("error -Unsuccessful CHV verification - "\
			"at least one attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Unsuccessful Unblock CHV - at least one attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Authentication failure [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x08) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error - Contradiction with CHV status [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x10) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error - Contradiction with invalidation status [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x40) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error -Unsuccessful CHV verification - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Unsuccessful Unblock CHV - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - CHV blocked [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x67 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		dbg("error -Incorrect Parameter 3 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6B && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		dbg("error -Incorrect Parameter 1 or 2 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6D && status_word2 == 0x00) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg("error -Unknown instruction given as command [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x6E && status_word2 == 0x00) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg("error -Unknown instruction given as command [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x69 && status_word2 == 0x82) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg("error -Access denied [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x87) {
		rst = SIM_ACCESS_FAILED;
		dbg("error -Incorrect parameters [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x82) {
		rst = SIM_ACCESS_FILE_NOT_FOUND; // not sure of the SW1 and SW2 meaning here
		dbg("error -File Not found [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x83) {
		rst = SIM_ACCESS_FILE_NOT_FOUND; // not sure of the SW1 and SW2 meaning here
		dbg("error -Record Not found [%x][%x]", status_word1, status_word2);
	} else {
		rst = SIM_ACCESS_CARD_ERROR;
		dbg("error -Unknown state [%x][%x]", status_word1, status_word2);
	}
	return rst;
}

static void __sim_update_sim_status(CoreObject *co_sim,
	enum tel_sim_status sim_status)
{
	enum tel_sim_status curr_sim_status;

	/*
	 * Send SIM Init status, if not sent already
	 */
	curr_sim_status = tcore_sim_get_status(co_sim);
	if (sim_status != curr_sim_status) {
		Server *s;
		struct tnoti_sim_status sim_status_noti = {0, };

		dbg("Change in SIM State - Old State: [0x%02x] --> New State: [0x%02x]",
				curr_sim_status, sim_status);

		/* Update SIM Status */
		tcore_sim_set_status(co_sim, sim_status);
		sim_status_noti.sim_status = sim_status;
		sim_status_noti.b_changed = FALSE;	/* TODO: checkout */

		s = tcore_plugin_ref_server(tcore_object_ref_plugin(co_sim));

		/* Send notification: SIM Status */
		tcore_server_send_notification(s, co_sim,
			TNOTI_SIM_STATUS,
			sizeof(struct tnoti_sim_status), &sim_status_noti);
	}
}

static gboolean __convert_scpin_str_to_enum(char* line,
		sim_sec_lock_type_t *lock_type, sim_sec_lock_key_t *lock_key)
{
	char *type =NULL, *key = NULL;
	GSList *tokens = NULL;

	if(line == NULL)
		return FALSE;

	tokens = tcore_at_tok_new(line);

	type = g_slist_nth_data(tokens, 0);
	if (!type) {
		err("Type is missing");
		tcore_at_tok_free(tokens);
		return FALSE;
	}

	if (g_strcmp0(type, "NO_LOCK") == 0) {
		key = g_slist_nth_data(tokens, 1);
		if (!key) {
			err("Key is missing");
			tcore_at_tok_free(tokens);
			return FALSE;
		}

		dbg("type: [%s], key: [%s]", type, key);
	}

	if(g_str_has_prefix (type, "NO_SIM"))
		*lock_type = SEC_LOCK_TYPE_NO_SIM;
	else if(g_str_has_prefix (type, "UNAVAIL"))
		*lock_type = SEC_LOCK_TYPE_UNAVAIL;
	else if(g_str_has_prefix (type, "NO_LOCK"))
		*lock_type =  SEC_LOCK_TYPE_READY;
	else if(g_str_has_prefix (type, "LOCK_PS"))
		*lock_type =  SEC_LOCK_TYPE_PS;
	else if(g_str_has_prefix (type, "LOCK_PF"))
		*lock_type = SEC_LOCK_TYPE_PF ;
	else if(g_str_has_prefix (type, "LOCK_SC"))
		*lock_type =  SEC_LOCK_TYPE_SC;
	else if(g_str_has_prefix (type, "LOCK_FD"))
		*lock_type =  SEC_LOCK_TYPE_FD;
	else if(g_str_has_prefix (type, "LOCK_PN"))
		*lock_type = SEC_LOCK_TYPE_PN ;
	else if(g_str_has_prefix (type, "LOCK_PU"))
		*lock_type = SEC_LOCK_TYPE_PU ;
	else if(g_str_has_prefix (type, "LOCK_PP"))
		*lock_type =  SEC_LOCK_TYPE_PP;
	else if(g_str_has_prefix (type, "LOCK_PC"))
		*lock_type =  SEC_LOCK_TYPE_PC;
	else if(g_str_has_prefix (type, "LOCK_SC2"))
		*lock_type = SEC_LOCK_TYPE_SC2 ;
	else if(g_str_has_prefix (type, "LOCK_ACL"))
		*lock_type = SEC_LOCK_TYPE_ACL;
	else if(g_str_has_prefix (type, "LOCK_PUK2"))
		*lock_type = SEC_LOCK_TYPE_PUK2;
	else if(g_str_has_prefix (type, "INIT_COMP"))
		*lock_type = SEC_SIM_INIT_COMPLETED;
	else if(g_str_has_prefix (type, "INIT_ERROR"))
		*lock_type = SEC_SIM_INIT_CRASH;
	else
		*lock_type = SEC_LOCK_TYPE_NONE;

	if(g_str_has_prefix (key, "PIN"))
		*lock_key = SEC_LOCK_KEY_PIN;
	else if(g_str_has_prefix (key, "PUK"))
		*lock_key = SEC_LOCK_KEY_PUK;
	else if(g_str_has_prefix (key, "PIN2"))
		*lock_key =  SEC_LOCK_KEY_PIN2;
	else if(g_str_has_prefix (key, "PUK2"))
		*lock_key =  SEC_LOCK_KEY_PUK2;
	else if(g_str_has_prefix (key, "BLOCKED"))
		*lock_key = SEC_LOCK_KEY_PERM_BLOCKED ;
	else if(g_str_has_prefix (key, "UNLOCKED"))
		*lock_key = SEC_LOCK_KEY_UNLOCKED ;
	else if(g_str_has_prefix (key, "PIN2_DISABLE"))
		*lock_key =  SEC_LOCK_KEY_PIN2_DISABLE;
	else
		*lock_key = SEC_LOCK_KEY_NONE;

	if(*lock_type ==  SEC_LOCK_TYPE_READY)
		*lock_key = SEC_LOCK_KEY_UNLOCKED;

	if((*lock_type == SEC_LOCK_TYPE_NO_SIM)||(*lock_type == SEC_LOCK_TYPE_UNAVAIL)||
			(*lock_type == SEC_SIM_INIT_COMPLETED)||(*lock_type == SEC_SIM_INIT_CRASH))
		*lock_key = SEC_LOCK_KEY_NONE;

	dbg("type: [%d], key: [%d]", *lock_type, *lock_key);

	tcore_at_tok_free(tokens);

	return TRUE;
}

static void __on_response_sim_get_sim_type(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	CoreObject *co_sim = tcore_pending_ref_core_object(p);
	enum tel_sim_type sim_type = SIM_TYPE_UNKNOWN;

	dbg("SIM Response - SIM Type: [+SCCT]");

	CHECK_AND_RETURN(co_sim != NULL);

	if (at_resp && at_resp->success) {
		if (at_resp->lines) {
			const gchar *line;
			GSList *tokens;

			line = (const gchar *)at_resp->lines->data;

			/*
			 * Tokenize
			 *
			 *	%SCCT: <state>
			 */
			tokens = tcore_at_tok_new(line);

			/* <state> */
			if (g_slist_length(tokens) == 1) {
				sim_type = atoi(g_slist_nth_data(tokens, 0));

				dbg("SIM Type: [%d]", sim_type);

				/* Update SIM type */
				tcore_sim_set_type(co_sim, sim_type);
			}
			else {
				err("Invalid message");
			}

			tcore_at_tok_free(tokens);
		}
	}
}

/*
 * Operation - get_sim_type
 *
 * Request -
 * AT-Command: AT%SCCT?
 *
 * Response - sim_type (enum tel_sim_type)
 * Success: (Single line) -
 *	+SCCT: <state>
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static void __sim_get_sim_type(CoreObject *co_sim)
{
	TReturn ret;

	/* Send Request to modem */
	ret = tcore_prepare_and_send_at_request(co_sim,
		"AT\%SCCT?", "+SCCT:",
		TCORE_AT_SINGLELINE,
		NULL,
		__on_response_sim_get_sim_type, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]",  ret);
}

static void __sim_process_sim_status(CoreObject *co_sim,
	enum tel_sim_status sim_card_status)
{
	switch (sim_card_status) {
	case SIM_STATUS_INIT_COMPLETED: {
		TReturn ret;

		dbg("SIM INIT COMPLETED");

		SIM_READ_FILE(co_sim, NULL, NULL, SIM_EF_IMSI, ret);
		dbg("ret: [%d]", ret);
		SIM_READ_FILE(co_sim, NULL, NULL, SIM_EF_SPN, ret);
		dbg("ret: [%d]", ret);

		return;
	}

	case SIM_STATUS_INITIALIZING: {
		enum tel_sim_type sim_type;

		dbg("SIM INITIALIZING");

		sim_type = tcore_sim_get_type(co_sim);
		if (sim_type == SIM_TYPE_UNKNOWN) {
			/*
			 * SIM is initialized for first time, need to
			 * fetch SIM type
			 */
			dbg("Fetching SIM type");
			__sim_get_sim_type(co_sim);

			return;
		}
	}
	break;

	case SIM_STATUS_CARD_REMOVED:
	case SIM_STATUS_CARD_NOT_PRESENT:
	case SIM_STATUS_CARD_ERROR:
		dbg("SIM CARD ERROR [0x%02x]", sim_card_status);
		tcore_sim_set_type(co_sim, SIM_TYPE_UNKNOWN);
		return __sim_update_sim_status(co_sim, sim_card_status);
	break;

	default:
		err("SIM Status: [0x%02x]", sim_card_status);
	break;
	}
}

static const char *__sim_get_fac_from_lock_type(enum tel_sim_facility_type lock_type)
{
	char *fac = NULL;
	switch(lock_type) {
	case SIM_FACILITY_PS:
		fac = (char *)"PS";
	break;

	case SIM_FACILITY_SC:
		fac = (char *)"SC";
	break;

	case SIM_FACILITY_FD:
		fac = (char *)"FD";
	break;

	case SIM_FACILITY_PN:
		fac = (char *)"PN";
	break;

	case SIM_FACILITY_PU:
		fac = (char *)"PU";
	break;

	case SIM_FACILITY_PP:
		fac = (char *)"PP";
	break;

	case SIM_FACILITY_PC:
		fac = (char *)"PC";
	break;

	default:
		err("Unhandled sim lock type [%d]", lock_type);
	}

	return fac;
}

static void __sim_next_from_read_data(CoreObject *co_sim, UserRequest *ur,
	sim_meta_info_t *file_meta, enum tel_sim_access_result sim_result, gboolean decode_ret)
{
	enum tel_sim_type card_type = SIM_TYPE_UNKNOWN;

	dbg("Entry");

	dbg("[SIM]EF[0x%x] read sim_result[%d] Decode rt[%d]",
		file_meta->file_id, sim_result, decode_ret);
	switch (file_meta->file_id) {
	case SIM_EF_ELP:
	case SIM_EF_USIM_PL:
	case SIM_EF_LP:
	case SIM_EF_USIM_LI:
		if (decode_ret == TRUE) {
			dbg("Sending response");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();
		} else {
			card_type = tcore_sim_get_type(co_sim);
			/* 2G */
			/* The ME requests the Extended Language Preference.
			 * The ME only requests the Language Preference (EFLP)
			 * if at least one of the following conditions holds:
			 * -	EFELP is not available;
			 * -	EFELP does not contain an entry corresponding to
			 *	a language specified in ISO 639[30];
			 * -	the ME does not support any of the languages in EFELP.
			 */
			/* 3G */
			/*
			 * The ME only requests the Language Preference (EFPL)
			 * if at least one of the following conditions holds:
			 * -	if the EFLI has the value 'FFFF' in its highest
			 *	priority position
			 * -	if the ME does not support any of the language
			 * codes indicated in EFLI , or if EFLI is not present
			 */
			if (SIM_TYPE_GSM == card_type) {
				if (file_meta->file_id == SIM_EF_LP) {
					dbg("Sending response");

					file_meta->files.result = sim_result;
					tcore_user_request_send_response(ur,
						__find_resp_command(ur),
						sizeof(struct tresp_sim_read), &file_meta->files);

					/* TODO: Check if required */
					FREE_METAINFO();
				} else {
					file_meta->file_id = SIM_EF_LP;
					ur = tcore_user_request_ref(ur);
					__sim_get_response(co_sim, ur, file_meta);
				}
			} else if (SIM_TYPE_USIM) {
				if (file_meta->file_id == SIM_EF_LP
						|| file_meta->file_id == SIM_EF_USIM_LI) {
					file_meta->file_id = SIM_EF_ELP;
					ur = tcore_user_request_ref(ur);
					__sim_get_response(co_sim, ur, file_meta);
				} else {
					dbg("Sending response");

					file_meta->files.result = sim_result;
					tcore_user_request_send_response(ur,
						__find_resp_command(ur),
						sizeof(struct tresp_sim_read), &file_meta->files);

					/* TODO: Check if required */
					FREE_METAINFO();
				}
			}
		}
	break;

	case SIM_EF_ECC:
		card_type = tcore_sim_get_type(co_sim);
		if (SIM_TYPE_USIM == card_type) {
			if (file_meta->current_index == file_meta->rec_count) {
				dbg("Sending response");

				file_meta->files.result = sim_result;
				tcore_user_request_send_response(ur,
					__find_resp_command(ur),
					sizeof(struct tresp_sim_read), &file_meta->files);

				/* TODO: Check if required */
				FREE_METAINFO();
			} else {
				file_meta->current_index++;
				ur = tcore_user_request_ref(ur);
				__sim_read_record(co_sim, ur, file_meta);
			}
		} else if (SIM_TYPE_GSM == card_type) {
			dbg("Sending response");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();
		} else {
			dbg("[SIM DATA]Invalid CardType[%d] Unable to handle", card_type);
		}
	break;

	case SIM_EF_IMSI:
		__sim_update_sim_status(co_sim, SIM_STATUS_INIT_COMPLETED);
	break;

#if MSISDN_SUPPORTED
	case SIM_EF_MSISDN:
		if (file_meta->current_index == file_meta->rec_count) {
			dbg("Sending response");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();
		} else {
			file_meta->current_index++;
			ur = tcore_user_request_ref(ur);
			__sim_read_record(co_sim, ur, file_meta);
		}
	break;
#endif

	case SIM_EF_OPL:
		if (file_meta->current_index == file_meta->rec_count) {
			dbg("Sending response");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();
		} else {
			file_meta->current_index++;
			ur = tcore_user_request_ref(ur);
			__sim_read_record(co_sim, ur, file_meta);
		}
	break;

	case SIM_EF_PNN:
		if (file_meta->current_index == file_meta->rec_count) {
			dbg("Sending response");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();
		} else {
			file_meta->current_index++;
			ur = tcore_user_request_ref(ur);
			__sim_read_record(co_sim, ur, file_meta);
		}
	break;

	case SIM_EF_USIM_CFIS:
	case SIM_EF_USIM_MWIS:
	case SIM_EF_USIM_MBI:
	case SIM_EF_MBDN:
	case SIM_EF_CPHS_MAILBOX_NUMBERS:
	case SIM_EF_CPHS_INFORMATION_NUMBERS:
		if (file_meta->current_index == file_meta->rec_count) {
			dbg("Sending response");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();
		} else {
			file_meta->current_index++;
			ur = tcore_user_request_ref(ur);
			__sim_read_record(co_sim, ur, file_meta);
		}
	break;

	case SIM_EF_CPHS_OPERATOR_NAME_STRING:
	{
		file_meta->files.result = sim_result;
		if (decode_ret == TRUE && sim_result == SIM_ACCESS_SUCCESS) {
			memcpy(file_meta->files.data.cphs_net.full_name,
				file_meta->files.data.cphs_net.full_name,
				strlen((char *)file_meta->files.data.cphs_net.full_name));
		}

		file_meta->file_id = SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING;
		file_meta->file_result = SIM_ACCESS_FAILED;
		ur = tcore_user_request_ref(ur);
		__sim_get_response(co_sim, ur, file_meta);
	}
	break;

	case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
		if (sim_result == SIM_ACCESS_SUCCESS) {
			file_meta->files.result = SIM_ACCESS_SUCCESS;
		}

		dbg("Sending response");

		file_meta->files.result = sim_result;
		tcore_user_request_send_response(ur,
			__find_resp_command(ur),
			sizeof(struct tresp_sim_read), &file_meta->files);

		/* TODO: Check if required */
		FREE_METAINFO();
	break;

	case SIM_EF_ICCID:
		dbg("Sending response");

		file_meta->files.result = sim_result;
		tcore_user_request_send_response(ur,
			__find_resp_command(ur),
			sizeof(struct tresp_sim_read), &file_meta->files);

		/* TODO: Check if required */
		FREE_METAINFO();
	break;

	case SIM_EF_SST:
	case SIM_EF_SPN:
	case SIM_EF_SPDI:
	case SIM_EF_OPLMN_ACT:
	case SIM_EF_CPHS_CPHS_INFO:
	case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case SIM_EF_CPHS_VOICE_MSG_WAITING:
	case SIM_EF_CPHS_DYNAMICFLAGS:
	case SIM_EF_CPHS_DYNAMIC2FLAG:
	case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		dbg("Sending response");

		file_meta->files.result = sim_result;
		tcore_user_request_send_response(ur,
			__find_resp_command(ur),
			sizeof(struct tresp_sim_read), &file_meta->files);

		/* TODO: Check if required */
		FREE_METAINFO();
	break;

	default:
		err("File id not handled [0x%x]", file_meta->file_id);
	break;
	}
}

static void __sim_next_from_get_response(CoreObject *co_sim, UserRequest *ur,
	sim_meta_info_t *file_meta, enum tel_sim_access_result sim_result, gboolean decode_ret)
{
	enum tel_sim_type card_type = SIM_TYPE_UNKNOWN;

	dbg("EF[0x%x] access Result[%d]", file_meta->file_id, sim_result);

	file_meta->files.result = sim_result;
	memset(&file_meta->files.data, 0x00, sizeof(file_meta->files.data));

	if ((file_meta->file_id != SIM_EF_ELP
			&& file_meta->file_id != SIM_EF_LP
			&& file_meta->file_id != SIM_EF_USIM_PL
			&& file_meta->file_id != SIM_EF_CPHS_CPHS_INFO
			&& file_meta->file_id != SIM_EF_MSISDN
			&& file_meta->file_id != SIM_EF_ICCID)
			&& (sim_result != SIM_ACCESS_SUCCESS)) {
			dbg("Sending response");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();

		return;
	}

	switch (file_meta->file_id) {
	case SIM_EF_ELP: {
		if (sim_result == SIM_ACCESS_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			ur = tcore_user_request_ref(ur);
			__sim_read_binary(co_sim, ur, file_meta);
		} else {
			card_type = tcore_sim_get_type(co_sim);
			if (SIM_TYPE_GSM == card_type) {
				dbg("[SIM DATA]SIM_EF_ELP(2F05) access fail. Request SIM_EF_LP(0x6F05) info");

				/* The ME requests the Language Preference (EFLP) if EFELP is not available */
				file_meta->file_id = SIM_EF_LP;
				file_meta->file_result = SIM_ACCESS_FAILED;
				file_meta->req_command = TREQ_SIM_GET_LANGUAGE;

				ur = tcore_user_request_ref(ur);
				__sim_get_response(co_sim, ur, file_meta);
			} else if (SIM_TYPE_USIM == card_type) {
				dbg(" [SIM DATA]fail to get Language information "\
					"in USIM(EF-LI(6F05),EF-PL(2F05))");

				file_meta->files.result = sim_result;
				tcore_user_request_send_response(ur,
					__find_resp_command(ur),
					sizeof(struct tresp_sim_read), &file_meta->files);

				/* TODO: Check if required */
				FREE_METAINFO();
				return;
			}
		}
	}
	break;

	case SIM_EF_LP: {
		if (sim_result == SIM_ACCESS_SUCCESS) {
			dbg("[SIM DATA] exist EFLP/LI(0x6F05)");
			ur = tcore_user_request_ref(ur);
			__sim_read_binary(co_sim, ur, file_meta);
		} else {
			card_type = tcore_sim_get_type(co_sim);
			dbg("[SIM DATA]SIM_EF_LP/LI(6F05) access fail. Current CardType[%d]", card_type);
			if (SIM_TYPE_GSM == card_type) {
				dbg("Sending response");

				file_meta->files.result = sim_result;
				tcore_user_request_send_response(ur,
					__find_resp_command(ur),
					sizeof(struct tresp_sim_read), &file_meta->files);

				/* TODO: Check if required */
				FREE_METAINFO();
				return;
			}
			/*
			 * If EFLI is not present, then the language selection
			 * shall be as defined in EFPL at the MF level
			 */
			else if (SIM_TYPE_USIM == card_type) {
				dbg("[SIM DATA] try USIM EFPL(0x2F05)");

				file_meta->file_id = SIM_EF_ELP;
				file_meta->file_result = SIM_ACCESS_FAILED;
				file_meta->req_command = TREQ_SIM_GET_LANGUAGE;

				ur = tcore_user_request_ref(ur);
				__sim_get_response(co_sim, ur, file_meta);
			}
		}
	}
	break;

	case SIM_EF_USIM_PL: {
		if (sim_result == SIM_ACCESS_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			ur = tcore_user_request_ref(ur);
			__sim_read_binary(co_sim, ur, file_meta);
		} else {
			/*
			 * EFELIand EFPL not present, so set language count
			 * as zero and select ECC
			 */
			dbg("[SIM DATA]SIM_EF_USIM_PL(2A05) access fail. "\
				"Request SIM_EF_ECC(0x6FB7) info");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();

			return;
		}
	}
	break;

	case SIM_EF_ECC: {
		card_type = tcore_sim_get_type(co_sim);
		if (SIM_TYPE_GSM == card_type) {
			ur = tcore_user_request_ref(ur);
			__sim_read_binary(co_sim, ur, file_meta);
		} else if (SIM_TYPE_USIM == card_type) {
			if (file_meta->rec_count > SIM_ECC_RECORD_CNT_MAX)
				file_meta->rec_count = SIM_ECC_RECORD_CNT_MAX;

			file_meta->current_index++;
			ur = tcore_user_request_ref(ur);
			__sim_read_record(co_sim, ur, file_meta);
		} else {
			tcore_sim_set_ecc_list(co_sim, NULL);
			if (ur) {
				tcore_user_request_send_response(ur, __find_resp_command(ur),
					sizeof(struct tresp_sim_read), &file_meta->files);
			}
		}
	}
	break;

	case SIM_EF_ICCID: {
		if (sim_result == SIM_ACCESS_SUCCESS) {
			__sim_read_binary(co_sim, ur, file_meta);
		} else {
		/* Emulator does not support ICCID, thus need to send dummy ICCID for SDK ITC test */
			g_strlcpy(file_meta->files.data.iccid.iccid, SIM_ICCID, SIM_ICCID_LEN_MAX);
			file_meta->files.result = SIM_ACCESS_SUCCESS;
			if (tcore_user_request_ref_communicator(ur)) {	//external call
				 tcore_user_request_send_response(ur, __find_resp_command(ur),
							sizeof(struct tresp_sim_read), &file_meta->files);
			 }
		}
	}
	break;

	case SIM_EF_IMSI:
	case SIM_EF_SST:
	case SIM_EF_SPN:
	case SIM_EF_SPDI:
	case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case SIM_EF_CPHS_VOICE_MSG_WAITING:
	case SIM_EF_CPHS_OPERATOR_NAME_STRING:
	case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
	case SIM_EF_CPHS_DYNAMICFLAGS:
	case SIM_EF_CPHS_DYNAMIC2FLAG:
	case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		ur = tcore_user_request_ref(ur);
		__sim_read_binary(co_sim, ur, file_meta);
	break;

	case SIM_EF_CPHS_CPHS_INFO: {
		if (sim_result == SIM_ACCESS_SUCCESS) {
			tcore_sim_set_cphs_status(co_sim, TRUE);
			__sim_update_sim_status(co_sim, SIM_STATUS_INIT_COMPLETED);

			ur = tcore_user_request_ref(ur);
			__sim_read_binary(co_sim, ur, file_meta);
		} else {
			tcore_sim_set_cphs_status(co_sim, FALSE);
			__sim_update_sim_status(co_sim, SIM_STATUS_INIT_COMPLETED);

			dbg("Sending response");

			file_meta->files.result = sim_result;
			tcore_user_request_send_response(ur,
				__find_resp_command(ur),
				sizeof(struct tresp_sim_read), &file_meta->files);

			/* TODO: Check if required */
			FREE_METAINFO();
		}
	}
	break;


	case SIM_EF_USIM_CFIS: {
		if (file_meta->rec_count > SIM_CF_RECORD_CNT_MAX)
			file_meta->rec_count = SIM_CF_RECORD_CNT_MAX;

		file_meta->current_index++;
		ur = tcore_user_request_ref(ur);
		__sim_read_record(co_sim, ur, file_meta);
	}
	break;

	case SIM_EF_MSISDN: {
		if (sim_result == SIM_ACCESS_SUCCESS) {
			__sim_read_record(co_sim, ur, file_meta);
		} else {
		/* Emulator does not support MSISDN, thus need to send MSISDN count as ZERO for SDK ITC test */
			file_meta->files.data.msisdn_list.count = 0;
			file_meta->files.result = SIM_ACCESS_SUCCESS;
			if (tcore_user_request_ref_communicator(ur)) {	//external call
				 tcore_user_request_send_response(ur, __find_resp_command(ur),
							sizeof(struct tresp_sim_read), &file_meta->files);
			 }
		}
	}
	break;
	case SIM_EF_OPL:
	case SIM_EF_PNN:
	case SIM_EF_USIM_MWIS:
	case SIM_EF_USIM_MBI:
	case SIM_EF_MBDN:
	case SIM_EF_CPHS_MAILBOX_NUMBERS:
	case SIM_EF_CPHS_INFORMATION_NUMBERS:
		file_meta->current_index++;
		ur = tcore_user_request_ref(ur);
		__sim_read_record(co_sim, ur, file_meta);
	break;
#if 0
	case SIM_SST_SMS_PARAMS: {
		sim_private_info_t *priv_info = NULL;

		priv_info = tcore_sim_ref_userdata(co_sim);

		dbg("SMSP info set to tcore : count:[%d], rec_len:[%d]",
			file_meta->rec_count, file_meta->rec_length);
		priv_info->smsp_count = file_meta->rec_count;
		priv_info->smsp_rec_len = file_meta->rec_length;
	}
	break;
#endif
	default:
		dbg("error - File id for get file info [0x%x]", file_meta->file_id);
	break;
	}
	return;
}

static void __on_response_sim_read_data(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *co_sim = NULL;
	GSList *tokens = NULL;
	enum tel_sim_access_result sim_result;
	gboolean dr = FALSE;
	const char *line = NULL;
	char *res = NULL;
	char *tmp = NULL;
	guint res_len;
	int sw1 = 0;
	int sw2 = 0;
	enum tel_sim_type card_type = SIM_TYPE_UNKNOWN;
	sim_meta_info_t *file_meta = (sim_meta_info_t *)user_data;
	UserRequest *ur;

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 2) {
				err("Invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));
		res = g_slist_nth_data(tokens, 2);

		tmp = tcore_at_tok_extract(res);
		__util_hexstring_to_bytes(tmp, &res, &res_len);
		dbg("Response: [%s] Response length: [%d]", res, res_len);

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			sim_result = SIM_ACCESS_SUCCESS;
			file_meta->files.result = sim_result;

			dbg("File ID: [0x%x]", file_meta->file_id);
			switch (file_meta->file_id) {
			case SIM_EF_IMSI: {
				dbg("Data: [%s]", res);
				dr = tcore_sim_decode_imsi(&file_meta->imsi,
					(unsigned char *)res, res_len);
				if (dr == FALSE) {
					err("IMSI decoding failed");
				} else {
					//__sim_set_identity(co_sim, &file_meta->imsi);

					/* Update IMSI */
					tcore_sim_set_imsi(co_sim, &file_meta->imsi);
				}
			}
			break;

			case SIM_EF_ICCID: {
				dr = tcore_sim_decode_iccid(&file_meta->files.data.iccid,
					(unsigned char *)res, res_len);
			}
			break;

			case SIM_EF_ELP:		/* 2G EF - 2 bytes decoding */
			case SIM_EF_USIM_LI:	/* 3G EF - 2 bytes decoding */
			case SIM_EF_USIM_PL:	/* 3G EF - same as EFELP, so 2 byte decoding */
			case SIM_EF_LP: 		/* 1 byte encoding */
			{
				card_type = tcore_sim_get_type(co_sim);
				if ((SIM_TYPE_GSM == card_type)
						&& (file_meta->file_id == SIM_EF_LP)) {
					/*
					 * 2G LP(0x6F05) has 1 byte for each language
					 */
					dr = tcore_sim_decode_lp(&file_meta->files.data.language,
						(unsigned char *)res, res_len);
				} else {
					/*
					 * 3G LI(0x6F05)/PL(0x2F05),
					 * 2G ELP(0x2F05) has 2 bytes for each language
					 */
					dr = tcore_sim_decode_li(file_meta->file_id, &file_meta->files.data.language,
						(unsigned char *)res, res_len);
				}
			}
			break;

			case SIM_EF_SPN:
				dr = tcore_sim_decode_spn(&file_meta->files.data.spn,
					(unsigned char *)res, res_len);
				tcore_sim_set_spn(co_sim, &file_meta->files.data.spn);
				dbg("SIM SPN: [%s]", file_meta->files.data.spn.spn);
			break;

			case SIM_EF_SPDI:
				dr = tcore_sim_decode_spdi(&file_meta->files.data.spdi,
					(unsigned char *)res, res_len);
			break;

			case SIM_EF_SST: {
				struct tel_sim_service_table *svct = NULL;

				card_type = tcore_sim_get_type(co_sim);
				file_meta->files.data.svct.sim_type = card_type;
				if (SIM_TYPE_GSM == card_type) {
					dr = tcore_sim_decode_sst(&file_meta->files.data.svct.table.sst,
						(unsigned char *)res, res_len);
				} else if (SIM_TYPE_USIM == card_type) {
					dr = tcore_sim_decode_ust(&file_meta->files.data.svct.table.ust,
						(unsigned char *)res, res_len);
				} else {
					err("Not handled card_type[%d]", card_type);
				}

				if (dr == FALSE) {
					err("SST decoding failed");
				} else {
					tcore_sim_set_service_table(co_sim, svct);
				}

				/* Free memory */
				g_free(svct);
			}
			break;

			case SIM_EF_ECC: {
				card_type = tcore_sim_get_type(co_sim);
				if (SIM_TYPE_GSM == card_type) {
					dr = tcore_sim_decode_ecc(&file_meta->files.data.ecc,
						(unsigned char *)res, res_len);
				} else if (SIM_TYPE_USIM == card_type) {
					struct tel_sim_ecc *ecc = NULL;

					ecc = g_try_new0(struct tel_sim_ecc, 1);
					dbg("Index [%d]", file_meta->current_index);

					dr = tcore_sim_decode_uecc(ecc, (unsigned char *)res, res_len);
					if (dr == TRUE) {
						memcpy(&file_meta->files.data.ecc.ecc[file_meta->files.data.ecc.ecc_count],
							ecc, sizeof(struct tel_sim_ecc));
						file_meta->files.data.ecc.ecc_count++;
					}

					/* Free memory */
					g_free(ecc);
				} else {
					dbg("Unknown/Unsupported SIM card Type: [%d]", card_type);
				}
			}
			break;

			case SIM_EF_MSISDN: {
				struct tel_sim_msisdn *msisdn = NULL;

				dbg("Index [%d]", file_meta->current_index);
				msisdn = g_try_new0(struct tel_sim_msisdn, 1);
				dr = tcore_sim_decode_msisdn(msisdn, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.msisdn_list.msisdn[file_meta->files.data.msisdn_list.count],
						msisdn, sizeof(struct tel_sim_msisdn));

					file_meta->files.data.msisdn_list.count++;
				}

				/* Free memory */
				g_free(msisdn);
			}
			break;

			case SIM_EF_OPL: {
				struct tel_sim_opl *opl = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				opl = g_try_new0(struct tel_sim_opl, 1);

				dr = tcore_sim_decode_opl(opl, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.opl.list[file_meta->files.data.opl.opl_count],
							opl, sizeof(struct tel_sim_opl));

					file_meta->files.data.opl.opl_count++;
				}

				/* Free memory */
				g_free(opl);
			}
			break;

			case SIM_EF_PNN: {
				struct tel_sim_pnn *pnn = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				pnn = g_try_new0(struct tel_sim_pnn, 1);

				dr = tcore_sim_decode_pnn(pnn, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.pnn.list[file_meta->files.data.pnn.pnn_count],
						pnn, sizeof(struct tel_sim_pnn));

					file_meta->files.data.pnn.pnn_count++;
				}

				/* Free memory */
				g_free(pnn);
			}
			break;

			case SIM_EF_OPLMN_ACT:
				/*dr = tcore_sim_decode_oplmnwact(&file_meta->files.data.opwa,
					(unsigned char *)res, res_len);*/
			break;

			case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
				/*dr = tcore_sim_decode_csp(&po->p_cphs->csp,
					p_data->response, p_data->response_len);*/
			break;

			case SIM_EF_USIM_MBI: {	/* linear type */
				struct tel_sim_mbi *mbi = NULL;

				mbi = g_try_new0(struct tel_sim_mbi, 1);
				dr = tcore_sim_decode_mbi(mbi, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->mbi_list.mbi[file_meta->mbi_list.profile_count],
						mbi, sizeof(struct tel_sim_mbi));
					file_meta->mbi_list.profile_count++;

					dbg("mbi count[%d]", file_meta->mbi_list.profile_count);
				}

				/* Free memory */
				g_free(mbi);
			}
			break;

			case SIM_EF_CPHS_MAILBOX_NUMBERS:	/* linear type */
			case SIM_EF_MBDN:			/* linear type */
#if 0	/* Temporarily blocked, MBDN is NOT suported in Emulator */
				dr = tcore_sim_decode_xdn((unsigned char *)res, res_len,
					file_meta->mb_list[file_meta->current_index-1].alpha_id,
					file_meta->mb_list[file_meta->current_index-1].number);
				file_meta->mb_list[file_meta->current_index-1].alpha_id_len =
					strlen(file_meta->mb_list[file_meta->current_index-1].alpha_id);
				file_meta->mb_list[file_meta->current_index-1].profile_id =
					file_meta->current_index;
#endif	/* Temporarily blocked, MBDN is NOT suported in Emulator */
			break;

			case SIM_EF_CPHS_VOICE_MSG_WAITING:	/* transparent type */
				dr = tcore_sim_decode_vmwf(&file_meta->files.data.mw.cphs_mw,
					(unsigned char *)res, res_len);
			break;

			case SIM_EF_USIM_MWIS: {	/* linear type */
				struct tel_sim_mw *mw = NULL;

				mw = g_try_new0(struct tel_sim_mw, 1);

				dr = tcore_sim_decode_mwis(mw, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.mw.mw_list.mw[file_meta->files.data.mw.mw_list.profile_count],
						mw, sizeof(struct tel_sim_mw));
					file_meta->files.data.mw.mw_list.profile_count++;
				}

				/* Free memory */
				g_free(mw);
			}
			break;

			case SIM_EF_CPHS_CALL_FORWARD_FLAGS:	/* transparent type */
				dr = tcore_sim_decode_cff(&file_meta->files.data.cf.cphs_cf,
					(unsigned char *)res, res_len);
			break;

			case SIM_EF_USIM_CFIS: {	/* linear type */
				struct tel_sim_cfis *cf = NULL;

				cf = g_try_new0(struct tel_sim_cfis, 1);
				dr = tcore_sim_decode_cfis(cf, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.cf.cf_list.cf[file_meta->files.data.cf.cf_list.profile_count],
						cf, sizeof(struct tel_sim_cfis));

					file_meta->files.data.cf.cf_list.profile_count++;
				}

				/* Free memory */
				g_free(cf);
			}
			break;

			case SIM_EF_CPHS_SERVICE_STRING_TABLE:
				dbg("not handled - SIM_EF_CPHS_SERVICE_STRING_TABLE ");
			break;

			case SIM_EF_CPHS_OPERATOR_NAME_STRING:
				dr = tcore_sim_decode_ons((unsigned char*)&file_meta->files.data.cphs_net.full_name,
					(unsigned char *)res, res_len);
				dbg("file_meta->files.result[%d],file_meta->files.data.cphs_net.full_name[%s]",
					file_meta->files.result, file_meta->files.data.cphs_net.full_name);
			break;

			case SIM_EF_CPHS_DYNAMICFLAGS:
				/*dr = tcore_sim_decode_dynamic_flag(&po->p_cphs->dflagsinfo,
					p_data->response, p_data->response_len);*/
			break;

			case SIM_EF_CPHS_DYNAMIC2FLAG:
				/*dr = tcore_sim_decode_dynamic2_flag(&po->p_cphs->d2flagsinfo, p_data->response,
					p_data->response_len);*/
			break;

			case SIM_EF_CPHS_CPHS_INFO:
				/*dr = tcore_sim_decode_cphs_info(&file_meta->files.data.cphs,
					(unsigned char *)res, res_len);*/
			break;

			case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
				dr = tcore_sim_decode_short_ons((unsigned char*)&file_meta->files.data.cphs_net.short_name,
					(unsigned char *)res, res_len);
				dbg("file_meta->files.result[%d],file_meta->files.data.cphs_net.short_name[%s]",
					file_meta->files.result, file_meta->files.data.cphs_net.short_name);
			break;

			case SIM_EF_CPHS_INFORMATION_NUMBERS:
				/*dr = tcore_sim_decode_information_number(&po->p_cphs->infn,
					p_data->response, p_data->response_len);*/
			break;

			default:
				dbg("File Decoding Failed - not handled File[0x%x]", file_meta->file_id);
				dr = 0;
			break;
			}
		} else {
			sim_result = __sim_decode_status_word(sw1, sw2);
			file_meta->files.result = sim_result;
		}

		/* Free memory */
		g_free(tmp);
		g_free(res);

		/* Free tokens */
		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");
		dbg("Error - File ID: [0x%x]", file_meta->file_id);
		sim_result = SIM_ACCESS_FAILED;
	}

	/* Get File data */
	__sim_next_from_read_data(tcore_pending_ref_core_object(p), ur,
		file_meta, sim_result, dr);

	dbg("Exit");
}

static void __on_response_sim_get_response(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *co_sim = NULL;
	enum tel_sim_access_result sim_result;
	GSList *tokens = NULL;
	const char *line = NULL;
	int sw1 = 0;
	int sw2 = 0;
	sim_meta_info_t *file_meta = (sim_meta_info_t *)user_data;
	UserRequest *ur;

	dbg("SIM Response - SIM File info: [+CRSM]");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 2) {
				err("Invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));

		/*1. SIM access success case*/
		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			unsigned char tag_len = 0;
			unsigned short record_len = 0;
			char num_of_records = 0;
			unsigned char file_id_len = 0;
			unsigned short file_id = 0;
			unsigned short file_size = 0;
			unsigned short file_type = 0;
			unsigned short arr_file_id = 0;
			int arr_file_id_rec_num = 0;
			enum tel_sim_type card_type = SIM_TYPE_UNKNOWN;

			/* handling only last 3 bits */
			unsigned char file_type_tag = 0x07;
			unsigned char *ptr_data;

			char *hexData;
			char *tmp;
			char *record_data = NULL;
			guint record_data_len;
			hexData = g_slist_nth_data(tokens, 2);
			dbg("hexData: %s", hexData);
			dbg("hexData: %s", hexData + 1);

			tmp = tcore_at_tok_extract(hexData);
			__util_hexstring_to_bytes(tmp, &record_data, &record_data_len);
			tcore_util_hex_dump("   ", record_data_len, record_data);
			g_free(tmp);

			ptr_data = (unsigned char *)record_data;
			card_type = tcore_sim_get_type(co_sim);
			if (SIM_TYPE_USIM == card_type) {
				/*
				 * ETSI TS 102 221 v7.9.0
				 * - Response Data
				 * '62'	FCP template tag
				 *
				 * - Response for an EF
				 * '82' M	File Descriptor
				 * '83' M	File Identifier
				 * 'A5' O	Proprietary information
				 * '8A' M	Life Cycle Status Integer
				 * '8B', '8C' or 'AB' C1 Security attributes
				 * '80' M	File size
				 * '81' O	Total file size
				 * '88' O	Short File Identifier (SFI)
				 */

				/* rsim.res_len has complete data length received */

				/* FCP template tag - File Control Parameters tag*/
				if (*ptr_data == 0x62) {
					/* parse complete FCP tag*/
					/* increment to next byte */
					ptr_data++;
					tag_len = *ptr_data++;
					dbg("tag_len: %02x", tag_len);
					/* FCP file descriptor - file type, accessibility, DF, ADF etc*/
					if (*ptr_data == 0x82) {
						/* increment to next byte */
						ptr_data++;
						/* 2 or 5 value*/
						ptr_data++;
						/* consider only last 3 bits*/
						dbg("file_type_tag: %02x", file_type_tag);
						file_type_tag = file_type_tag & (*ptr_data);
						dbg("file_type_tag: %02x", file_type_tag);

						switch (file_type_tag) {
						/* increment to next byte */
						// ptr_data++;
						case 0x1:
							dbg("Getting FileType: [Transparent file type]");
							file_type = SIM_FILE_TYPE_TRANSPARENT;

							/* increment to next byte */
							ptr_data++;
							/* increment to next byte */
							ptr_data++;
						break;

						case 0x2:
							dbg("Getting FileType: [Linear fixed file type]");
							/* increment to next byte */
							ptr_data++;
							/* data coding byte - value 21 */
							ptr_data++;
							/* 2bytes */
							memcpy(&record_len, ptr_data, 2);
							/* swap bytes */
							SWAP_BYTES_16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							/* Data lossy conversation from enum (int) to unsigned char */
							file_type = SIM_FILE_TYPE_LINEAR_FIXED;
						break;

						case 0x6:
							dbg("Cyclic fixed file type");
							/* increment to next byte */
							ptr_data++;
							/* data coding byte - value 21 */
							ptr_data++;
							/* 2bytes */
							memcpy(&record_len, ptr_data, 2);
							/* swap bytes */
							SWAP_BYTES_16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							file_type = SIM_FILE_TYPE_CYCLIC;
						break;

						default:
							dbg("not handled file type [0x%x]", *ptr_data);
						break;
						}
					} else {
						dbg("INVALID FCP received - DEbug!");
						tcore_at_tok_free(tokens);
						g_free(record_data);
						return;
					}

					/*File identifier - 0x84,0x85,0x86 etc are currently ignored and not handled */
					if (*ptr_data == 0x83) {
						/* increment to next byte */
						ptr_data++;
						file_id_len = *ptr_data++;
						dbg("file_id_len: %02x", file_id_len);

						memcpy(&file_id, ptr_data, file_id_len);
						dbg("file_id: %x", file_id);

						/* swap bytes	 */
						SWAP_BYTES_16(file_id);
						dbg("file_id: %x", file_id);

						ptr_data = ptr_data + 2;
						dbg("Getting FileID=[0x%x]", file_id);
					} else {
						dbg("INVALID FCP received - DEbug!");
						tcore_at_tok_free(tokens);
						g_free(record_data);
						return;
					}

					/* proprietary information */
					if (*ptr_data == 0xA5) {
						unsigned short prop_len;
						/* increment to next byte */
						ptr_data++;

						/* length */
						prop_len = *ptr_data;
						dbg("prop_len: %02x", prop_len);

						/* skip data */
						ptr_data = ptr_data + prop_len + 1;
					} else {
						dbg("INVALID FCP received - DEbug!");
					}

					/* life cycle status integer [8A][length:0x01][status]*/
					/*
					 status info b8~b1
					 00000000 : No information given
					 00000001 : creation state
					 00000011 : initialization state
					 000001-1 : operation state -activated
					 000001-0 : operation state -deactivated
					 000011-- : Termination state
					 b8~b5 !=0, b4~b1=X : Proprietary
					 Any other value : RFU
					 */
					if (*ptr_data == 0x8A) {
						/* increment to next byte */
						ptr_data++;
						/* length - value 1 */
						ptr_data++;

						switch (*ptr_data) {
						case 0x04:
						case 0x06:
							dbg("<RX> operation state -deactivated");
							ptr_data++;
						break;

						case 0x05:
						case 0x07:
							dbg("<RX> operation state -activated");
							ptr_data++;
						break;

						default:
							dbg("<RX> DEBUG! LIFE CYCLE STATUS =[0x%x]", *ptr_data);
							ptr_data++;
						break;
						}
					}

					/* related to security attributes : currently not handled*/
					if (*ptr_data == 0x86 || *ptr_data == 0x8B || *ptr_data == 0x8C || *ptr_data == 0xAB) {
						/* increment to next byte */
						ptr_data++;
						/* if tag length is 3 */
						if (*ptr_data == 0x03) {
							/* increment to next byte */
							ptr_data++;
							/* EFARR file id */
							memcpy(&arr_file_id, ptr_data, 2);
							/* swap byes */
							SWAP_BYTES_16(arr_file_id);
							ptr_data = ptr_data + 2;
							arr_file_id_rec_num = *ptr_data++;
							dbg("arr_file_id_rec_num:[%d]", arr_file_id_rec_num);
						} else {
							/* if tag length is not 3 */
							/* ignoring bytes	*/
							// ptr_data = ptr_data + 4;
							dbg("Useless security attributes, so jump to next tag");
							ptr_data = ptr_data + (*ptr_data + 1);
						}
					} else {
						dbg("INVALID FCP received[0x%x] - DEbug!", *ptr_data);
						tcore_at_tok_free(tokens);
						g_free(record_data);
						return;
					}

					dbg("Current ptr_data value is [%x]", *ptr_data);

					/* file size excluding structural info*/
					if (*ptr_data == 0x80) {
						/* for EF file size is body of file and for Linear or cyclic it is
						 * number of recXsizeof(one record)
						 */
						/* increment to next byte */
						ptr_data++;
						/* length is 1 byte - value is 2 bytes or more */
						ptr_data++;
						memcpy(&file_size, ptr_data, 2);
						/* swap bytes */
						SWAP_BYTES_16(file_size);
						ptr_data = ptr_data + 2;
					} else {
						dbg("INVALID FCP received - DEbug!");
						tcore_at_tok_free(tokens);
						g_free(record_data);
						return;
					}

					/* total file size including structural info*/
					if (*ptr_data == 0x81) {
						int len;
						/* increment to next byte */
						ptr_data++;
						/* length */
						len = *ptr_data;
						dbg("len:[%d]", len);
						/* ignored bytes */
						ptr_data = ptr_data + 3;
					} else {
						dbg("INVALID FCP received - DEbug!");
						/* 0x81 is optional tag?? check out! so do not return -1 from here! */
					}
					/*short file identifier ignored*/
					if (*ptr_data == 0x88) {
						dbg("0x88: Do Nothing");
						/*DO NOTHING*/
					}
				} else {
					dbg("INVALID FCP received - DEbug!");
					tcore_at_tok_free(tokens);
					g_free(record_data);
					return;
				}
			} else if (SIM_TYPE_GSM == card_type) {
				unsigned char gsm_specific_file_data_len = 0;
				/* ignore RFU byte1 and byte2 */
				ptr_data++;
				ptr_data++;
				/* file size */
				// file_size = p_info->response_len;
				memcpy(&file_size, ptr_data, 2);
				/* swap bytes */
				SWAP_BYTES_16(file_size);
				/* parsed file size */
				ptr_data = ptr_data + 2;
				/* file id */
				memcpy(&file_id, ptr_data, 2);
				SWAP_BYTES_16(file_id);
				dbg("FILE id --> [%x]", file_id);
				ptr_data = ptr_data + 2;
				/* save file type - transparent, linear fixed or cyclic */
				file_type_tag = (*(ptr_data + 7));

				switch (*ptr_data) {
				case 0x0:
					/* RFU file type */
					dbg("RFU file type- not handled - Debug!");
				break;

				case 0x1:
					/* MF file type */
					dbg("MF file type - not handled - Debug!");
					break;

				case 0x2:
					/* DF file type */
					dbg("DF file type - not handled - Debug!");
				break;

				case 0x4:
					/* EF file type */
					dbg("EF file type [%d] ", file_type_tag);
					/*	increment to next byte */
					ptr_data++;

					if (file_type_tag == 0x00 || file_type_tag == 0x01) {
						/* increament to next byte as this byte is RFU */
						ptr_data++;
						file_type =
							(file_type_tag == 0x00) ? SIM_FILE_TYPE_TRANSPARENT : SIM_FILE_TYPE_LINEAR_FIXED;
					} else {
						/* increment to next byte */
						ptr_data++;
						/* For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
						/* the INCREASE command is allowed on the selected cyclic file. */
						file_type = SIM_FILE_TYPE_CYCLIC;
					}
					/* bytes 9 to 11 give SIM file access conditions */
					ptr_data++;
					/* byte 10 has one nibble that is RF U and another for INCREASE which is not used currently */
					ptr_data++;
					/* byte 11 is invalidate and rehabilate nibbles */
					ptr_data++;
					/* byte 12 - file status */
					ptr_data++;
					/* byte 13 - GSM specific data */
					gsm_specific_file_data_len = *ptr_data;
					dbg("gsm_specific_file_data_len:[%d]", gsm_specific_file_data_len);
					ptr_data++;
					/* byte 14 - structure of EF - transparent or linear or cyclic , already saved above */
					ptr_data++;
					/* byte 15 - length of record for linear and cyclic , for transparent it is set to 0x00. */
					record_len = *ptr_data;
					dbg("record length[%d], file size[%d]", record_len, file_size);
					if (record_len != 0)
						num_of_records = (file_size / record_len);

					dbg("Number of records [%d]", num_of_records);
				break;

				default:
					dbg("not handled file type");
				break;
				}
			} else {
				err("Unknown Card Type - [%d]", card_type);
			}

			dbg("req ef[0x%x] resp ef[0x%x] size[%ld] Type[0x%x] "\
				"NumOfRecords[%ld] RecordLen[%ld]",
				file_meta->file_id, file_id, file_size,
				file_type, num_of_records, record_len);

			file_meta->file_type = file_type;
			file_meta->data_size = file_size;
			file_meta->rec_length = record_len;
			file_meta->rec_count = num_of_records;
			file_meta->current_index = 0;		/* reset for new record type EF */
			sim_result = SIM_ACCESS_SUCCESS;
			g_free(record_data);
		} else {
			/*2. SIM access fail case*/
			err("Failed to get ef[0x%x] (file_meta->file_id) ", file_meta->file_id);
			sim_result = __sim_decode_status_word(sw1, sw2);
		}

		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");
		err("Failed to get ef[0x%x] (file_meta->file_id)",
			file_meta->file_id);
		sim_result = SIM_ACCESS_FAILED;
	}

	dbg("Calling __sim_next_from_get_response");
	__sim_next_from_get_response(co_sim, ur, file_meta, sim_result, FALSE);
	dbg("Exit");
}

static void __sim_read_record(CoreObject *co_sim, UserRequest *ur, sim_meta_info_t *file_meta)
{
	gchar *at_cmd = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d",
		SIM_ACCESS_READ_RECORD, file_meta->file_id);

	ret = tcore_prepare_and_send_at_request(co_sim,
		at_cmd, "+CRSM:",
		TCORE_AT_SINGLELINE,
		ur,
		__on_response_sim_read_data, file_meta,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);

	dbg("Exit");
}

static void __sim_read_binary(CoreObject *co_sim, UserRequest *ur, sim_meta_info_t *file_meta)
{
	gchar *at_cmd = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;
	int offset = 0;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	/*
	 * According to TS 102 221, values of P1, P2, P3 can be as below:
	 * 11.1.3 READ BINARY
	 *	P1: See table 11.10
	 *	P2: Offset low
	 *	Lc: Not present
	 *	Data: Not present
	 *	Le: Number of bytes to be read (P3)
	 */
	p1 = (unsigned char) (offset & 0xFF00) >> 8;
	p2 = (unsigned char) offset & 0x00FF;			/* offset low */
	p3 = (unsigned char) file_meta->data_size;

	if ((file_meta->file_id == SIM_EF_SPN)
			|| (file_meta->file_id == SIM_EF_IMSI)
			|| (file_meta->file_id == SIM_EF_LP)
			|| (file_meta->file_id == SIM_EF_SST))
		at_cmd = g_strdup_printf("AT+CRSM=%d, %d",
				SIM_ACCESS_READ_BINARY, file_meta->file_id);
	else
		at_cmd = g_strdup_printf("AT+CRSM=%d, %d, %d, %d, %d",
				SIM_ACCESS_READ_BINARY, file_meta->file_id, p1, p2, p3);

	ret = tcore_prepare_and_send_at_request(co_sim,
		at_cmd, "+CRSM:",
		TCORE_AT_SINGLELINE,
		ur,
		__on_response_sim_read_data, file_meta,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);

	dbg("Exit");
}

static TReturn __sim_get_response(CoreObject *co_sim, UserRequest *ur, sim_meta_info_t *file_meta)
{
	gchar *at_cmd = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d",
		SIM_ACCESS_GET_RESPONSE, file_meta->file_id);

	ret = tcore_prepare_and_send_at_request(co_sim,
		at_cmd, "+CRSM:",
		TCORE_AT_SINGLELINE,
		ur,
		__on_response_sim_get_response, file_meta,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(at_cmd);

	return ret;
}

#if 0	/* To be used later */
static int __sim_get_lock_type(sim_sec_op_t sec_op)
{
	switch(sec_op) {
		case SIM_CURR_SEC_OP_SIM_DISABLE :
		case SIM_CURR_SEC_OP_SIM_ENABLE :
		case SIM_CURR_SEC_OP_SIM_STATUS :
			return SIM_FACILITY_PS;
		case SIM_CURR_SEC_OP_PIN1_DISABLE :
		case SIM_CURR_SEC_OP_PIN1_ENABLE :
		case SIM_CURR_SEC_OP_PIN1_STATUS :
			return SIM_FACILITY_SC;
		case SIM_CURR_SEC_OP_FDN_DISABLE :
		case SIM_CURR_SEC_OP_FDN_ENABLE :
		case SIM_CURR_SEC_OP_FDN_STATUS :
			return SIM_FACILITY_FD;
		case SIM_CURR_SEC_OP_NET_DISABLE :
		case SIM_CURR_SEC_OP_NET_ENABLE :
		case SIM_CURR_SEC_OP_NET_STATUS :
			return SIM_FACILITY_PN;
		case SIM_CURR_SEC_OP_NS_DISABLE :
		case SIM_CURR_SEC_OP_NS_ENABLE :
		case SIM_CURR_SEC_OP_NS_STATUS :
			return SIM_FACILITY_PU;
		case SIM_CURR_SEC_OP_SP_DISABLE :
		case SIM_CURR_SEC_OP_SP_ENABLE :
		case SIM_CURR_SEC_OP_SP_STATUS :
			return SIM_FACILITY_PP;
		case SIM_CURR_SEC_OP_CP_DISABLE :
		case SIM_CURR_SEC_OP_CP_ENABLE :
		case SIM_CURR_SEC_OP_CP_STATUS :
			return SIM_FACILITY_PC ;
		default :
			err("Invalid sec op [%d]", sec_op);
			return -1;
	}
}
#endif

/* Notifications */
/*
 * Notification: +SCSIM: <SIM state>
 *
 * Possible values of <SIM state> can be
 * 0	SIM not present
 * 1	PIN verification needed
 * 2	PIN verification not needed - Ready
 * 3	PIN verified - Ready
 * 4	PUK verification needed
 * 5	SIM permanently blocked
 * 6	SIM Error
 * 7	ready for attach (+COPS)
 * 8	SIM Technical Problem
 * 9	SIM Removed
 * 10	SIM Reactivating
 * 11	SIM Reactivated
 * 12	SIM SMS Caching Completed. (Sent only when SMS caching enabled)
 * 99	SIM State Unknown
 */
static gboolean on_notification_sim_status(CoreObject *co_sim,
	const void *event_info, void *user_data)
{
	GSList *lines = (GSList *)event_info;
	const gchar *line = (const gchar *)lines->data;
	enum tel_sim_status sim_status = SIM_STATUS_INITIALIZING;
	sim_sec_lock_type_t locktype = SEC_LOCK_TYPE_NONE;
	sim_sec_lock_key_t lockkey = SEC_LOCK_KEY_NONE;

	if (__convert_scpin_str_to_enum((char *)line, &locktype, &lockkey) == FALSE)
		return TRUE;

	switch (locktype) {
	case SEC_LOCK_TYPE_READY:
		if (lockkey == SEC_LOCK_KEY_UNLOCKED)
			sim_status = SIM_STATUS_INITIALIZING;
		else
			sim_status = SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_PS:
		sim_status = SIM_STATUS_LOCK_REQUIRED;
	break;

	case SEC_LOCK_TYPE_PF:
		sim_status = SIM_STATUS_CARD_ERROR;
	break;

	case SEC_LOCK_TYPE_SC:
		switch (lockkey) {
		case SEC_LOCK_KEY_UNLOCKED:
		break;

		case SEC_LOCK_KEY_PIN:
			sim_status = SIM_STATUS_PIN_REQUIRED;
		break;

		case SEC_LOCK_KEY_PUK:
			sim_status = SIM_STATUS_PUK_REQUIRED;
		break;

		case SEC_LOCK_KEY_PERM_BLOCKED:
			sim_status = SIM_STATUS_CARD_BLOCKED;
		break;

		default:
			err("Not handled SEC Lock key: [%d]", lockkey);
			sim_status = SIM_STATUS_UNKNOWN;
		break;
		}
	break;

	case SEC_LOCK_TYPE_FD:
		break;

	case SEC_LOCK_TYPE_PN:
		if (SEC_LOCK_KEY_PIN)
			sim_status = SIM_STATUS_NCK_REQUIRED;
		else
			sim_status = SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_PU:
		if (SEC_LOCK_KEY_PIN)
			sim_status = SIM_STATUS_NSCK_REQUIRED;
		else
			sim_status = SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_PP:
		if (SEC_LOCK_KEY_PIN)
			sim_status = SIM_STATUS_SPCK_REQUIRED;
		else
			sim_status = SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_PC:
		if (SEC_LOCK_KEY_PIN)
			sim_status = SIM_STATUS_CCK_REQUIRED;
		else
			sim_status = SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_SC2:
	case SEC_LOCK_TYPE_PUK2:
	break;

	case SEC_LOCK_TYPE_NO_SIM:
		sim_status = SIM_STATUS_CARD_NOT_PRESENT;
	break;

	case SEC_LOCK_TYPE_UNAVAIL:
	case SEC_SIM_INIT_CRASH:
		sim_status = SIM_STATUS_CARD_ERROR;
	break;

	case SEC_SIM_INIT_COMPLETED:
		sim_status = SIM_STATUS_INIT_COMPLETED;
	break;

	case SEC_PB_INIT_COMPLETED:
	break;

	default:
		err("Not handled SEC lock type: [%d]", locktype);
		sim_status = SIM_STATUS_UNKNOWN;
	break;
	}

	__sim_process_sim_status(co_sim, sim_status);

	return TRUE;
}

/* Response Functions */
static void on_response_sim_verify_pins(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	CoreObject *co_sim;
	UserRequest *ur;
	struct treq_sim_verify_pins *verify_pin_req;
	struct tresp_sim_verify_pins verify_pin_resp;

	dbg("Entry");

	memset(&verify_pin_resp, 0x0, sizeof(struct tresp_sim_verify_pins));

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	verify_pin_req = (struct treq_sim_verify_pins *)tcore_user_request_ref_data(ur, NULL);

	if (verify_pin_req->pin_type == SIM_PTYPE_PIN1) {
		enum tel_sim_status status;

		verify_pin_resp.pin_type = SIM_PTYPE_PIN1;

		status = tcore_sim_get_status(co_sim);
		if (status != SIM_STATUS_INIT_COMPLETED) {
			/* Update sim status */
			__sim_update_sim_status(co_sim, SIM_STATUS_INITIALIZING);
			dbg("SIM is initializing...");
		}
	} else if (verify_pin_req->pin_type == SIM_PTYPE_PIN2) {
		verify_pin_resp.pin_type = SIM_PTYPE_PIN2;
	}

	if (at_resp && at_resp->success) {
		dbg("SIM Verify Pin Response- [OK]");
		verify_pin_resp.result = SIM_PIN_OPERATION_SUCCESS;

	} else {
		err("SIM Verify Pin Response- [NOK]");

		/* Update retry count */
		verify_pin_resp.retry_count = 3;
		verify_pin_resp.result = SIM_INCORRECT_PASSWORD;
	}

	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SIM_VERIFY_PINS,
			sizeof(struct tresp_sim_verify_pins), &verify_pin_resp);
	}  else {
		err("ur is NULL");
	}
}

static void on_response_sim_verify_puks(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	struct treq_sim_verify_puks *verify_puk_req;
	struct tresp_sim_verify_puks verify_puk_resp;
	UserRequest *ur;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	verify_puk_req = (struct treq_sim_verify_puks *)tcore_user_request_ref_data(ur, NULL);

	verify_puk_resp.pin_type = verify_puk_req->puk_type;

	if (at_resp && at_resp->success) {
		dbg("SIM Verify Puk Response- [OK]");
		verify_puk_resp.result = SIM_PIN_OPERATION_SUCCESS;
	} else {
		err("SIM Verify Puk Response- [NOK]");

		/* Update retry count */
		verify_puk_resp.retry_count = 3;
		verify_puk_resp.result = SIM_INCORRECT_PASSWORD;
	}

	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SIM_VERIFY_PUKS,
			sizeof(struct tresp_sim_verify_puks), &verify_puk_resp);
	}  else {
		err("ur is NULL");
	}
}

static void on_response_sim_change_pins(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	struct treq_sim_change_pins *sim_change_req;
	struct tresp_sim_change_pins sim_change_resp;
	UserRequest *ur;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	sim_change_req = (struct treq_sim_change_pins *)tcore_user_request_ref_data(ur, NULL);

	sim_change_resp.pin_type = sim_change_req->type;

	if (at_resp && at_resp->success) {
		dbg("SIM Change Pin Response- [OK]");
		sim_change_resp.result = SIM_PIN_OPERATION_SUCCESS;
	} else {
		err("SIM Change Pin Response- [NOK]");

		/* Update retry count */
		sim_change_resp.retry_count = 3;
		sim_change_resp.result = SIM_INCORRECT_PASSWORD;
	}

	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SIM_CHANGE_PINS,
			sizeof(struct tresp_sim_change_pins), &sim_change_resp);
	}  else {
		err("ur is NULL");
	}
}

static void on_response_sim_disable_facility(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	struct treq_sim_disable_facility *disable_facility_req;
	struct tresp_sim_disable_facility disable_facility_resp;
	UserRequest *ur;

	dbg("Entry");

	memset(&disable_facility_resp, 0x0, sizeof(struct tresp_sim_disable_facility));

	ur = tcore_pending_ref_user_request(p);
	disable_facility_req = (struct treq_sim_disable_facility *)tcore_user_request_ref_data(ur, NULL);

	disable_facility_resp.type = disable_facility_req->type;

	if (at_resp && at_resp->success) {
		dbg("SIM Disable Facility Response- [OK]");
		disable_facility_resp.result = SIM_PIN_OPERATION_SUCCESS;
	} else {
		err("SIM Disable Facility Response- [NOK]");

		/* Update retry count */
		disable_facility_resp.retry_count = 3;
		disable_facility_resp.result = SIM_INCORRECT_PASSWORD;
	}

	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SIM_DISABLE_FACILITY,
			sizeof(struct tresp_sim_disable_facility), &disable_facility_resp);
	}  else {
		err("ur is NULL");
	}
}

static void on_response_sim_enable_facility(TcorePending *p,
	gint data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	struct treq_sim_enable_facility *enable_facility_req;
	struct tresp_sim_enable_facility enable_facility_resp;
	UserRequest *ur;

	dbg("Entry");

	memset(&enable_facility_resp, 0x0, sizeof(struct tresp_sim_enable_facility));

	ur = tcore_pending_ref_user_request(p);
	enable_facility_req = (struct treq_sim_enable_facility *)tcore_user_request_ref_data(ur, NULL);

	enable_facility_resp.type = enable_facility_req->type;

	if (at_resp && at_resp->success) {
		dbg("SIM Disable Facility Response- [OK]");
		enable_facility_resp.result = SIM_PIN_OPERATION_SUCCESS;
	} else {
		err("SIM Disable Facility Response- [NOK]");

		/* Update retry count */
		enable_facility_resp.retry_count = 3;
		enable_facility_resp.result = SIM_INCORRECT_PASSWORD;
	}

	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SIM_ENABLE_FACILITY,
			sizeof(struct tresp_sim_enable_facility), &enable_facility_resp);
	}  else {
		err("ur is NULL");
	}
}

static void on_response_sim_get_facility(TcorePending *p, gint data_len,
		const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	struct treq_sim_get_facility_status *get_facility_req;
	struct tresp_sim_get_facility_status get_facility_resp;
	UserRequest *ur;

	dbg("Entry");

	memset(&get_facility_resp, 0x0, sizeof(struct tresp_sim_get_facility_status));

	ur = tcore_pending_ref_user_request(p);
	get_facility_req = (struct treq_sim_get_facility_status *)tcore_user_request_ref_data(ur, NULL);

	get_facility_resp.type = get_facility_req->type;
	get_facility_resp.result = SIM_CARD_ERROR;

	if (at_resp && at_resp->success) {
		GSList *tokens = NULL;
		const char *line;

		dbg("SIM Disable Facility Response- [OK]");
		if (at_resp->lines) {
			line = (const char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				err("Invalid message");
			}
			else {
				char *local_data = g_slist_nth_data(tokens, 0);
				if (local_data != NULL) {
					get_facility_resp.b_enable = atoi(local_data);
					dbg("Facility: [%s] - [%s]",
						__sim_get_fac_from_lock_type(get_facility_req->type),
						(get_facility_resp.b_enable ? "Enabled" : "Disabled"));

					get_facility_resp.result = SIM_PIN_OPERATION_SUCCESS;
				}
				else {
					err("Invalid message");
				}
			}

			tcore_at_tok_free(tokens);
		}
	} else {
		err("SIM Disable Facility Response- [NOK]");
	}

	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_SIM_GET_FACILITY_STATUS,
			sizeof(struct tresp_sim_get_facility_status), &get_facility_resp);
	}  else {
		err("ur is NULL");
	}
}

/* SIM Operations */
/*
 * Operation - get_imsi
 *
 * Request -
 * AT-Command: AT+CRSM= <command>[,<fileid>[,<P1>,<P2>,<P3>[,<data>[,<pathid>]]]]
 * where,
 * <command>
 * 176 READ BINARY
 * 178 READ RECORD
 * 192 GET RESPONSE
 * 214 UPDATE BINARY
 * 220 UPDATE RECORD
 * 242 STATUS
 *
 * <fileid>
 * 28423 meaning IMSI file (6F07)
 * 28473 meaning ACM file (6F39)
 * 28481 meaning PUKT file (6F41)
 * 28482 meaning SMS file (6F42)
 *
 * <P1>, <P2>, <P3>
 * Integer type defining the request.
 * These parameters are mandatory for every command, except GET RESPONSE and STATUS.
 *
 * <data>
 * Information which shall be written to the SIM
 *
 * <pathid>
 * String type, contains the path of an elementary file on the SIM/USIM in hexadecimal format
 *
 * <status>
 * 0 not active
 * 1 active
 *
 * Success:
 * 	OK
 * 	+CRSM: <sw1>,<sw2>[,<response>]
 *
 * <sw1>, <sw2>
 * Integer type containing the SIM information
 *
 * <response>
 * Response of successful completion of the command previously issued
 *
 * Failure:
 *	+CME ERROR: <error>
 */
#if 0	/* To be used later */
static TReturn __sim_get_imsi(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_IMSI;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_IMSI;

	return __sim_get_response(co_sim, ur, file_meta);
}
#endif
static TReturn __sim_get_ecc(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;
	TReturn ret;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_ECC;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_ECC;

	ret = __sim_get_response(co_sim, ur, file_meta);

	return ret;
}

static TReturn __sim_get_spdi(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;
	TReturn ret;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_SPDI;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_SPDI;

	ret = __sim_get_response(co_sim, ur, file_meta);

	return ret;
}

static TReturn __sim_get_cfis(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;
	TReturn ret;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_USIM_CFIS;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_CALLFORWARDING;

	ret = __sim_get_response(co_sim, ur, file_meta);

	return ret;
}

static TReturn __sim_get_spn(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;
	TReturn ret;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_SPN;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_SPN;

	ret = __sim_get_response(co_sim, ur, file_meta);

	return ret;
}

static TReturn __sim_get_language(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;
	TReturn ret;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_LP;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_LANGUAGE;

	ret = __sim_get_response(co_sim, ur, file_meta);

	return ret;
}

static TReturn __sim_get_sst(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;
	TReturn ret;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_SST;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_SERVICE_TABLE;

	ret = __sim_get_response(co_sim, ur, file_meta);

	return ret;
}

static TReturn __sim_get_iccid(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;
	TReturn ret;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_ICCID;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_ICCID;

	ret = __sim_get_response(co_sim, ur, file_meta);

	return ret;
}

static TReturn __sim_get_msisdn(CoreObject *co_sim, UserRequest *ur)
{
	sim_meta_info_t *file_meta;
	TReturn ret;

	dbg("Entry");

	ALLOC_METAINFO();
	file_meta->file_id = SIM_EF_MSISDN;
	file_meta->file_result = SIM_ACCESS_FAILED;
	file_meta->req_command = TREQ_SIM_GET_MSISDN;

	ret = __sim_get_response(co_sim, ur, file_meta);

	return ret;
}
/*
 * Operation - verify_pins/verify_puks/change_pins
 *
 * Request -
 * For SIM PIN
 * AT-Command: AT+CPIN= <pin> [, <newpin>]
 * where,
 * <pin>, <newpin>
 * String type values
 *
 * For SIM PIN2
 * AT-Command: AT+CPIN2= <puk2/oldpin2> [, <newpin2>]andAT+CPIN2=<oldpin2>
 * where,
 * <puk2/pin2>, <newpin2>
 * String type values
 *
 * Success:
 * 	OK
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn s_sim_verify_pins(CoreObject *co_sim, UserRequest *ur)
{
	struct treq_sim_verify_pins *verify_pins_req;
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *cmd_str = NULL;

	dbg("Entry");

	verify_pins_req = (struct treq_sim_verify_pins *)tcore_user_request_ref_data(ur, NULL);

	if ((verify_pins_req->pin_type == SIM_PTYPE_PIN1)
			|| (verify_pins_req->pin_type == SIM_PTYPE_PIN2)) {
		dbg("PUK type: [%d]", verify_pins_req->pin_type);
	} else {
		err("Invalid pin type [%d]", verify_pins_req->pin_type);
		return TCORE_RETURN_EINVAL;
	}

	cmd_str = g_strdup_printf("AT+CPIN=\"%s\"", verify_pins_req->pin);

	ret = tcore_prepare_and_send_at_request(co_sim,
		cmd_str, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_sim_verify_pins, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(cmd_str);
	return ret;
}

static TReturn s_sim_verify_puks(CoreObject *co_sim, UserRequest *ur)
{
	struct treq_sim_verify_puks *verify_puks_req;
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *cmd_str = NULL;

	dbg("Entry");

	verify_puks_req = (struct treq_sim_verify_puks *)tcore_user_request_ref_data(ur, NULL);

	if ((verify_puks_req->puk_type == SIM_PTYPE_PUK1)
			|| (verify_puks_req->puk_type == SIM_PTYPE_PUK2)) {
		dbg("PUK type: [%d]", verify_puks_req->puk_type);
	} else {
		err("Invalid puk type [%d]", verify_puks_req->puk_type);
		return TCORE_RETURN_EINVAL;
	}

	cmd_str = g_strdup_printf("AT+CPIN=\"%s\", \"%s\"",
		verify_puks_req->puk, verify_puks_req->pin);

	ret = tcore_prepare_and_send_at_request(co_sim,
		cmd_str, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_sim_verify_puks, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(cmd_str);
	return ret;
}

static TReturn s_sim_change_pins(CoreObject *co_sim, UserRequest *ur)
{
	struct treq_sim_change_pins *sim_change_req;
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *cmd_str = NULL;

	dbg("Entry");

	sim_change_req = (struct treq_sim_change_pins *)tcore_user_request_ref_data(ur, NULL);

	if ((sim_change_req->type == SIM_PTYPE_PIN1)
			|| (sim_change_req->type == SIM_PTYPE_PIN2)) {
		dbg("PIN type: [%d]", sim_change_req->type);
	} else {
		err("Invalid pin type [%d]", sim_change_req->type);
		return TCORE_RETURN_EINVAL;
	}

	cmd_str = g_strdup_printf("AT+CPIN=\"%s\", \"%s\"", sim_change_req->old_pin, sim_change_req->new_pin);

	ret = tcore_prepare_and_send_at_request(co_sim,
		cmd_str, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_response_sim_change_pins, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(cmd_str);
	return ret;
}

/*
 * Operation - disable_facility/enable_facility/get_facility
 *
 * Request -
 * AT-Command: AT+CLCK = <fac>, <mode> [, <passwd> [, <class>]]
 * where,
 * <fac>
 * SIM facility
 *
 * <mode>
 * 0 unlock
 * 1 lock
 * 2 query status
 *
 * <passwd>
 * Password string
 *
 * <status>
 * 0 not active
 * 1 active
 *
 * Success: when <mode>=2:
 * 	OK
 * 	+CLCK: <status>[,<class1> [<CR><LF>
 * 	+CLCK: <status>,<class2> [...]]
 *
 * Failure:
 */
static TReturn s_sim_disable_facility(CoreObject *co_sim, UserRequest *ur)
{
	struct treq_sim_disable_facility *disable_facility_req;
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *cmd_str = NULL;
	const char *fac = "SC";
	int mode = 0; /*mode = 0 for disable lock*/

	dbg("Entry");

	disable_facility_req = (struct treq_sim_disable_facility *)tcore_user_request_ref_data(ur, NULL);

	fac = __sim_get_fac_from_lock_type(disable_facility_req->type);
	if (!fac) {
		err("Invalid 'fac'");
		return TCORE_RETURN_EINVAL;
	}

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"", fac, mode, disable_facility_req->password);

	ret = tcore_prepare_and_send_at_request(co_sim,
		cmd_str, "+CLCK:",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_sim_disable_facility, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(cmd_str);
	return ret;
}

static TReturn s_sim_enable_facility(CoreObject *co_sim, UserRequest *ur)
{
	struct treq_sim_enable_facility *enable_facility_req;
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *cmd_str = NULL;
	const char *fac = "SC";
	int mode = 1; /*mode = 1 for enable lock*/

	dbg("Entry");

	enable_facility_req = (struct treq_sim_enable_facility *)tcore_user_request_ref_data(ur, NULL);

	fac = __sim_get_fac_from_lock_type(enable_facility_req->type);
	if (!fac) {
		err("Invalid 'fac'");
		return TCORE_RETURN_EINVAL;
	}

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"", fac, mode, enable_facility_req->password);

	ret = tcore_prepare_and_send_at_request(co_sim,
		cmd_str, "+CLCK:",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_sim_enable_facility, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(cmd_str);
	return ret;
}

TReturn s_sim_read_file(CoreObject *co_sim, UserRequest *ur)
{
	TReturn ret = TCORE_RETURN_SUCCESS;
	enum tcore_request_command command;

	dbg("Entry");

	command = tcore_user_request_get_command(ur);

	switch (command) {
	case TREQ_SIM_GET_ECC:
		ret = __sim_get_ecc(co_sim, ur);
	break;

	case TREQ_SIM_GET_LANGUAGE:
		ret = __sim_get_language(co_sim, ur);
	break;

	case TREQ_SIM_GET_CALLFORWARDING:
		ret = __sim_get_cfis(co_sim, ur);
	break;

	case TREQ_SIM_GET_SPN:
		ret = __sim_get_spn(co_sim, ur);
	break;

	case TREQ_SIM_GET_SPDI:
		ret = __sim_get_spdi(co_sim, ur);
	break;

	case TREQ_SIM_GET_SERVICE_TABLE:
		ret = __sim_get_sst(co_sim, ur);
	break;

	case TREQ_SIM_GET_ICCID:
		ret = __sim_get_iccid(co_sim, ur);
	break;

	case TREQ_SIM_GET_MSISDN:
		ret = __sim_get_msisdn(co_sim, ur);
	break;

	case TREQ_SIM_GET_MESSAGEWAITING:
	case TREQ_SIM_GET_CPHS_INFO:
	case TREQ_SIM_GET_OPL:
	case TREQ_SIM_GET_PNN:
	case TREQ_SIM_GET_CPHS_NETNAME:
	case TREQ_SIM_GET_OPLMNWACT:
	case TREQ_SIM_GET_MAILBOX:
	default:
		dbg("Unhandled read requests - command: [0x%x]", command);
		ret = TCORE_RETURN_EINVAL;
		break;
	}
	dbg("ret: [0x%x]", ret);

	return ret;
}

static TReturn s_sim_get_facility(CoreObject *co_sim, UserRequest *ur)
{
	struct treq_sim_get_facility_status *get_facility_req;
	TReturn ret = TCORE_RETURN_FAILURE;
	gchar *cmd_str = NULL;
	const char *fac = "SC";
	int mode = 2; /*mode = 2 for Get Facility*/

	dbg("Entry");

	get_facility_req = (struct treq_sim_get_facility_status *)tcore_user_request_ref_data(ur, NULL);

	fac = __sim_get_fac_from_lock_type(get_facility_req->type);
	if (!fac) {
		err("Invalid 'fac'");
		return TCORE_RETURN_EINVAL;
	}

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d", fac, mode);

	ret = tcore_prepare_and_send_at_request(co_sim,
		cmd_str, "+CLCK:",
		TCORE_AT_SINGLELINE,
		ur,
		on_response_sim_get_facility, NULL,
		on_send_at_request, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	g_free(cmd_str);
	return ret;
}

/* SIM Operations */
static struct tcore_sim_operations sim_ops = {
	.verify_pins = s_sim_verify_pins,
	.verify_puks = s_sim_verify_puks,
	.change_pins = s_sim_change_pins,
	.get_facility_status = s_sim_get_facility,
	.enable_facility = s_sim_enable_facility,
	.disable_facility = s_sim_disable_facility,
	.read_file = s_sim_read_file,
	.update_file = NULL,
	.transmit_apdu = NULL,
	.get_atr = NULL,
	.req_authentication = NULL
};

gboolean s_sim_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *co_sim;

	co_sim = tcore_sim_new(p, "sim", &sim_ops, h);
	if (!co_sim) {
		err("Core object is NULL");
		return FALSE;
	}

	tcore_object_add_callback(co_sim, "+SCSIM:",
		on_notification_sim_status, NULL);

	return TRUE;
}

void s_sim_exit(TcorePlugin *p)
{
	CoreObject *co_sim;

	co_sim = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SIM);
	if (!co_sim)
		return;

	tcore_sim_free(co_sim);
}


