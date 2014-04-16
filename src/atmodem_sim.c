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
#include <vconf.h>

#include <co_sim.h>
#include <co_sms.h>

#include "atmodem_sim.h"
#include "atmodem_common.h"

#define ENABLE_FLAG 1
#define DISABLE_FLAG 2

#define ATMODEM_SIM_ACCESS_READ_BINARY		176
#define ATMODEM_SIM_ACCESS_READ_RECORD		178
#define ATMODEM_SIM_ACCESS_GET_RESPONSE		192
#define ATMODEM_SIM_ACCESS_UPDATE_BINARY		214
#define ATMODEM_SIM_ACCESS_UPDATE_RECORD		220

typedef enum {
	ATMODEM_SIM_FILE_TYPE_DEDICATED = 0x00,	/**< Dedicated */
	ATMODEM_SIM_FILE_TYPE_TRANSPARENT = 0x01,	/**< Transparent -binary type*/
	ATMODEM_SIM_FILE_TYPE_LINEAR_FIXED = 0x02,	/**< Linear fixed - record type*/
	ATMODEM_SIM_FILE_TYPE_CYCLIC = 0x04,	/**< Cyclic - record type*/
	ATMODEM_SIM_FILE_TYPE_INVALID_TYPE = 0xFF	/**< Invalid type */
} AtmodemSimFileType;

typedef enum {
	ATMODEM_SIM_CURR_SEC_OP_PIN1_VERIFY,
	ATMODEM_SIM_CURR_SEC_OP_PIN2_VERIFY,
	ATMODEM_SIM_CURR_SEC_OP_PUK1_VERIFY,
	ATMODEM_SIM_CURR_SEC_OP_PUK2_VERIFY,
	ATMODEM_SIM_CURR_SEC_OP_SIM_VERIFY,
	ATMODEM_SIM_CURR_SEC_OP_ADM_VERIFY,
	ATMODEM_SIM_CURR_SEC_OP_PIN1_CHANGE,
	ATMODEM_SIM_CURR_SEC_OP_PIN2_CHANGE,
	ATMODEM_SIM_CURR_SEC_OP_PIN1_ENABLE,
	ATMODEM_SIM_CURR_SEC_OP_PIN1_DISABLE,
	ATMODEM_SIM_CURR_SEC_OP_PIN2_ENABLE,
	ATMODEM_SIM_CURR_SEC_OP_PIN2_DISABLE, // 10
	ATMODEM_SIM_CURR_SEC_OP_SIM_ENABLE,
	ATMODEM_SIM_CURR_SEC_OP_SIM_DISABLE,
	ATMODEM_SIM_CURR_SEC_OP_NET_ENABLE,
	ATMODEM_SIM_CURR_SEC_OP_NET_DISABLE,
	ATMODEM_SIM_CURR_SEC_OP_NS_ENABLE,
	ATMODEM_SIM_CURR_SEC_OP_NS_DISABLE,
	ATMODEM_SIM_CURR_SEC_OP_SP_ENABLE,
	ATMODEM_SIM_CURR_SEC_OP_SP_DISABLE,
	ATMODEM_SIM_CURR_SEC_OP_CP_ENABLE,
	ATMODEM_SIM_CURR_SEC_OP_CP_DISABLE, // 20
	ATMODEM_SIM_CURR_SEC_OP_FDN_ENABLE,
	ATMODEM_SIM_CURR_SEC_OP_FDN_DISABLE,
	ATMODEM_SIM_CURR_SEC_OP_PIN1_STATUS,
	ATMODEM_SIM_CURR_SEC_OP_PIN2_STATUS,
	ATMODEM_SIM_CURR_SEC_OP_FDN_STATUS,
	ATMODEM_SIM_CURR_SEC_OP_NET_STATUS,
	ATMODEM_SIM_CURR_SEC_OP_NS_STATUS,
	ATMODEM_SIM_CURR_SEC_OP_SP_STATUS,
	ATMODEM_SIM_CURR_SEC_OP_CP_STATUS,
	ATMODEM_SIM_CURR_SEC_OP_SIM_STATUS,
	ATMODEM_SIM_CURR_SEC_OP_SIM_UNKNOWN = 0xff
} AtmodemSimCurrSecOp;

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
} AtmodemSimSecLockType;

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
} AtmodemSimSecLockKey;

typedef struct {
	guint smsp_count;					/**< SMSP record count */
	guint smsp_rec_len;					/**< SMSP record length */
} AtmodemSimPrivateInfo;

typedef struct {
	gboolean b_valid;					/**< Valid or not */
	guint rec_length;					/**< Length of one record in file */
	guint rec_count;					/**< Number of records in file */
	guint data_size;					/**< File size */
	guint current_index;					/**< Current index to read */
	AtmodemSimFileType file_type;				/**< File type and structure */
	AtmodemSimCurrSecOp sec_op;					/**< Current index to read */
	TelSimMailboxList mbi_list;				/**< Mailbox List */
	TelSimMailBoxNumber mb_list[TEL_SIM_MSP_CNT_MAX*5];	/**< Mailbox number */
	TelSimFileId file_id;					/**< Current file id */
	TelSimResult file_result;				/**< File access result */
	TelSimFileResult files;					/**< File read data */
	TcoreCommand req_command;				/**< Request command Id */
	TelSimImsiInfo imsi;					/**< Stored locally as of now,
								          Need to store in secure storage*/
} AtmodemSimMetaInfo;

/* Request Function Declaration */
static TelReturn atmodem_sim_get_imsi (CoreObject *co_sim, TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_get_ecc (CoreObject *co_sim, TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_get_spdi (CoreObject *co_sim, TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_get_spn (CoreObject *co_sim, TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_get_language (CoreObject *co_sim, TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_verify_pins(CoreObject *co, const TelSimSecPinPw *request,
		TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_verify_puks(CoreObject *co, const TelSimSecPukPw *request,
		TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_change_pins(CoreObject *co, const TelSimSecChangePinPw *request,
		TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_disable_facility(CoreObject *co, const TelSimFacilityPw *request,
		TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_enable_facility(CoreObject *co, const TelSimFacilityPw *request,
		TcoreObjectResponseCallback cb, void *cb_data);
static TelReturn atmodem_sim_get_facility(CoreObject *co, TelSimLockType lock_type,
		TcoreObjectResponseCallback cb, void *cb_data);

/* Utility Function Declaration */
static TelSimResult __atmodem_sim_decode_status_word(unsigned short status_word1, unsigned short status_word2);
static void __atmodem_sim_update_sim_status(CoreObject *co, TelSimCardStatus sim_status);
static void __atmodem_sim_get_sim_type(CoreObject *co, TcoreObjectResponseCallback cb, void *cb_data);
static void __atmodem_sim_next_from_get_file_data(CoreObject *co,
	AtmodemRespCbData *resp_cb_data, TelSimResult sim_result, gboolean decode_ret);
static void __atmodem_sim_next_from_get_file_info(CoreObject *co,
	AtmodemRespCbData *resp_cb_data, TelSimResult sim_result);
static void __atmodem_sim_get_file_record(CoreObject *co,
	AtmodemRespCbData *resp_cb_data);
static void __atmodem_sim_get_file_data(CoreObject *co,
	AtmodemRespCbData *resp_cb_data);
static TelReturn __atmodem_sim_get_file_info(CoreObject *co,
	AtmodemRespCbData *resp_cb_data);
static char *__atmodem_sim_get_fac_from_lock_type(TelSimLockType lock_type,
	AtmodemSimCurrSecOp *sec_op, int flag);
static int __atmodem_sim_get_lock_type(AtmodemSimCurrSecOp sec_op);
static gboolean __atmodem_convert_scpin_str_to_enum(char* line,
	AtmodemSimSecLockType* lock_type, AtmodemSimSecLockKey* lock_key);

/* Internal Response Functions*/
static void __atmodem_sim_next_from_read_binary(CoreObject *co,
	AtmodemRespCbData *resp_cb_data,
	TelSimResult sim_result, gboolean decode_ret);
static void __atmodem_sim_next_from_get_response(CoreObject *co,
	AtmodemRespCbData *resp_cb_data, TelSimResult sim_result);

#if 0 //blocking for the moment
static TelReturn __atmodem_sim_update_file(CoreObject *co,
	AtmodemRespCbData *resp_cb_data,
	int cmd, TelSimFileId ef,
	int p1, int p2, int p3, char *encoded_data);
#endif
static void __atmodem_sim_read_record(CoreObject *co, AtmodemRespCbData *resp_cb_data);
static void __atmodem_sim_read_binary(CoreObject *co, AtmodemRespCbData *resp_cb_data);
static TelReturn __atmodem_sim_get_response (CoreObject *co, AtmodemRespCbData *resp_cb_data);
static void __on_response_atmodem_sim_get_sim_type_internal(CoreObject *co,
	gint result, const void *response, void *user_data);
static void __on_response_atmodem_sim_get_sim_type(TcorePending *p,
	guint data_len, const void *data, void *user_data);
static void __on_response_atmodem_sim_get_file_data(TcorePending *p,
	guint data_len, const void *data, void *user_data);
static void __on_response_atmodem_sim_get_file_info(TcorePending *p,
	guint data_len, const void *data, void *user_data);

#define ATMODEM_SIM_READ_FILE(co, cb, cb_data, fileId, ret) \
{ \
	AtmodemSimMetaInfo file_meta = {0, }; \
	AtmodemRespCbData *resp_cb_data = NULL; \
	\
	file_meta.file_id = fileId; \
	file_meta.file_result = TEL_SIM_RESULT_FAILURE; \
	\
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data, &file_meta, sizeof(AtmodemSimMetaInfo)); \
	\
	ret = __atmodem_sim_get_response(co, resp_cb_data); \
}

static void __atmodem_sim_set_identity(CoreObject *co, TelSimImsiInfo *imsi)
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
			tcore_sim_set_identification(co, TRUE);
		} else {
			dbg("Same SIM");
			tcore_sim_set_identification(co, FALSE);
		}
	} else {
		dbg("Old IMSI value is NULL, set IMSI");
		vconf_set_str("db/telephony/imsi", new_imsi);
		tcore_sim_set_identification(co, TRUE);
	}
}

/* Utility Functions */
static TelSimResult __atmodem_sim_decode_status_word(unsigned short status_word1,
	unsigned short status_word2)
{
	TelSimResult rst = TEL_SIM_RESULT_FAILURE;

	if (status_word1 == 0x93 && status_word2 == 0x00) {
		/*Failed SIM request command*/
		dbg("error - SIM application toolkit busy [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x00) {
		/*Failed SIM request command*/
		dbg("error - No EF Selected [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x02) {
		/*Failed SIM request command*/
		dbg("error - Out of Range - Invalid address or record number[%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x04) {
		/*Failed SIM request command*/
		dbg("error - File ID not found [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x08) {
		/*Failed SIM request command*/
		dbg("error - File is inconsistent with command - "\
			"Modem not support or USE IPC [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x02) {
		/*Failed SIM request command*/
		dbg("error - CHV not initialized [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x04) {
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
		/*Failed SIM request command*/
		dbg("error - Contradiction with CHV status [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x10) {
		/*Failed SIM request command*/
		dbg("error - Contradiction with invalidation status [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x40) {
		/*Failed SIM request command*/
		dbg("error -Unsuccessful CHV verification - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Unsuccessful Unblock CHV - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - CHV blocked [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x67 && status_word2 == 0x00) {
		dbg("error -Incorrect Parameter 3 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6B && status_word2 == 0x00) {
		dbg("error -Incorrect Parameter 1 or 2 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6D && status_word2 == 0x00) {
		dbg("error -Unknown instruction given as command [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x6E && status_word2 == 0x00) {
		dbg("error -Unknown instruction given as command [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x69 && status_word2 == 0x82) {
		dbg("error -Access denied [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x87) {
		dbg("error -Incorrect parameters [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x82) {
		dbg("error -File Not found [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x83) {
		dbg("error -Record Not found [%x][%x]", status_word1, status_word2);
	} else {
		rst = TEL_SIM_RESULT_CARD_ERROR;
		dbg("error -Unknown state [%x][%x]", status_word1, status_word2);
	}
	return rst;
}

static void __atmodem_sim_update_sim_status(CoreObject *co_sim,
	TelSimCardStatus sim_status)
{
	TelSimCardStatus curr_sim_status;

	/*
	 * Send SIM Init status, if not sent already
	 */
	(void)tcore_sim_get_status(co_sim, &curr_sim_status);
	if (sim_status != curr_sim_status) {
		TelSimCardStatusInfo sim_status_noti = {0, };

		dbg("Change in SIM State - Old State: [0x%02x] --> New State: [0x%02x]",
				curr_sim_status, sim_status);

		/* Update SIM Status */
		tcore_sim_set_status(co_sim, sim_status);
		sim_status_noti.status = sim_status;
		sim_status_noti.change_status = TEL_SIM_CHANGE_STATUS_SAME;	/* TODO: checkout */

		/* Send notification: SIM Status */
		tcore_object_send_notification(co_sim,
			TCORE_NOTIFICATION_SIM_STATUS,
			sizeof(sim_status_noti), &sim_status_noti);
	}
}

static gboolean __atmodem_convert_scpin_str_to_enum(char* line,
		AtmodemSimSecLockType *lock_type, AtmodemSimSecLockKey *lock_key)
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

static void __on_response_atmodem_sim_get_sim_type_internal(CoreObject *co_sim,
	gint result, const void *response, void *user_data)
{
	dbg("SIM Response - SIM Type (internal): [\%SCCT]");

	/* Get SIM type if SIM is initialized */
	if (result == TEL_SIM_RESULT_SUCCESS) {
		TelSimCardType *sim_type = (TelSimCardType *)response;

		/* Update SIM type */
		tcore_sim_set_type(co_sim, *sim_type);
		if (*sim_type != TEL_SIM_CARD_TYPE_UNKNOWN) {
			/* Send SIM Type notification */
			tcore_object_send_notification(co_sim,
				TCORE_NOTIFICATION_SIM_TYPE,
				sizeof(TelSimCardType), sim_type);
		}
	}
}

static void __on_response_atmodem_sim_get_sim_type(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co_sim = tcore_pending_ref_core_object(p);
	AtmodemRespCbData *resp_cb_data = user_data;
	TelSimCardType sim_type = TEL_SIM_CARD_TYPE_UNKNOWN;

	TelSimResult result = TEL_SIM_RESULT_FAILURE;

	dbg("SIM Response - SIM Type: [\%SCCT]");

	tcore_check_return_assert(co_sim != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

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

				result = TEL_SIM_RESULT_SUCCESS;
			}
			else {
				err("Invalid message");
			}

			tcore_at_tok_free(tokens);
		}
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co_sim, (gint)result, &sim_type, resp_cb_data->cb_data);

	/* Free callback data */
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

/*
 * Operation - get_sim_type
 *
 * Request -
 * AT-Command: AT%SCCT?
 *
 * Response - sim_type (TelSimCardType)
 * Success: (Single line) -
 *	+SCCT: <state>
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static void __atmodem_sim_get_sim_type(CoreObject *co_sim,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	AtmodemRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_sim,
		"AT\%SCCT?", "\%SCCT:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_atmodem_sim_get_sim_type, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get SIM Type");

	dbg("ret: [%d]",  ret);
}

static void __atmodem_sim_process_sim_status(CoreObject *co,
	TelSimCardStatus sim_card_status)
{
	switch (sim_card_status) {
	case TEL_SIM_STATUS_SIM_INIT_COMPLETED: {
		TelReturn ret;

		dbg("SIM INIT COMPLETED");

		ATMODEM_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_IMSI, ret);
		ATMODEM_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_SPDI, ret);
		dbg("ret: [%d]", ret);

		return;
	}

	case TEL_SIM_STATUS_SIM_INITIALIZING: {
		TelSimCardType sim_type;

		dbg("SIM INITIALIZING");

		(void)tcore_sim_get_type(co, &sim_type);
		if (sim_type == TEL_SIM_CARD_TYPE_UNKNOWN) {
			/*
			 * SIM is initialized for first time, need to
			 * fetch SIM type
			 */
			__atmodem_sim_get_sim_type(co,
				__on_response_atmodem_sim_get_sim_type_internal, NULL);

			return;
		}
	}
	break;

	case TEL_SIM_STATUS_CARD_REMOVED:
		dbg("SIM CARD REMOVED");
		tcore_sim_set_type(co, TEL_SIM_CARD_TYPE_UNKNOWN);
	break;

	case TEL_SIM_STATUS_CARD_NOT_PRESENT:
		dbg("SIM CARD NOT PRESENT");
		tcore_sim_set_type(co, TEL_SIM_CARD_TYPE_UNKNOWN);
	break;

	case TEL_SIM_STATUS_CARD_ERROR:
		dbg("SIM CARD ERROR");
		tcore_sim_set_type(co, TEL_SIM_CARD_TYPE_UNKNOWN);
	break;

	default:
		err("SIM Status: [0x%02x]", sim_card_status);
	break;
	}

	/* Update SIM Status */
	return __atmodem_sim_update_sim_status(co, sim_card_status);
}

static void __atmodem_sim_next_from_get_file_data(CoreObject *co_sim,
	AtmodemRespCbData *resp_cb_data,
	TelSimResult sim_result, gboolean decode_ret)
{
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

	dbg("Entry");

	dbg("[SIM]EF[0x%x] read sim_result[%d] Decode rt[%d]",
		file_meta->file_id, sim_result, decode_ret);
	switch (file_meta->file_id) {
	case TEL_SIM_EF_ELP:
	case TEL_SIM_EF_USIM_PL:
	case TEL_SIM_EF_LP:
	case TEL_SIM_EF_USIM_LI:
		if (decode_ret == TRUE) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			tcore_sim_get_type(co_sim, &card_type);
			/* 2G */
			/*
			 * The ME requests the Extended Language Preference.
			 * The ME only requests the Language Preference (EFLP) if at
			 * least one of the following conditions holds:
			 * -	EFELP is not available;
			 * -	EFELP does not contain an entry corresponding to a
			 *	language specified in ISO 639[30];
			 * -	the ME does not support any of the languages in EFELP.
			 */
			/* 3G */
			/*
			 * The ME only requests the Language Preference (EFPL)
			 * if at least one of the following conditions holds:
			 * -	if the EFLI has the value 'FFFF' in its highest
			 *	priority position
			 * -	if the ME does not support any of the language codes
			 *	indicated in EFLI , or if EFLI is not present
			 */
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				if (file_meta->file_id == TEL_SIM_EF_LP) {
					if (resp_cb_data->cb)
						resp_cb_data->cb(co_sim, (gint)sim_result,
							&file_meta->files.data, resp_cb_data->cb_data);
				} else {
					file_meta->file_id = TEL_SIM_EF_LP;
					__atmodem_sim_get_file_info(co_sim, resp_cb_data);
				}
			} else if (TEL_SIM_CARD_TYPE_USIM) {
				if (file_meta->file_id == TEL_SIM_EF_LP
						|| file_meta->file_id == TEL_SIM_EF_USIM_LI) {
					file_meta->file_id = TEL_SIM_EF_ELP;
					__atmodem_sim_get_file_info(co_sim, resp_cb_data);
				} else {
					if (resp_cb_data->cb)
						resp_cb_data->cb(co_sim, (gint)sim_result,
							&file_meta->files.data, resp_cb_data->cb_data);
				}
			}
		}
	break;

	case TEL_SIM_EF_ECC:
		tcore_sim_get_type(co_sim, &card_type);
		if (TEL_SIM_CARD_TYPE_USIM == card_type) {
			if (file_meta->current_index == file_meta->rec_count) {
				if (resp_cb_data->cb)
					resp_cb_data->cb(co_sim, (gint)sim_result,
						&file_meta->files.data, resp_cb_data->cb_data);
			} else {
				file_meta->current_index++;
				__atmodem_sim_get_file_record(co_sim, resp_cb_data);
			}
		} else if (TEL_SIM_CARD_TYPE_GSM == card_type) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			dbg("[SIM DATA] Invalid CardType: [%d]. Unable to handle", card_type);
		}
	break;

	case TEL_SIM_EF_IMSI:
		if (resp_cb_data->cb) {
			resp_cb_data->cb(co_sim, (gint)sim_result,
				&file_meta->imsi, resp_cb_data->cb_data);
		} else {
			/* Update Status */
			__atmodem_sim_update_sim_status(co_sim, TEL_SIM_STATUS_SIM_INIT_COMPLETED);
		}
	break;

	case TEL_SIM_EF_MSISDN:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__atmodem_sim_get_file_record(co_sim, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_OPL:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__atmodem_sim_get_file_record(co_sim, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_PNN:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__atmodem_sim_get_file_record(co_sim, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_USIM_CFIS:
	case TEL_SIM_EF_USIM_MWIS:
	case TEL_SIM_EF_USIM_MBI:
	case TEL_SIM_EF_MBDN:
	case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:
	case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__atmodem_sim_get_file_record(co_sim, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
	{
		file_meta->files.result = sim_result;
		if (decode_ret == TRUE && sim_result == TEL_SIM_RESULT_SUCCESS) {
			memcpy(file_meta->files.data.cphs_net.full_name, file_meta->files.data.cphs_net.full_name, strlen((char *)file_meta->files.data.cphs_net.full_name));
		}

		file_meta->file_id = TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING;
		file_meta->file_result = TEL_SIM_RESULT_FAILURE;
		file_meta->req_command = TCORE_COMMAND_SIM_GET_CPHS_NET_NAME;

		__atmodem_sim_get_file_info(co_sim, resp_cb_data);
	}
	break;

	case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
		if (file_meta->files.result == TEL_SIM_RESULT_SUCCESS)
			file_meta->files.result = TEL_SIM_RESULT_SUCCESS;

		if (strlen((char *)file_meta->files.data.cphs_net.full_name))
			memcpy(&file_meta->files.data.cphs_net.full_name,
				&file_meta->files.data.cphs_net.full_name,
				strlen((char *)file_meta->files.data.cphs_net.full_name));

		if (resp_cb_data->cb)
			resp_cb_data->cb(co_sim, (gint)sim_result,
				&file_meta->files.data, resp_cb_data->cb_data);
	break;

	case TEL_SIM_EF_ICCID:
	case TEL_SIM_EF_SST:
	case TEL_SIM_EF_SPN:
	case TEL_SIM_EF_SPDI:
	case TEL_SIM_EF_OPLMN_ACT:
	case TEL_SIM_EF_CPHS_CPHS_INFO:
	case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:
	case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
	case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		if (resp_cb_data->cb)
			resp_cb_data->cb(co_sim, (gint)sim_result,
				&file_meta->files.data, resp_cb_data->cb_data);
	break;

	default:
		err("File id not handled [0x%x]", file_meta->file_id);
	break;
	}
}

static void __atmodem_sim_next_from_get_file_info(CoreObject *co_sim,
	AtmodemRespCbData *resp_cb_data, TelSimResult sim_result)
{
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

	dbg("EF[0x%x] access Result[%d]", file_meta->file_id, sim_result);

	file_meta->files.result = sim_result;
	memset(&file_meta->files.data, 0x00, sizeof(file_meta->files.data));

	if ((file_meta->file_id != TEL_SIM_EF_ELP
			&& file_meta->file_id != TEL_SIM_EF_LP
			&& file_meta->file_id != TEL_SIM_EF_USIM_PL
			&& file_meta->file_id != TEL_SIM_EF_CPHS_CPHS_INFO)
			&& (sim_result != TEL_SIM_RESULT_SUCCESS)) {
		if (resp_cb_data->cb)
			resp_cb_data->cb(co_sim, (gint)sim_result,
				&file_meta->files.data, resp_cb_data->cb_data);

		return;
	}

	switch (file_meta->file_id) {
	case TEL_SIM_EF_ELP:
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			__atmodem_sim_get_file_data(co_sim, resp_cb_data);
		} else {
			tcore_sim_get_type(co_sim, &card_type);
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				AtmodemSimMetaInfo file_meta_new = {0,};

				dbg("[SIM DATA]SIM_EF_ELP(2F05) access fail. Request SIM_EF_LP(0x6F05) info");
				/* The ME requests the Language Preference (EFLP) if EFELP is not available */
				file_meta_new.file_id = TEL_SIM_EF_LP;
				file_meta_new.file_result = TEL_SIM_RESULT_FAILURE;
				file_meta_new.req_command = TCORE_COMMAND_SIM_GET_LANGUAGE;

				memcpy(resp_cb_data->data, &file_meta_new, sizeof(AtmodemSimMetaInfo));

				__atmodem_sim_get_file_info(co_sim, resp_cb_data);
			} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
				dbg(" [SIM DATA]fail to get Language information in USIM(EF-LI(6F05),EF-PL(2F05))");
				if (resp_cb_data->cb)
					resp_cb_data->cb(co_sim, (gint)sim_result,
						&file_meta->files.data, resp_cb_data->cb_data);

				return;
			}
		}
	break;

	case TEL_SIM_EF_LP:
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFLP/LI(0x6F05)");
			__atmodem_sim_get_file_data(co_sim, resp_cb_data);
		} else {
			tcore_sim_get_type(co_sim, &card_type);
			dbg("[SIM DATA]SIM_EF_LP/LI(6F05) access fail. Current CardType[%d]", card_type);
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				if (resp_cb_data->cb)
					resp_cb_data->cb(co_sim, (gint)sim_result,
						&file_meta->files.data, resp_cb_data->cb_data);
				return;
			}

			/*
			 * If EFLI is not present, then the language selection
			 * shall be as defined in EFPL at the MF level
			 */
			else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
				AtmodemSimMetaInfo file_meta_new = {0,};

				dbg("[SIM DATA] try USIM EFPL(0x2F05)");
				file_meta_new.file_id = TEL_SIM_EF_ELP;
				file_meta_new.file_result = TEL_SIM_RESULT_FAILURE;
				file_meta_new.req_command = TCORE_COMMAND_SIM_GET_LANGUAGE;

				memcpy(resp_cb_data->data, &file_meta_new, sizeof(AtmodemSimMetaInfo));

				__atmodem_sim_get_file_info(co_sim, resp_cb_data);
			}
		}
	break;

	case TEL_SIM_EF_USIM_PL:
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			__atmodem_sim_get_file_data(co_sim, resp_cb_data);
		} else {
			/*
			 * EFELIand EFPL not present, so set language
			 * count as zero and select ECC
			 */
			dbg("[SIM DATA] SIM_EF_USIM_PL(2A05) access fail. "\
				"Request SIM_EF_ECC(0x6FB7) info");
			if (resp_cb_data->cb)
					resp_cb_data->cb(co_sim, (gint)sim_result,
						&file_meta->files.data, resp_cb_data->cb_data);

			return;
		}
	break;

	case TEL_SIM_EF_ECC:
		tcore_sim_get_type(co_sim, &card_type);
		if (TEL_SIM_CARD_TYPE_GSM == card_type) {
			__atmodem_sim_get_file_data(co_sim, resp_cb_data);
		} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
			if (file_meta->rec_count > TEL_SIM_ECC_LIST_MAX)
				file_meta->rec_count = TEL_SIM_ECC_LIST_MAX;

			file_meta->current_index++;
			__atmodem_sim_get_file_record(co_sim, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_ICCID:
	case TEL_SIM_EF_IMSI:
	case TEL_SIM_EF_SST:
	case TEL_SIM_EF_SPN:
	case TEL_SIM_EF_SPDI:
	case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:
	case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
	case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
	case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
	case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		__atmodem_sim_get_file_data(co_sim, resp_cb_data);
	break;

	case TEL_SIM_EF_CPHS_CPHS_INFO:
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			tcore_sim_set_cphs_status(co_sim, TRUE);
			__atmodem_sim_update_sim_status(co_sim, TEL_SIM_STATUS_SIM_INIT_COMPLETED);

			__atmodem_sim_get_file_data(co_sim, resp_cb_data);
		} else {
			tcore_sim_set_cphs_status(co_sim, FALSE);
			__atmodem_sim_update_sim_status(co_sim, TEL_SIM_STATUS_SIM_INIT_COMPLETED);

			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		}
	break;


	case TEL_SIM_EF_USIM_CFIS:
		if (file_meta->rec_count > TEL_SIM_CALL_FORWARDING_TYPE_MAX)
			file_meta->rec_count = TEL_SIM_CALL_FORWARDING_TYPE_MAX;

		file_meta->current_index++;

		__atmodem_sim_get_file_record(co_sim, resp_cb_data);
	break;

	case TEL_SIM_EF_OPL:
	case TEL_SIM_EF_PNN:
	case TEL_SIM_EF_USIM_MWIS:
	case TEL_SIM_EF_USIM_MBI:
	case TEL_SIM_EF_MBDN:
	case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:
	case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
	case TEL_SIM_EF_MSISDN:
		file_meta->current_index++;

		__atmodem_sim_get_file_record(co_sim, resp_cb_data);
	break;

	default:
		err("Unknown File ID for get File info: [0x%x]", file_meta->file_id);
	break;
	}
}

static void __on_response_atmodem_sim_get_file_data(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co_sim = NULL;
	GSList *tokens = NULL;
	TelSimResult sim_result;
	gboolean dr = FALSE;
	const char *line = NULL;
	char *res = NULL;
	char *tmp = NULL;
	int res_len;
	int sw1 = 0;
	int sw2 = 0;
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;
	AtmodemRespCbData *resp_cb_data = (AtmodemRespCbData *) user_data;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 2) {
				msg("Invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));
		res = g_slist_nth_data(tokens, 2);

		tmp = tcore_at_tok_extract(res);
		tcore_util_hexstring_to_bytes(tmp, &res, (guint *)&res_len);

		dbg("Response: [%s] Response length: [%d]", res, res_len);

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			sim_result = TEL_SIM_RESULT_SUCCESS;
			file_meta->files.result = sim_result;

			dbg("File ID: [0x%x]", file_meta->file_id);
			switch (file_meta->file_id) {
			case TEL_SIM_EF_IMSI: {
				dbg("Data: [%s]", res);
				dr = tcore_sim_decode_imsi((unsigned char *)res, res_len, &file_meta->imsi);
				if (dr == FALSE) {
					err("IMSI decoding failed");
				} else {
					/* Update IMSI */
					tcore_sim_set_imsi(co_sim, &file_meta->imsi);
				}
			}
			break;

			case TEL_SIM_EF_ICCID:
				dr = tcore_sim_decode_iccid((unsigned char *)res, res_len,
					file_meta->files.data.iccid);
			break;

			case TEL_SIM_EF_ELP:		/* 2G EF - 2 bytes decoding */
			case TEL_SIM_EF_USIM_LI:	/* 3G EF - 2 bytes decoding */
			case TEL_SIM_EF_USIM_PL:	/* 3G EF - same as EFELP, so 2 byte decoding */
			case TEL_SIM_EF_LP: 		/* 1 byte encoding */
			{
				tcore_sim_get_type(co_sim, &card_type);
				if ((TEL_SIM_CARD_TYPE_GSM == card_type)
						&& (file_meta->file_id == TEL_SIM_EF_LP)) {
					/*
					 * 2G LP(0x6F05) has 1 byte for each language
					 */
					dr = tcore_sim_decode_lp((unsigned char *)res, res_len,
						&file_meta->files.data.language);
				} else {
					/*
					 * 3G LI(0x6F05)/PL(0x2F05),
					 * 2G ELP(0x2F05) has 2 bytes for each language
					 */
					dr = tcore_sim_decode_li((unsigned char *)res, res_len,
						file_meta->file_id, &file_meta->files.data.language);
				}
			}
			break;

			case TEL_SIM_EF_SPN:
				dr = tcore_sim_decode_spn((unsigned char *)res, res_len,
					&file_meta->files.data.spn);
			break;

			case TEL_SIM_EF_SPDI:
				dr = tcore_sim_decode_spdi((unsigned char *)res, res_len,
					&file_meta->files.data.spdi);
			break;

			case TEL_SIM_EF_SST: {
				TelSimServiceTable *svct = NULL;

				svct = g_try_new0(TelSimServiceTable, 1);
				tcore_sim_get_type(co_sim, &card_type);
				svct->sim_type = card_type;
				if (TEL_SIM_CARD_TYPE_GSM == card_type) {
					dr = tcore_sim_decode_sst((unsigned char *)res, res_len,
						svct->table.sst_service);
				} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
					dr = tcore_sim_decode_ust((unsigned char *)res, res_len,
						svct->table.ust_service);
				} else {
					err("Not handled card_type[%d]", card_type);
				}

				if (dr == FALSE) {
					err("SST/UST decoding failed");
				} else {
					tcore_sim_set_service_table(co_sim, svct);
				}

				/* Free memory */
				g_free(svct);
			}
			break;

			case TEL_SIM_EF_ECC: {
				tcore_sim_get_type(co_sim, &card_type);
				if (TEL_SIM_CARD_TYPE_GSM == card_type) {
					dr = tcore_sim_decode_ecc((unsigned char *)res, res_len,
						&file_meta->files.data.ecc);
				} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
					TelSimEcc *ecc = NULL;

					ecc = g_try_new0(TelSimEcc, 1);
					dbg("Index [%d]", file_meta->current_index);

					dr = tcore_sim_decode_uecc((unsigned char *)res, res_len, ecc);
					if (dr == TRUE) {
						memcpy(&file_meta->files.data.ecc.list[file_meta->files.data.ecc.count],
							ecc, sizeof(TelSimEcc));
						file_meta->files.data.ecc.count++;
					}

					/* Free memory */
					g_free(ecc);
				} else {
					dbg("Unknown/Unsupported SIM card Type: [%d]", card_type);
				}
			}
			break;

			case TEL_SIM_EF_MSISDN: {
				TelSimSubscriberInfo *msisdn = NULL;

				dbg("Index [%d]", file_meta->current_index);
				msisdn = g_try_new0(TelSimSubscriberInfo, 1);
				dr = tcore_sim_decode_msisdn((unsigned char *)res, res_len, msisdn);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.msisdn_list.list[file_meta->files.data.msisdn_list.count],
						msisdn, sizeof(TelSimSubscriberInfo));

					file_meta->files.data.msisdn_list.count++;
				}

				/* Free memory */
				g_free(msisdn);
			}
			break;

			case TEL_SIM_EF_OPL: {
				TelSimOpl *opl = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				opl = g_try_new0(TelSimOpl, 1);

				dr = tcore_sim_decode_opl((unsigned char *)res, res_len, opl);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.opl.list[file_meta->files.data.opl.opl_count],
						opl, sizeof(TelSimOpl));

					file_meta->files.data.opl.opl_count++;
				}

				/* Free memory */
				g_free(opl);
			}
			break;

			case TEL_SIM_EF_PNN: {
				TelSimPnn *pnn = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				pnn = g_try_new0(TelSimPnn, 1);

				dr = tcore_sim_decode_pnn((unsigned char *)res, res_len, pnn);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.pnn.list[file_meta->files.data.pnn.pnn_count],
						pnn, sizeof(TelSimPnn));

					file_meta->files.data.pnn.pnn_count++;
				}

				/* Free memory */
				g_free(pnn);
			}
			break;

			case TEL_SIM_EF_OPLMN_ACT:
				/*dr = tcore_sim_decode_oplmnwact(&file_meta->files.data.opwa,
						(unsigned char *)res, res_len);*/
			break;

			case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
				/*dr = tcore_sim_decode_csp(&po->p_cphs->csp,
					p_data->response, p_data->response_len);*/
			break;

			case TEL_SIM_EF_USIM_MBI: {	/* linear type */
				TelSimMbi *mbi = NULL;

				mbi = g_try_new0(TelSimMbi, 1);
				dr = tcore_sim_decode_mbi((unsigned char *)res, res_len, mbi);
				if (dr == TRUE) {
					memcpy(&file_meta->mbi_list.list[file_meta->mbi_list.count],
										mbi, sizeof(TelSimMbi));
					file_meta->mbi_list.count++;

					dbg("mbi count[%d]", file_meta->mbi_list.count);
				}

				/* Free memory */
				g_free(mbi);
			}
			break;

			case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:	/* linear type */
			case TEL_SIM_EF_MBDN:			/* linear type */
				dr = tcore_sim_decode_xdn((unsigned char *)res, res_len,
					file_meta->mb_list[file_meta->current_index-1].alpha_id,
					file_meta->mb_list[file_meta->current_index-1].number);

				file_meta->mb_list[file_meta->current_index-1].alpha_id_len =
					strlen(file_meta->mb_list[file_meta->current_index-1].alpha_id);

				file_meta->mb_list[file_meta->current_index-1].profile_id =
					file_meta->current_index;
			break;

			case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:	/* transparent type */
				dr = tcore_sim_decode_vmwf((unsigned char *)res, res_len,
					file_meta->files.data.mw.mw);
			break;

			case TEL_SIM_EF_USIM_MWIS: {	/* linear type */
				TelSimMwis *mw = NULL;

				mw = g_try_new0(TelSimMwis, 1);

				dr = tcore_sim_decode_mwis((unsigned char *)res, res_len, mw);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.mw.mw[file_meta->files.data.mw.profile_count],
						mw, sizeof(TelSimMwis));

					file_meta->files.data.mw.profile_count++;
				}

				/* Free memory */
				g_free(mw);
			}
			break;

			case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:	/* transparent type */
				dr = tcore_sim_decode_cff((unsigned char *)res, res_len,
					file_meta->files.data.mw.mw);
			break;

			case TEL_SIM_EF_USIM_CFIS:	/* linear type */
			{
				TelSimCfis *cf = NULL;

				cf = g_try_new0(TelSimCfis, 1);
				dr = tcore_sim_decode_cfis((unsigned char *)res, res_len, cf);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.cf.cf[file_meta->files.data.cf.profile_count],
						cf, sizeof(TelSimCfis));

					file_meta->files.data.cf.profile_count++;
				}

				/* Free memory */
				g_free(cf);
			}
			break;

			case TEL_SIM_EF_CPHS_SERVICE_STRING_TABLE:
				dbg("not handled - TEL_SIM_EF_CPHS_SERVICE_STRING_TABLE ");
			break;

			case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
				dr = tcore_sim_decode_ons((unsigned char *)res, res_len,
					(unsigned char*)&file_meta->files.data.cphs_net.full_name);
				dbg("file_meta->files.result: [%d] " \
					"file_meta->files.data.cphs_net.full_name[%s]",
					file_meta->files.result,
					file_meta->files.data.cphs_net.full_name);
			break;

			case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
				/*dr = tcore_sim_decode_dynamic_flag(&po->p_cphs->dflagsinfo,
					p_data->response, p_data->response_len);*/
			break;

			case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
				/*dr = tcore_sim_decode_dynamic2_flag(&po->p_cphs->d2flagsinfo,
					p_data->response, p_data->response_len);*/
			break;

			case TEL_SIM_EF_CPHS_CPHS_INFO:
				/*dr = tcore_sim_decode_cphs_info(&file_meta->files.data.cphs,
					(unsigned char *)res, res_len);*/
			break;

			case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
				dr = tcore_sim_decode_short_ons((unsigned char *)res, res_len,
					(unsigned char*)&file_meta->files.data.cphs_net.short_name);

				dbg("file_meta->files.result[%d] "\
					"file_meta->files.data.cphs_net.short_name[%s]",
					file_meta->files.result,
					file_meta->files.data.cphs_net.short_name);
			break;

			case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
				/*dr = tcore_sim_decode_information_number(&po->p_cphs->infn,
					p_data->response, p_data->response_len);*/
			break;

			default:
				dbg("File Decoding Failed - not handled File[0x%x]",
					file_meta->file_id);
				dr = 0;
			break;
			}
		} else {
			sim_result = __atmodem_sim_decode_status_word(sw1, sw2);
			file_meta->files.result = sim_result;
		}

		/* Free memory */
		g_free(tmp);
		g_free(res);

		/* Free tokens */
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOK");
		dbg("Error - File ID: [0x%x]", file_meta->file_id);
		sim_result = TEL_SIM_RESULT_FAILURE;
	}

	/* Get File data */
	__atmodem_sim_next_from_get_file_data(tcore_pending_ref_core_object(p),
		resp_cb_data, sim_result, dr);

	dbg("Exit");
}

static void __on_response_atmodem_sim_get_file_info(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co_sim = NULL;
	TelSimResult sim_result;
	GSList *tokens = NULL;
	const char *line = NULL;
	int sw1 = 0;
	int sw2 = 0;
	AtmodemRespCbData *resp_cb_data = (AtmodemRespCbData *)user_data;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("SIM Response - SIM File info: [+CRSM]");

	co_sim = tcore_pending_ref_core_object(p);

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
			guint buf_len = 0;
			TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

			/* handling only last 3 bits */
			unsigned char file_type_tag = 0x07;
			unsigned char *ptr_data;

			char *hexData;
			char *tmp;
			char *record_data = NULL;
			hexData = g_slist_nth_data(tokens, 2);
			dbg("hexData: %s", hexData);
			dbg("hexData: %s", hexData + 1);

			tmp = tcore_at_tok_extract(hexData);
			tcore_util_hexstring_to_bytes(tmp, &record_data, &buf_len); /*TODO : Check*/
			tcore_util_hex_dump("   ", buf_len, record_data);
			g_free(tmp);

			ptr_data = (unsigned char *)record_data;
			tcore_sim_get_type(co_sim, &card_type);
			if (TEL_SIM_CARD_TYPE_USIM == card_type) {
				/*
				 ETSI TS 102 221 v7.9.0
				 - Response Data
				 '62'	FCP template tag
				 - Response for an EF
				 '82'	M	File Descriptor
				 '83'	M	File Identifier
				 'A5'	O	Proprietary information
				 '8A'	M	Life Cycle Status Integer
				 '8B', '8C' or 'AB' C1	Security attributes
				 '80'	M	File size
				 '81'	O	Total file size
				 '88'	O	Short File Identifier (SFI)
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
							file_type = ATMODEM_SIM_FILE_TYPE_TRANSPARENT;

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
							ATMODEM_SWAP_BYTES_16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							/* Data lossy conversation from enum (int) to unsigned char */
							file_type = ATMODEM_SIM_FILE_TYPE_LINEAR_FIXED;
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
							ATMODEM_SWAP_BYTES_16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							file_type = ATMODEM_SIM_FILE_TYPE_CYCLIC;
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
						ATMODEM_SWAP_BYTES_16(file_id);
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
							ATMODEM_SWAP_BYTES_16(arr_file_id);
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
						ATMODEM_SWAP_BYTES_16(file_size);
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
			} else if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				unsigned char gsm_specific_file_data_len = 0;
				/* ignore RFU byte1 and byte2 */
				ptr_data++;
				ptr_data++;
				/* file size */
				// file_size = p_info->response_len;
				memcpy(&file_size, ptr_data, 2);
				/* swap bytes */
				ATMODEM_SWAP_BYTES_16(file_size);
				/* parsed file size */
				ptr_data = ptr_data + 2;
				/* file id */
				memcpy(&file_id, ptr_data, 2);
				ATMODEM_SWAP_BYTES_16(file_id);
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
							(file_type_tag == 0x00) ? ATMODEM_SIM_FILE_TYPE_TRANSPARENT : ATMODEM_SIM_FILE_TYPE_LINEAR_FIXED;
					} else {
						/* increment to next byte */
						ptr_data++;
						/* For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
						/* the INCREASE command is allowed on the selected cyclic file. */
						file_type = ATMODEM_SIM_FILE_TYPE_CYCLIC;
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

			dbg("req ef[0x%x] resp ef[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]",
				file_meta->file_id, file_id, file_size, file_type, num_of_records, record_len);

			file_meta->file_type = file_type;
			file_meta->data_size = file_size;
			file_meta->rec_length = record_len;
			file_meta->rec_count = num_of_records;
			file_meta->current_index = 0;		/* reset for new record type EF */
			sim_result = TEL_SIM_RESULT_SUCCESS;
			g_free(record_data);
		} else {
			/*2. SIM access fail case*/
			err("Failed to get ef[0x%x] (file_meta->file_id) ", file_meta->file_id);
			sim_result = __atmodem_sim_decode_status_word(sw1, sw2);
		}

		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");
		err("Failed to get ef[0x%x] (file_meta->file_id) ", file_meta->file_id);
		sim_result = TEL_SIM_RESULT_FAILURE;
	}
	dbg("Calling __atmodem_sim_next_from_get_file_info");
	__atmodem_sim_next_from_get_file_info(co_sim, resp_cb_data, sim_result);
	dbg("Exit");
}

static void __atmodem_sim_get_file_record(CoreObject *co_sim, AtmodemRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	/* According to TS 102 221, values of p1, p2, p3 can be as below:
	 * 11.1.5 READ RECORD
	 * P1: Record number
	 * P2: Mode, see table 11.11
	 * Lc: Not present
	 * Data: Not present
	 * Le: Number of bytes to be read (P3)
	 */

	p1 = (unsigned char) file_meta->current_index;
	p2 = (unsigned char) 0x04;			/* 0x4 for absolute mode */
	p3 = (unsigned char) file_meta->rec_length;

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d",
				ATMODEM_SIM_ACCESS_READ_RECORD, file_meta->file_id);

	ret = tcore_at_prepare_and_send_request(co_sim,
		at_cmd, "+CRSM:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_atmodem_sim_get_file_data, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Record");

	dbg("ret:[%d]", ret);
	g_free(at_cmd);

	dbg("Exit");
}

static void __atmodem_sim_get_file_data(CoreObject *co_sim,
	AtmodemRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;
	int offset = 0;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	/*
	 * According to TS 102 221, values of P1, P2, P3 can be as below:
	 * 11.1.3 READ BINARY
	 * P1: See table 11.10
	 * P2: Offset low
	 * Lc: Not present
	 * Data: Not present
	 * Le: Number of bytes to be read (P3)
	 */

	p1 = (unsigned char) (offset & 0xFF00) >> 8;
	p2 = (unsigned char) offset & 0x00FF;			/* offset low */
	p3 = (unsigned char) file_meta->data_size;

	if (file_meta->file_id == TEL_SIM_EF_IMSI
		|| file_meta->file_id == TEL_SIM_EF_SPN
		|| file_meta->file_id == TEL_SIM_EF_LP)
		at_cmd = g_strdup_printf("AT+CRSM=%d, %d ",
					ATMODEM_SIM_ACCESS_READ_BINARY, file_meta->file_id);
	else
		at_cmd = g_strdup_printf("AT+CRSM=%d, %d, %d, %d, %d",
					ATMODEM_SIM_ACCESS_READ_BINARY, file_meta->file_id, p1, p2, p3);

	ret = tcore_at_prepare_and_send_request(co_sim,
		at_cmd, "+CRSM:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_atmodem_sim_get_file_data, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Data");

	dbg("ret:[%d]", ret);
	g_free(at_cmd);

	dbg("Exit");
}

static TelReturn __atmodem_sim_get_file_info(CoreObject *co_sim,
	AtmodemRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d",
		ATMODEM_SIM_ACCESS_GET_RESPONSE, file_meta->file_id);

	ret = tcore_at_prepare_and_send_request(co_sim,
		at_cmd, "+CRSM:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_atmodem_sim_get_file_info, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Info");

	g_free(at_cmd);
	dbg("Exit");
	return ret;
}

static char *__atmodem_sim_get_fac_from_lock_type(TelSimLockType lock_type,
	AtmodemSimCurrSecOp *sec_op, int flag)
{
	char *fac = NULL;
	switch(lock_type) {
	case TEL_SIM_LOCK_PS:
		fac = "PS";
		if (flag == ENABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_SIM_ENABLE;
		else if (flag == DISABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_SIM_DISABLE;
		else
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_SIM_STATUS;
	break;

	case TEL_SIM_LOCK_SC:
		fac = "SC";
		if (flag == ENABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_PIN1_ENABLE;
		else if (flag == DISABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_PIN1_DISABLE;
		else
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_PIN1_STATUS;
	break;

	case TEL_SIM_LOCK_FD:
		fac = "FD";
		if (flag == ENABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_FDN_ENABLE;
		else if (flag == DISABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_FDN_DISABLE;
		else
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_FDN_STATUS;
	break;

	case TEL_SIM_LOCK_PN:
		fac = "PN";
		if (flag == ENABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_NET_ENABLE;
		else if (flag == DISABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_NET_DISABLE;
		else
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_NET_STATUS;
	break;

	case TEL_SIM_LOCK_PU:
		fac = "PU";
		if (flag == ENABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_NS_ENABLE;
		else if (flag == DISABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_NS_DISABLE;
		else
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_NS_STATUS;
	break;

	case TEL_SIM_LOCK_PP:
		fac = "PP";
		if (flag == ENABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_SP_ENABLE;
		else if (flag == DISABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_SP_DISABLE;
		else
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_SP_STATUS;
	break;

	case TEL_SIM_LOCK_PC:
		fac = "PC";
		if (flag == ENABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_CP_ENABLE;
		else if (flag == DISABLE_FLAG)
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_CP_DISABLE;
		else
			*sec_op = ATMODEM_SIM_CURR_SEC_OP_CP_STATUS;
	break;

	default:
		err("Unhandled sim lock type [%d]", lock_type);
	}

	return fac;
}

static void __atmodem_sim_next_from_read_binary(CoreObject *co,
	AtmodemRespCbData *resp_cb_data, TelSimResult sim_result, gboolean decode_ret)
{
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

	dbg("Entry");

	dbg("[SIM]EF[0x%x] read sim_result[%d] Decode rt[%d]",
		file_meta->file_id, sim_result, decode_ret);
	switch (file_meta->file_id) {
	case TEL_SIM_EF_ELP:
	case TEL_SIM_EF_USIM_PL:
	case TEL_SIM_EF_LP:
	case TEL_SIM_EF_USIM_LI:
		if (decode_ret == TRUE) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			tcore_sim_get_type(co, &card_type);
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
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				if (file_meta->file_id == TEL_SIM_EF_LP) {
					if (resp_cb_data->cb)
						resp_cb_data->cb(co, (gint)sim_result,
							&file_meta->files.data, resp_cb_data->cb_data);
				} else {
					file_meta->file_id = TEL_SIM_EF_LP;
					__atmodem_sim_get_response(co, resp_cb_data);
				}
			} else if (TEL_SIM_CARD_TYPE_USIM) {
				if (file_meta->file_id == TEL_SIM_EF_LP
						|| file_meta->file_id == TEL_SIM_EF_USIM_LI) {
					file_meta->file_id = TEL_SIM_EF_ELP;
					__atmodem_sim_get_response(co, resp_cb_data);
				} else {
					if (resp_cb_data->cb)
						resp_cb_data->cb(co, (gint)sim_result,
							&file_meta->files.data, resp_cb_data->cb_data);
				}
			}
		}
	break;

	case TEL_SIM_EF_ECC:
		tcore_sim_get_type(co, &card_type);
		if (TEL_SIM_CARD_TYPE_USIM == card_type) {
			if (file_meta->current_index == file_meta->rec_count) {
				if (resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)sim_result,
						&file_meta->files.data, resp_cb_data->cb_data);
			} else {
				file_meta->current_index++;
				__atmodem_sim_read_record(co, resp_cb_data);
			}
		} else if (TEL_SIM_CARD_TYPE_GSM == card_type) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			dbg("[SIM DATA]Invalid CardType[%d] Unable to handle", card_type);
		}
	break;

	case TEL_SIM_EF_IMSI:
		__atmodem_sim_update_sim_status(co, TEL_SIM_STATUS_SIM_INIT_COMPLETED);
	break;

	case TEL_SIM_EF_MSISDN:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__atmodem_sim_read_record(co, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_OPL:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__atmodem_sim_read_record(co, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_PNN:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__atmodem_sim_read_record(co, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_USIM_CFIS:
	case TEL_SIM_EF_USIM_MWIS:
	case TEL_SIM_EF_USIM_MBI:
	case TEL_SIM_EF_MBDN:
	case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:
	case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__atmodem_sim_read_record(co, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
	{
		file_meta->files.result = sim_result;
		if (decode_ret == TRUE && sim_result == TEL_SIM_RESULT_SUCCESS) {
			memcpy(file_meta->files.data.cphs_net.full_name,
				file_meta->files.data.cphs_net.full_name,
				strlen((char *)file_meta->files.data.cphs_net.full_name));
		}

		file_meta->file_id = TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING;
		file_meta->file_result = TEL_SIM_RESULT_FAILURE;
		__atmodem_sim_get_response(co, resp_cb_data);
	}
	break;

	case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
		if (file_meta->files.result == TEL_SIM_RESULT_SUCCESS) {
			file_meta->files.result = TEL_SIM_RESULT_SUCCESS;
		}
		if (strlen((char *)file_meta->files.data.cphs_net.full_name)) {
			memcpy(&file_meta->files.data.cphs_net.full_name,
				&file_meta->files.data.cphs_net.full_name,
				strlen((char *)file_meta->files.data.cphs_net.full_name));
		}
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)sim_result,
				&file_meta->files.data, resp_cb_data->cb_data);
	break;

	case TEL_SIM_EF_ICCID:
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)sim_result,
				&file_meta->files.data.iccid, resp_cb_data->cb_data);
	break;

	case TEL_SIM_EF_SST:
	case TEL_SIM_EF_SPN:
	case TEL_SIM_EF_SPDI:
	case TEL_SIM_EF_OPLMN_ACT:
	case TEL_SIM_EF_CPHS_CPHS_INFO:
	case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:
	case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
	case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)sim_result,
				&file_meta->files.data, resp_cb_data->cb_data);
	break;

	default:
		err("File id not handled [0x%x]", file_meta->file_id);
	break;
	}
}

static void __atmodem_sim_next_from_get_response(CoreObject *co,
	AtmodemRespCbData *resp_cb_data, TelSimResult sim_result)
{
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

	dbg("EF[0x%x] access Result[%d]", file_meta->file_id, sim_result);

	file_meta->files.result = sim_result;
	memset(&file_meta->files.data, 0x00, sizeof(file_meta->files.data));

	if ((file_meta->file_id != TEL_SIM_EF_ELP
			&& file_meta->file_id != TEL_SIM_EF_LP
			&& file_meta->file_id != TEL_SIM_EF_USIM_PL
			&& file_meta->file_id != TEL_SIM_EF_CPHS_CPHS_INFO)
			&& (sim_result != TEL_SIM_RESULT_SUCCESS)) {
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)sim_result,
				&file_meta->files.data, resp_cb_data->cb_data);

		return;
	}

	switch (file_meta->file_id) {
	case TEL_SIM_EF_ELP: {
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			__atmodem_sim_read_binary(co, resp_cb_data);
		} else {
			tcore_sim_get_type(co, &card_type);
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				AtmodemSimMetaInfo file_meta_new = {0,};

				dbg("[SIM DATA]SIM_EF_ELP(2F05) access fail. Request SIM_EF_LP(0x6F05) info");
				/* The ME requests the Language Preference (EFLP) if EFELP is not available */
				file_meta_new.file_id = TEL_SIM_EF_LP;
				file_meta_new.file_result = TEL_SIM_RESULT_FAILURE;
				file_meta_new.req_command = TCORE_COMMAND_SIM_GET_LANGUAGE;

				memcpy(resp_cb_data->data, &file_meta_new, sizeof(AtmodemSimMetaInfo));

				__atmodem_sim_get_response(co, resp_cb_data);
			} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
				dbg(" [SIM DATA]fail to get Language information "\
					"in USIM(EF-LI(6F05),EF-PL(2F05))");
				if (resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)sim_result,
						&file_meta->files.data, resp_cb_data->cb_data);
				return;
			}
		}
	}
	break;

	case TEL_SIM_EF_LP: {
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFLP/LI(0x6F05)");
			__atmodem_sim_read_binary(co, resp_cb_data);
		} else {
			tcore_sim_get_type(co, &card_type);
			dbg("[SIM DATA]SIM_EF_LP/LI(6F05) access fail. Current CardType[%d]", card_type);
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				if (resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)sim_result,
						&file_meta->files.data, resp_cb_data->cb_data);
				return;
			}
			/*
			 * If EFLI is not present, then the language selection
			 * shall be as defined in EFPL at the MF level
			 */
			else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
				AtmodemSimMetaInfo file_meta_new = {0,};

				dbg("[SIM DATA] try USIM EFPL(0x2F05)");
				file_meta_new.file_id = TEL_SIM_EF_ELP;
				file_meta_new.file_result = TEL_SIM_RESULT_FAILURE;
				file_meta_new.req_command = TCORE_COMMAND_SIM_GET_LANGUAGE;

				memcpy(resp_cb_data->data, &file_meta_new, sizeof(AtmodemSimMetaInfo));

				__atmodem_sim_get_response(co, resp_cb_data);
			}
		}
	}
	break;

	case TEL_SIM_EF_USIM_PL: {
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			__atmodem_sim_read_binary(co, resp_cb_data);
		} else {
			/*
			 * EFELIand EFPL not present, so set language count
			 * as zero and select ECC
			 */
			dbg("[SIM DATA]SIM_EF_USIM_PL(2A05) access fail. "\
				"Request SIM_EF_ECC(0x6FB7) info");
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);

			return;
		}
	}
	break;

	case TEL_SIM_EF_ECC: {
		tcore_sim_get_type(co, &card_type);
		if (TEL_SIM_CARD_TYPE_GSM == card_type) {
			__atmodem_sim_read_binary(co, resp_cb_data);
		} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
			if (file_meta->rec_count > TEL_SIM_ECC_LIST_MAX)
				file_meta->rec_count = TEL_SIM_ECC_LIST_MAX;

			file_meta->current_index++;
			__atmodem_sim_read_record(co, resp_cb_data);
		}
	}
	break;

	case TEL_SIM_EF_ICCID:
	case TEL_SIM_EF_IMSI:
	case TEL_SIM_EF_SST:
	case TEL_SIM_EF_SPN:
	case TEL_SIM_EF_SPDI:
	case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:
	case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
	case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
	case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
	case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		__atmodem_sim_read_binary(co, resp_cb_data);
	break;

	case TEL_SIM_EF_CPHS_CPHS_INFO: {
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			tcore_sim_set_cphs_status(co, TRUE);
			__atmodem_sim_update_sim_status(co, TEL_SIM_STATUS_SIM_INIT_COMPLETED);

			__atmodem_sim_read_binary(co, resp_cb_data);
		} else {
			tcore_sim_set_cphs_status(co, FALSE);
			__atmodem_sim_update_sim_status(co, TEL_SIM_STATUS_SIM_INIT_COMPLETED);

			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data, resp_cb_data->cb_data);
		}
	}
	break;


	case TEL_SIM_EF_USIM_CFIS: {
		if (file_meta->rec_count > TEL_SIM_CALL_FORWARDING_TYPE_MAX)
			file_meta->rec_count = TEL_SIM_CALL_FORWARDING_TYPE_MAX;

		file_meta->current_index++;
		__atmodem_sim_read_record(co, resp_cb_data);
	}
	break;

	case TEL_SIM_EF_OPL:
	case TEL_SIM_EF_PNN:
	case TEL_SIM_EF_USIM_MWIS:
	case TEL_SIM_EF_USIM_MBI:
	case TEL_SIM_EF_MBDN:
	case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:
	case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
	case TEL_SIM_EF_MSISDN:
		file_meta->current_index++;
		__atmodem_sim_read_record(co, resp_cb_data);
	break;

	case TEL_SIM_EF_SMSP: {
		AtmodemSimPrivateInfo *priv_info = NULL;

		priv_info = tcore_sim_ref_userdata(co);

		dbg("SMSP info set to tcore : count:[%d], rec_len:[%d]",
			file_meta->rec_count, file_meta->rec_length);
		priv_info->smsp_count = file_meta->rec_count;
		priv_info->smsp_rec_len = file_meta->rec_length;
	}
	break;

	default:
		dbg("error - File id for get file info [0x%x]", file_meta->file_id);
	break;
	}
	return;
}

#if 0 //blocking for the moment
static void __on_response_atmodem_sim_update_file(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co_sim = NULL;
	GSList *tokens = NULL;
	TelSimResult sim_result = TEL_SIM_RESULT_CARD_ERROR;
	const char *line;
	AtmodemRespCbData *resp_cb_data = (AtmodemRespCbData *)user_data;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);

	dbg("file_id:[0x%x]", file_meta->file_id);

	if (resp->success > 0) {
		int sw1 = 0;
		int sw2 = 0;
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 2) {
				err("Invalid message");
				goto out;
			}
			sw1 = atoi(g_slist_nth_data(tokens, 0));
			sw2 = atoi(g_slist_nth_data(tokens, 1));
		}

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			sim_result = TEL_SIM_RESULT_SUCCESS;
		} else {
			sim_result = __atmodem_sim_decode_status_word(sw1, sw2);
		}
	} else {
		err("RESPONSE NOK");
		sim_result = TEL_SIM_RESULT_FAILURE;
	}
out:
	/* Send Response */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co_sim, (gint)sim_result,
			NULL, resp_cb_data->cb_data);

	tcore_at_tok_free(tokens);
	dbg("Exit");
}
#endif

static void __on_response_atmodem_sim_read_data(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co = NULL;
	GSList *tokens = NULL;
	TelSimResult sim_result;
	gboolean dr = FALSE;
	const char *line = NULL;
	char *res = NULL;
	char *tmp = NULL;
	guint res_len;
	int sw1 = 0;
	int sw2 = 0;
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;
	AtmodemRespCbData *resp_cb_data = (AtmodemRespCbData *) user_data;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Entry");

	co = tcore_pending_ref_core_object(p);

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
		tcore_util_hexstring_to_bytes(tmp, &res, &res_len);
		dbg("Response: [%s] Response length: [%d]", res, res_len);

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			sim_result = TEL_SIM_RESULT_SUCCESS;
			file_meta->files.result = sim_result;

			dbg("File ID: [0x%x]", file_meta->file_id);
			switch (file_meta->file_id) {
			case TEL_SIM_EF_IMSI: {
				dbg("Data: [%s]", res);
				dr = tcore_sim_decode_imsi((unsigned char *)res,
					res_len, &file_meta->imsi);
				if (dr == FALSE) {
					err("IMSI decoding failed");
				} else {
					__atmodem_sim_set_identity(co, &file_meta->imsi);

					/* Update IMSI */
					tcore_sim_set_imsi(co, &file_meta->imsi);
				}
			}
			break;

			case TEL_SIM_EF_ICCID: {
				dr = tcore_sim_decode_iccid((unsigned char *)res, res_len,
					file_meta->files.data.iccid);
			}
			break;

			case TEL_SIM_EF_ELP:		/* 2G EF - 2 bytes decoding */
			case TEL_SIM_EF_USIM_LI:	/* 3G EF - 2 bytes decoding */
			case TEL_SIM_EF_USIM_PL:	/* 3G EF - same as EFELP, so 2 byte decoding */
			case TEL_SIM_EF_LP: 		/* 1 byte encoding */
			{
				tcore_sim_get_type(co, &card_type);
				if ((TEL_SIM_CARD_TYPE_GSM == card_type)
						&& (file_meta->file_id == TEL_SIM_EF_LP)) {
					/*
					 * 2G LP(0x6F05) has 1 byte for each language
					 */
					dr = tcore_sim_decode_lp((unsigned char *)res,
						res_len, &file_meta->files.data.language);
				} else {
					/*
					 * 3G LI(0x6F05)/PL(0x2F05),
					 * 2G ELP(0x2F05) has 2 bytes for each language
					 */
					dr = tcore_sim_decode_li((unsigned char *)res, res_len,
						file_meta->file_id, &file_meta->files.data.language);
				}
			}
			break;

			case TEL_SIM_EF_SPN:
				dr = tcore_sim_decode_spn((unsigned char *)res,
					res_len, &file_meta->files.data.spn);
			break;

			case TEL_SIM_EF_SPDI:
				dr = tcore_sim_decode_spdi((unsigned char *)res,
					res_len, &file_meta->files.data.spdi);
			break;

			case TEL_SIM_EF_SST: {
				TelSimServiceTable *svct = NULL;

				svct = g_try_new0(TelSimServiceTable, 1);
				tcore_sim_get_type(co, &card_type);
				svct->sim_type = card_type;
				if (TEL_SIM_CARD_TYPE_GSM == card_type) {
					dr = tcore_sim_decode_sst((unsigned char *)res,
						res_len, svct->table.sst_service);
				} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
					dr = tcore_sim_decode_ust((unsigned char *)res,
						res_len, svct->table.ust_service);
				} else {
					err("Not handled card_type[%d]", card_type);
				}

				if (dr == FALSE) {
					err("SST/UST decoding failed");
				} else {
					tcore_sim_set_service_table(co, svct);
				}

				/* Free memory */
				g_free(svct);
			}
			break;

			case TEL_SIM_EF_ECC: {
				tcore_sim_get_type(co, &card_type);
				if (TEL_SIM_CARD_TYPE_GSM == card_type) {
					dr = tcore_sim_decode_ecc((unsigned char *)res,
						res_len, &file_meta->files.data.ecc);
				} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
					TelSimEcc *ecc = NULL;

					ecc = g_try_new0(TelSimEcc, 1);
					dbg("Index [%d]", file_meta->current_index);

					dr = tcore_sim_decode_uecc((unsigned char *)res, res_len, ecc);
					if (dr == TRUE) {
						memcpy(&file_meta->files.data.ecc.list[file_meta->files.data.ecc.count],
							ecc, sizeof(TelSimEcc));
						file_meta->files.data.ecc.count++;
					}

					/* Free memory */
					g_free(ecc);
				} else {
					dbg("Unknown/Unsupported SIM card Type: [%d]", card_type);
				}
			}
			break;

			case TEL_SIM_EF_MSISDN: {
				TelSimSubscriberInfo *msisdn = NULL;

				dbg("Index [%d]", file_meta->current_index);
				msisdn = g_try_new0(TelSimSubscriberInfo, 1);
				dr = tcore_sim_decode_msisdn((unsigned char *)res, res_len, msisdn);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.msisdn_list.list[file_meta->files.data.msisdn_list.count],
						msisdn, sizeof(TelSimSubscriberInfo));

					file_meta->files.data.msisdn_list.count++;
				}

				/* Free memory */
				g_free(msisdn);
			}
			break;

			case TEL_SIM_EF_OPL: {
				TelSimOpl *opl = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				opl = g_try_new0(TelSimOpl, 1);

				dr = tcore_sim_decode_opl((unsigned char *)res, res_len, opl);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.opl.list[file_meta->files.data.opl.opl_count],
							opl, sizeof(TelSimOpl));

					file_meta->files.data.opl.opl_count++;
				}

				/* Free memory */
				g_free(opl);
			}
			break;

			case TEL_SIM_EF_PNN: {
				TelSimPnn *pnn = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				pnn = g_try_new0(TelSimPnn, 1);

				dr = tcore_sim_decode_pnn((unsigned char *)res, res_len, pnn);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.pnn.list[file_meta->files.data.pnn.pnn_count],
						pnn, sizeof(TelSimPnn));

					file_meta->files.data.pnn.pnn_count++;
				}

				/* Free memory */
				g_free(pnn);
			}
			break;

			case TEL_SIM_EF_OPLMN_ACT:
				/*dr = tcore_sim_decode_oplmnwact(&file_meta->files.data.opwa,
					(unsigned char *)res, res_len);*/
			break;

			case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
				/*dr = tcore_sim_decode_csp(&po->p_cphs->csp,
					p_data->response, p_data->response_len);*/
			break;

			case TEL_SIM_EF_USIM_MBI: {	/* linear type */
				TelSimMbi *mbi = NULL;

				mbi = g_try_new0(TelSimMbi, 1);
				dr = tcore_sim_decode_mbi((unsigned char *)res, res_len, mbi);
				if (dr == TRUE) {
					memcpy(&file_meta->mbi_list.list[file_meta->mbi_list.count],
						mbi, sizeof(TelSimMbi));
					file_meta->mbi_list.count++;

					dbg("mbi count[%d]", file_meta->mbi_list.count);
				}

				/* Free memory */
				g_free(mbi);
			}
			break;

			case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:	/* linear type */
			case TEL_SIM_EF_MBDN:			/* linear type */
				dr = tcore_sim_decode_xdn((unsigned char *)res, res_len,
					file_meta->mb_list[file_meta->current_index-1].alpha_id,
					file_meta->mb_list[file_meta->current_index-1].number);
				file_meta->mb_list[file_meta->current_index-1].alpha_id_len =
					strlen(file_meta->mb_list[file_meta->current_index-1].alpha_id);
				file_meta->mb_list[file_meta->current_index-1].profile_id =
					file_meta->current_index;
			break;

			case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:	/* transparent type */
				dr = tcore_sim_decode_vmwf((unsigned char *)res,
					res_len, file_meta->files.data.mw.mw);
			break;

			case TEL_SIM_EF_USIM_MWIS: {	/* linear type */
				TelSimMwis *mw = NULL;

				mw = g_try_new0(TelSimMwis, 1);

				dr = tcore_sim_decode_mwis((unsigned char *)res, res_len, mw);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.mw.mw[file_meta->files.data.mw.profile_count],
						mw, sizeof(TelSimMwis));
					file_meta->files.data.mw.profile_count++;
				}

				/* Free memory */
				g_free(mw);
			}
			break;

			case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:	/* transparent type */
				dr = tcore_sim_decode_cff((unsigned char *)res,
					res_len, file_meta->files.data.mw.mw);
			break;

			case TEL_SIM_EF_USIM_CFIS: {	/* linear type */
				TelSimCfis *cf = NULL;

				cf = g_try_new0(TelSimCfis, 1);
				dr = tcore_sim_decode_cfis((unsigned char *)res, res_len, cf);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.cf.cf[file_meta->files.data.cf.profile_count],
						cf, sizeof(TelSimCfis));
					file_meta->files.data.cf.profile_count++;
				}

				/* Free memory */
				g_free(cf);
			}
			break;

			case TEL_SIM_EF_CPHS_SERVICE_STRING_TABLE:
				dbg("not handled - TEL_SIM_EF_CPHS_SERVICE_STRING_TABLE ");
			break;

			case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
				dr = tcore_sim_decode_ons((unsigned char *)res,
					res_len,
					(unsigned char*)&file_meta->files.data.cphs_net.full_name);
				dbg("file_meta->files.result[%d],file_meta->files.data.cphs_net.full_name[%s]",
					file_meta->files.result, file_meta->files.data.cphs_net.full_name);
			break;

			case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
				/*dr = tcore_sim_decode_dynamic_flag(&po->p_cphs->dflagsinfo,
					p_data->response, p_data->response_len);*/
			break;

			case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
				/*dr = tcore_sim_decode_dynamic2_flag(&po->p_cphs->d2flagsinfo, p_data->response,
					p_data->response_len);*/
			break;

			case TEL_SIM_EF_CPHS_CPHS_INFO:
				/*dr = tcore_sim_decode_cphs_info(&file_meta->files.data.cphs,
					(unsigned char *)res, res_len);*/
			break;

			case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
				dr = tcore_sim_decode_short_ons((unsigned char *)res, res_len,
					(unsigned char*)&file_meta->files.data.cphs_net.short_name);
				dbg("file_meta->files.result[%d],file_meta->files.data.cphs_net.short_name[%s]",
					file_meta->files.result, file_meta->files.data.cphs_net.short_name);
			break;

			case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
				/*dr = tcore_sim_decode_information_number(&po->p_cphs->infn,
					p_data->response, p_data->response_len);*/
			break;

			default:
				dbg("File Decoding Failed - not handled File[0x%x]", file_meta->file_id);
				dr = 0;
			break;
			}
		} else {
			sim_result = __atmodem_sim_decode_status_word(sw1, sw2);
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
		sim_result = TEL_SIM_RESULT_FAILURE;
	}

	/* Get File data */
	__atmodem_sim_next_from_read_binary(tcore_pending_ref_core_object(p),
		resp_cb_data, sim_result, dr);

	dbg("Exit");
}

static void __on_response_atmodem_sim_get_response(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co = NULL;
	TelSimResult sim_result;
	GSList *tokens = NULL;
	const char *line = NULL;
	int sw1 = 0;
	int sw2 = 0;
	AtmodemRespCbData *resp_cb_data = (AtmodemRespCbData *)user_data;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("SIM Response - SIM File info: [+CRSM]");

	co = tcore_pending_ref_core_object(p);

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
			TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

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
			tcore_util_hexstring_to_bytes(tmp, &record_data, &record_data_len);
			tcore_util_hex_dump("   ", record_data_len, record_data);
			g_free(tmp);

			ptr_data = (unsigned char *)record_data;
			tcore_sim_get_type(co, &card_type);
			if (TEL_SIM_CARD_TYPE_USIM == card_type) {
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
							file_type = ATMODEM_SIM_FILE_TYPE_TRANSPARENT;

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
							ATMODEM_SWAP_BYTES_16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							/* Data lossy conversation from enum (int) to unsigned char */
							file_type = ATMODEM_SIM_FILE_TYPE_LINEAR_FIXED;
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
							ATMODEM_SWAP_BYTES_16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							file_type = ATMODEM_SIM_FILE_TYPE_CYCLIC;
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
						ATMODEM_SWAP_BYTES_16(file_id);
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
							ATMODEM_SWAP_BYTES_16(arr_file_id);
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
						ATMODEM_SWAP_BYTES_16(file_size);
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
			} else if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				unsigned char gsm_specific_file_data_len = 0;
				/* ignore RFU byte1 and byte2 */
				ptr_data++;
				ptr_data++;
				/* file size */
				// file_size = p_info->response_len;
				memcpy(&file_size, ptr_data, 2);
				/* swap bytes */
				ATMODEM_SWAP_BYTES_16(file_size);
				/* parsed file size */
				ptr_data = ptr_data + 2;
				/* file id */
				memcpy(&file_id, ptr_data, 2);
				ATMODEM_SWAP_BYTES_16(file_id);
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
							(file_type_tag == 0x00) ? ATMODEM_SIM_FILE_TYPE_TRANSPARENT : ATMODEM_SIM_FILE_TYPE_LINEAR_FIXED;
					} else {
						/* increment to next byte */
						ptr_data++;
						/* For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
						/* the INCREASE command is allowed on the selected cyclic file. */
						file_type = ATMODEM_SIM_FILE_TYPE_CYCLIC;
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
			sim_result = TEL_SIM_RESULT_SUCCESS;
			g_free(record_data);
		} else {
			/*2. SIM access fail case*/
			err("Failed to get ef[0x%x] (file_meta->file_id) ", file_meta->file_id);
			sim_result = __atmodem_sim_decode_status_word(sw1, sw2);
		}

		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");
		err("Failed to get ef[0x%x] (file_meta->file_id)",
			file_meta->file_id);
		sim_result = TEL_SIM_RESULT_FAILURE;
	}

	dbg("Calling __atmodem_sim_next_from_get_response");
	__atmodem_sim_next_from_get_response(co, resp_cb_data, sim_result);
	dbg("Exit");
}

#if 0 //blocking for the moment
static TelReturn __atmodem_sim_update_file(CoreObject *co,
	AtmodemRespCbData *resp_cb_data,
	int cmd, TelSimFileId ef,
	int p1, int p2, int p3, char *encoded_data)
{
	char *cmd_str = NULL;
	TelReturn ret = TEL_RETURN_FAILURE;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	cmd_str = g_strdup_printf("AT+CRSM=%d,%d,%d,%d,%d,\"%s\"",
		cmd, ef, p1, p2, p3, encoded_data);

	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, "+CRSM:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_atmodem_sim_update_file, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Update SIM File");

	tcore_free(encoded_data);
	g_free(cmd_str);

	dbg("Exit");
	return ret;
}
#endif

static void __atmodem_sim_read_record(CoreObject *co,
	AtmodemRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;
	AtmodemSimMetaInfo *file_meta = (AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	/* According to TS 102 221, values of p1, p2, p3 can be as below:
	 * 11.1.5 READ RECORD
	 *	P1: Record number
	 *	P2: Mode, see table 11.11
	 *	Lc: Not present
	 *	Data: Not present
	 *	Le: Number of bytes to be read (P3)
	 */
	p1 = (unsigned char) file_meta->current_index;
	p2 = (unsigned char) 0x04;			/* 0x4 for absolute mode */
	p3 = (unsigned char) file_meta->rec_length;

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d, %d, %d, %d",
				ATMODEM_SIM_ACCESS_READ_RECORD, file_meta->file_id, p1, p2, p3);

	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CRSM:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_atmodem_sim_read_data, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Record");

	dbg("ret:[%d]", ret);
	g_free(at_cmd);

	dbg("Exit");
}

static void __atmodem_sim_read_binary(CoreObject *co, AtmodemRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;
	int offset = 0;
	AtmodemSimMetaInfo *file_meta = (AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

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

	if (file_meta->file_id == TEL_SIM_EF_SPDI)
		at_cmd = g_strdup_printf("AT+CRSM=%d, %d",
				ATMODEM_SIM_ACCESS_READ_BINARY, file_meta->file_id);
	else
		at_cmd = g_strdup_printf("AT+CRSM=%d, %d, %d, %d, %d",
				ATMODEM_SIM_ACCESS_READ_BINARY, file_meta->file_id, p1, p2, p3);

	ret = tcore_at_prepare_and_send_request(co, at_cmd, "+CRSM:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_atmodem_sim_read_data, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Data");

	dbg("ret:[%d]", ret);
	g_free(at_cmd);

	dbg("Exit");
}

static TelReturn __atmodem_sim_get_response(CoreObject *co, AtmodemRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	AtmodemSimMetaInfo *file_meta =
		(AtmodemSimMetaInfo *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d",
		ATMODEM_SIM_ACCESS_GET_RESPONSE, file_meta->file_id);

	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CRSM:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_atmodem_sim_get_response, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Info");

	g_free(at_cmd);
	dbg("Exit");
	return ret;
}

static int __atmodem_sim_get_lock_type(AtmodemSimCurrSecOp sec_op)
{
	switch(sec_op) {
		case ATMODEM_SIM_CURR_SEC_OP_SIM_DISABLE :
		case ATMODEM_SIM_CURR_SEC_OP_SIM_ENABLE :
		case ATMODEM_SIM_CURR_SEC_OP_SIM_STATUS :
			return TEL_SIM_LOCK_PS;
		case ATMODEM_SIM_CURR_SEC_OP_PIN1_DISABLE :
		case ATMODEM_SIM_CURR_SEC_OP_PIN1_ENABLE :
		case ATMODEM_SIM_CURR_SEC_OP_PIN1_STATUS :
			return TEL_SIM_LOCK_SC;
		case ATMODEM_SIM_CURR_SEC_OP_FDN_DISABLE :
		case ATMODEM_SIM_CURR_SEC_OP_FDN_ENABLE :
		case ATMODEM_SIM_CURR_SEC_OP_FDN_STATUS :
			return TEL_SIM_LOCK_FD;
		case ATMODEM_SIM_CURR_SEC_OP_NET_DISABLE :
		case ATMODEM_SIM_CURR_SEC_OP_NET_ENABLE :
		case ATMODEM_SIM_CURR_SEC_OP_NET_STATUS :
			return TEL_SIM_LOCK_PN;
		case ATMODEM_SIM_CURR_SEC_OP_NS_DISABLE :
		case ATMODEM_SIM_CURR_SEC_OP_NS_ENABLE :
		case ATMODEM_SIM_CURR_SEC_OP_NS_STATUS :
			return TEL_SIM_LOCK_PU;
		case ATMODEM_SIM_CURR_SEC_OP_SP_DISABLE :
		case ATMODEM_SIM_CURR_SEC_OP_SP_ENABLE :
		case ATMODEM_SIM_CURR_SEC_OP_SP_STATUS :
			return TEL_SIM_LOCK_PP;
		case ATMODEM_SIM_CURR_SEC_OP_CP_DISABLE :
		case ATMODEM_SIM_CURR_SEC_OP_CP_ENABLE :
		case ATMODEM_SIM_CURR_SEC_OP_CP_STATUS :
			return TEL_SIM_LOCK_PC ;
		default :
			err("Invalid sec op [%d]", sec_op);
			return -1;
	}
}

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
static gboolean on_notification_atmodem_sim_status(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *lines = (GSList *)event_info;
	const gchar *line = (const gchar *)lines->data;
	TelSimCardStatus sim_status = TEL_SIM_STATUS_SIM_INITIALIZING;
	AtmodemSimSecLockType locktype = SEC_LOCK_TYPE_NONE;
	AtmodemSimSecLockKey lockkey = SEC_LOCK_KEY_NONE;

	if (__atmodem_convert_scpin_str_to_enum((char *)line, &locktype, &lockkey) == FALSE)
		return TRUE;

	switch (locktype) {
	case SEC_LOCK_TYPE_READY:
		if (lockkey == SEC_LOCK_KEY_UNLOCKED)
			sim_status = TEL_SIM_STATUS_SIM_INITIALIZING;
		else
			sim_status = TEL_SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_PS:
		sim_status = TEL_SIM_STATUS_SIM_LOCK_REQUIRED;
	break;

	case SEC_LOCK_TYPE_PF:
		sim_status = TEL_SIM_STATUS_CARD_ERROR;
	break;

	case SEC_LOCK_TYPE_SC:
		switch (lockkey) {
		case SEC_LOCK_KEY_UNLOCKED:
		break;

		case SEC_LOCK_KEY_PIN:
			sim_status = TEL_SIM_STATUS_SIM_PIN_REQUIRED;
		break;

		case SEC_LOCK_KEY_PUK:
			sim_status = TEL_SIM_STATUS_SIM_PUK_REQUIRED;
		break;

		case SEC_LOCK_KEY_PERM_BLOCKED:
			sim_status = TEL_SIM_STATUS_CARD_BLOCKED;
		break;

		default:
			err("Not handled SEC Lock key: [%d]", lockkey);
			sim_status = TEL_SIM_STATUS_UNKNOWN;
		break;
		}
	break;

	case SEC_LOCK_TYPE_FD:
		break;

	case SEC_LOCK_TYPE_PN:
		if (SEC_LOCK_KEY_PIN)
			sim_status = TEL_SIM_STATUS_SIM_NCK_REQUIRED;
		else
			sim_status = TEL_SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_PU:
		if (SEC_LOCK_KEY_PIN)
			sim_status = TEL_SIM_STATUS_SIM_NSCK_REQUIRED;
		else
			sim_status = TEL_SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_PP:
		if (SEC_LOCK_KEY_PIN)
			sim_status = TEL_SIM_STATUS_SIM_SPCK_REQUIRED;
		else
			sim_status = TEL_SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_PC:
		if (SEC_LOCK_KEY_PIN)
			sim_status = TEL_SIM_STATUS_SIM_CCK_REQUIRED;
		else
			sim_status = TEL_SIM_STATUS_UNKNOWN;
	break;

	case SEC_LOCK_TYPE_SC2:
	case SEC_LOCK_TYPE_PUK2:
	break;

	case SEC_LOCK_TYPE_NO_SIM:
		sim_status = TEL_SIM_STATUS_CARD_NOT_PRESENT;
	break;

	case SEC_LOCK_TYPE_UNAVAIL:
	case SEC_SIM_INIT_CRASH:
		sim_status = TEL_SIM_STATUS_CARD_ERROR;
	break;

	case SEC_SIM_INIT_COMPLETED:
		sim_status = TEL_SIM_STATUS_SIM_INIT_COMPLETED;
	break;

	case SEC_PB_INIT_COMPLETED:
	break;

	default:
		err("Not handled SEC lock type: [%d]", locktype);
		sim_status = TEL_SIM_STATUS_UNKNOWN;
	break;
	}

	__atmodem_sim_process_sim_status(co, sim_status);

	return TRUE;
}

/* Response Functions */
static void on_response_atmodem_sim_verify_pins(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	AtmodemRespCbData *resp_cb_data = user_data;
	CoreObject *co_sim = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	AtmodemSimCurrSecOp *sec_op = NULL;
	TelSimSecPinResult verify_pin_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co_sim != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (AtmodemSimCurrSecOp *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (*sec_op == ATMODEM_SIM_CURR_SEC_OP_PIN1_VERIFY) {
		TelSimCardStatus status;

		verify_pin_resp.pin_type = TEL_SIM_PIN_TYPE_PIN1;

		tcore_sim_get_status(co_sim, &status);
		if (status != TEL_SIM_STATUS_SIM_INIT_COMPLETED) {
			/*Update sim status*/
			__atmodem_sim_update_sim_status(co_sim,
				TEL_SIM_STATUS_SIM_INITIALIZING);
		}
	} else if (*sec_op == ATMODEM_SIM_CURR_SEC_OP_PIN2_VERIFY) {
		verify_pin_resp.pin_type = TEL_SIM_PIN_TYPE_PIN2;
	}

	if (at_resp && at_resp->success) {
		dbg("SIM Verify Pin Response- [OK]");
		result = TEL_SIM_RESULT_SUCCESS;

	} else {
		err("SIM Verify Pin Response- [NOK]");

		/* Update retry count */
		verify_pin_resp.retry_count = 3;
	}

	/*Invoke callback*/
	if (resp_cb_data->cb)
		resp_cb_data->cb(co_sim, (gint)result,
			&verify_pin_resp, resp_cb_data->cb_data);

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_sim_verify_puks(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	AtmodemRespCbData *resp_cb_data = user_data;
	CoreObject *co_sim = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	AtmodemSimCurrSecOp *sec_op = NULL;
	TelSimSecPukResult verify_puk_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co_sim != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (AtmodemSimCurrSecOp *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (*sec_op == ATMODEM_SIM_CURR_SEC_OP_PUK1_VERIFY) {
		verify_puk_resp.puk_type = TEL_SIM_PUK_TYPE_PUK1;
	} else if (*sec_op == ATMODEM_SIM_CURR_SEC_OP_PUK2_VERIFY) {
		verify_puk_resp.puk_type = TEL_SIM_PUK_TYPE_PUK2;
	}
	if (at_resp && at_resp->success) {
		dbg("SIM Verify Puk Response- [OK]");
		result = TEL_SIM_RESULT_SUCCESS;
	} else {
		err("SIM Verify Puk Response- [NOK]");

		/* Update retry count */
		verify_puk_resp.retry_count = 3;
	}

	/*Invoke callback*/
	if (resp_cb_data->cb)
		resp_cb_data->cb(co_sim, (gint)result,
				&verify_puk_resp,
				resp_cb_data->cb_data);
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_sim_change_pins(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	AtmodemRespCbData *resp_cb_data = user_data;
	CoreObject *co_sim = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	AtmodemSimCurrSecOp *sec_op = NULL;
	TelSimSecPinResult change_pin_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co_sim != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (AtmodemSimCurrSecOp *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		dbg("SIM Change Pin Response- [OK]");

		result = TEL_SIM_RESULT_SUCCESS;

		if (*sec_op == ATMODEM_SIM_CURR_SEC_OP_PIN1_CHANGE) {
			change_pin_resp.pin_type = TEL_SIM_PIN_TYPE_PIN1;
		} else if (*sec_op == ATMODEM_SIM_CURR_SEC_OP_PIN2_CHANGE) {
			change_pin_resp.pin_type = TEL_SIM_PIN_TYPE_PIN2;
		}

		/*Invoke callback*/
		if (resp_cb_data->cb)
			resp_cb_data->cb(co_sim, (gint)result,
				&change_pin_resp, resp_cb_data->cb_data);
	}
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_sim_disable_facility(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	AtmodemRespCbData *resp_cb_data = user_data;
	CoreObject *co_sim = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	AtmodemSimCurrSecOp *sec_op = NULL;
	TelSimFacilityResult disable_facility_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co_sim != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (AtmodemSimCurrSecOp *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		int lock_type;
		dbg("SIM Disable Facility Response- [OK]");

		lock_type = __atmodem_sim_get_lock_type(*sec_op);
		if (lock_type == -1) {
			result = TEL_SIM_RESULT_INVALID_PARAMETER;

			/*Invoke callback*/
			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)result,
					NULL, resp_cb_data->cb_data);
			atmodem_destroy_resp_cb_data(resp_cb_data);
			return;
		}

		disable_facility_resp.type = lock_type;
		result = TEL_SIM_RESULT_SUCCESS;

		/*Invoke callback*/
		if (resp_cb_data->cb)
			resp_cb_data->cb(co_sim, (gint)result,
				&disable_facility_resp, resp_cb_data->cb_data);
	}

	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_sim_enable_facility(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	AtmodemRespCbData *resp_cb_data = user_data;
	CoreObject *co_sim = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	AtmodemSimCurrSecOp *sec_op = NULL;
	TelSimFacilityResult enable_facility_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co_sim != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (AtmodemSimCurrSecOp *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		int lock_type;
		dbg("SIM Enable Facility Response- [OK]");

		lock_type = __atmodem_sim_get_lock_type(*sec_op);
		if (lock_type == -1) {
			result = TEL_SIM_RESULT_INVALID_PARAMETER;

			/*Invoke callback*/
			if (resp_cb_data->cb)
				resp_cb_data->cb(co_sim, (gint)result,
					NULL, resp_cb_data->cb_data);
			atmodem_destroy_resp_cb_data(resp_cb_data);
			return;
		}

		enable_facility_resp.type = lock_type;
		result = TEL_SIM_RESULT_SUCCESS;

		/*Invoke callback*/
		if (resp_cb_data->cb)
			resp_cb_data->cb(co_sim, (gint)result,
					&enable_facility_resp,
					resp_cb_data->cb_data);
	}
	atmodem_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_atmodem_sim_get_facility(TcorePending *p, guint data_len,
		const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	AtmodemRespCbData *resp_cb_data = user_data;
	CoreObject *co_sim = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	AtmodemSimCurrSecOp *sec_op = NULL;
	TelSimFacilityInfo get_facility_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co_sim != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (AtmodemSimCurrSecOp *)ATMODEM_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		GSList *tokens = NULL;
		const char *line;
		int lock_type;

		dbg("SIM Get Facility Response- [OK]");

		lock_type = __atmodem_sim_get_lock_type(*sec_op);
		if (lock_type == -1) {
			result = TEL_SIM_RESULT_INVALID_PARAMETER;
			goto out;
		}
		if (at_resp->lines) {
			line = (const char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				err("Invalid message");
				tcore_at_tok_free(tokens);
				goto out;
			}
			get_facility_resp.f_status = atoi(g_slist_nth_data(tokens, 0));
			get_facility_resp.type = lock_type;
			result = TEL_SIM_RESULT_SUCCESS;
		}

		tcore_at_tok_free(tokens);
	} else {
		err("SIM Get Facility Response- [NOK]");
	}
out:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co_sim, (gint)result, &get_facility_resp, resp_cb_data->cb_data);
	atmodem_destroy_resp_cb_data(resp_cb_data);
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
static TelReturn atmodem_sim_get_imsi (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	AtmodemSimMetaInfo file_meta = {0, };
	AtmodemRespCbData *resp_cb_data = NULL;

	dbg("Entry");

	file_meta.file_id = TEL_SIM_EF_IMSI;
	file_meta.file_result = TEL_SIM_RESULT_FAILURE;
	file_meta.req_command = TCORE_COMMAND_SIM_GET_IMSI;

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
		&file_meta, sizeof(AtmodemSimMetaInfo));

	return __atmodem_sim_get_file_info(co, resp_cb_data);
}

static TelReturn atmodem_sim_get_ecc (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	AtmodemSimMetaInfo file_meta = {0, };
	AtmodemRespCbData *resp_cb_data = NULL;

	dbg("Entry");

	file_meta.file_id = TEL_SIM_EF_ECC;
	file_meta.file_result = TEL_SIM_RESULT_FAILURE;
	file_meta.req_command = TCORE_COMMAND_SIM_GET_ECC;

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
		&file_meta, sizeof(AtmodemSimMetaInfo));

	return __atmodem_sim_get_file_info(co, resp_cb_data);
}

static TelReturn atmodem_sim_get_spdi (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	AtmodemSimMetaInfo file_meta = {0, };
	AtmodemRespCbData *resp_cb_data = NULL;

	dbg("Entry");

	file_meta.file_id = TEL_SIM_EF_SPDI;
	file_meta.file_result = TEL_SIM_RESULT_FAILURE;
	file_meta.req_command = TCORE_COMMAND_SIM_GET_SP_DISPLAY_INFO;

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
		&file_meta, sizeof(AtmodemSimMetaInfo));

	return __atmodem_sim_get_file_info(co, resp_cb_data);
}

static TelReturn atmodem_sim_get_spn (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	AtmodemSimMetaInfo file_meta = {0, };
	AtmodemRespCbData *resp_cb_data = NULL;

	dbg("Entry");

	file_meta.file_id = TEL_SIM_EF_SPN;
	file_meta.file_result = TEL_SIM_RESULT_FAILURE;
	file_meta.req_command = TCORE_COMMAND_SIM_GET_SPN;

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
		&file_meta, sizeof(AtmodemSimMetaInfo));

	return __atmodem_sim_get_file_info(co, resp_cb_data);
}

static TelReturn atmodem_sim_get_language (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	AtmodemSimMetaInfo file_meta = {0, };
	AtmodemRespCbData *resp_cb_data = NULL;

	dbg("Entry");

	file_meta.file_id = TEL_SIM_EF_LP;
	file_meta.file_result = TEL_SIM_RESULT_FAILURE;
	file_meta.req_command = TCORE_COMMAND_SIM_GET_LANGUAGE;

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
		&file_meta, sizeof(AtmodemSimMetaInfo));

	return __atmodem_sim_get_file_info(co, resp_cb_data);
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
static TelReturn atmodem_sim_verify_pins(CoreObject *co,
	const TelSimSecPinPw *request,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	AtmodemRespCbData *resp_cb_data = NULL;
	AtmodemSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;

	dbg("Entry");

	if (request->pin_type == TEL_SIM_PIN_TYPE_PIN1) {
		sec_op = ATMODEM_SIM_CURR_SEC_OP_PIN1_VERIFY;
	} else if (request->pin_type == TEL_SIM_PIN_TYPE_PIN2) {
		sec_op = ATMODEM_SIM_CURR_SEC_OP_PIN2_VERIFY;
	} else {
		err("Invalid pin type [%d]", request->pin_type);
		return TEL_RETURN_INVALID_PARAMETER;
	}

	cmd_str = g_strdup_printf("AT+CPIN=\"%s\"", request->pw);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_atmodem_sim_verify_pins, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "SIM Verify PIN");

	g_free(cmd_str);
	return ret;
}

static TelReturn atmodem_sim_verify_puks(CoreObject *co,
	const TelSimSecPukPw *request,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	AtmodemRespCbData *resp_cb_data = NULL;
	AtmodemSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;

	dbg("Entry");

	if (request->puk_type == TEL_SIM_PUK_TYPE_PUK1) {
		sec_op = ATMODEM_SIM_CURR_SEC_OP_PUK1_VERIFY;
	} else if (request->puk_type == TEL_SIM_PUK_TYPE_PUK2) {
		sec_op = ATMODEM_SIM_CURR_SEC_OP_PUK2_VERIFY;
	} else {
		err("Invalid puk type [%d]", request->puk_type);
		return TEL_RETURN_INVALID_PARAMETER;
	}

	cmd_str = g_strdup_printf("AT+CPIN=\"%s\", \"%s\"",
		request->puk_pw, request->new_pin_pw);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_atmodem_sim_verify_puks, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "SIM Verify PUK");

	g_free(cmd_str);
	return ret;
}

static TelReturn atmodem_sim_change_pins(CoreObject *co,
	const TelSimSecChangePinPw *request,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	AtmodemRespCbData *resp_cb_data = NULL;
	AtmodemSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;

	dbg("Entry");

	if (request->pin_type == TEL_SIM_PIN_TYPE_PIN1) {
		sec_op = ATMODEM_SIM_CURR_SEC_OP_PIN1_CHANGE;
	} else if (request->pin_type == TEL_SIM_PIN_TYPE_PIN2) {
		sec_op = ATMODEM_SIM_CURR_SEC_OP_PIN2_CHANGE;
	} else {
		err("Invalid pin type [%d]", request->pin_type);
		return TEL_RETURN_INVALID_PARAMETER;
	}

	cmd_str = g_strdup_printf("AT+CPIN=\"%s\", \"%s\"", request->old_pw, request->new_pw);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_atmodem_sim_change_pins, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "SIM Change PIN");

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
static TelReturn atmodem_sim_disable_facility(CoreObject *co,
	const TelSimFacilityPw *request,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	AtmodemRespCbData *resp_cb_data = NULL;
	AtmodemSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;
	char *fac = "SC";
	int mode = 0; /*mode = 0 for disable lock*/

	dbg("Entry");

	fac = __atmodem_sim_get_fac_from_lock_type(request->lock_type,
			&sec_op, DISABLE_FLAG);
	if (!fac)
		return TEL_RETURN_INVALID_PARAMETER;

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"",
			fac, mode, request->pw);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, "+CLCK:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_atmodem_sim_disable_facility, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "SIM Disable Facility");

	g_free(cmd_str);
	return ret;
}

static TelReturn atmodem_sim_enable_facility(CoreObject *co,
	const TelSimFacilityPw *request,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	AtmodemRespCbData *resp_cb_data = NULL;
	AtmodemSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;
	char *fac = "SC";
	int mode = 1; /*mode = 1 for enable lock*/

	dbg("Entry");

	fac = __atmodem_sim_get_fac_from_lock_type(request->lock_type,
			&sec_op, ENABLE_FLAG);
	if (!fac)
		return TEL_RETURN_INVALID_PARAMETER;

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"",
			fac, mode, request->pw);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, "+CLCK:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_atmodem_sim_enable_facility, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "SIM Disable Facility");

	g_free(cmd_str);
	return ret;
}

static TelReturn atmodem_sim_get_facility(CoreObject *co,
	TelSimLockType lock_type,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	AtmodemRespCbData *resp_cb_data = NULL;
	AtmodemSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;
	char *fac = "SC";
	int mode = 2; /*mode = 2 for Get Facility*/

	dbg("Entry");

	fac = __atmodem_sim_get_fac_from_lock_type(lock_type,
			&sec_op, 0);
	if (!fac)
		return TEL_RETURN_INVALID_PARAMETER;

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d", fac, mode);

	resp_cb_data = atmodem_create_resp_cb_data(cb, cb_data,
				&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, "+CLCK:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_atmodem_sim_get_facility, resp_cb_data,
		on_send_atmodem_request, NULL);
	ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, "SIM Get Facility");

	g_free(cmd_str);
	return ret;
}

/* SIM Operations */
static TcoreSimOps atmodem_sim_ops = {
	.get_imsi = atmodem_sim_get_imsi,
	.get_ecc = atmodem_sim_get_ecc,
	.get_iccid = NULL,
	.get_language = atmodem_sim_get_language,
	.set_language = NULL,
	.get_callforwarding_info = NULL,
	.get_messagewaiting_info = NULL,
	.set_messagewaiting_info = NULL,
	.get_mailbox_info = NULL,
	.set_mailbox_info = NULL,
	.get_msisdn = NULL,
	.get_spn = atmodem_sim_get_spn,
	.get_cphs_netname = NULL,
	.get_sp_display_info = atmodem_sim_get_spdi,
	.req_authentication = NULL,
	.verify_pins = atmodem_sim_verify_pins,
	.verify_puks = atmodem_sim_verify_puks,
	.change_pins = atmodem_sim_change_pins,
	.disable_facility = atmodem_sim_disable_facility,
	.enable_facility = atmodem_sim_enable_facility,
	.get_facility = atmodem_sim_get_facility,
	.get_lock_info = NULL,
	.req_apdu = NULL,
	.req_atr = NULL
};

gboolean atmodem_sim_init(TcorePlugin *p, CoreObject *co_sim)
{
	dbg("Entry");

	/* Set operations */
	tcore_sim_set_ops(co_sim, &atmodem_sim_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co_sim, "\%SCSIM:",
		on_notification_atmodem_sim_status, NULL);

	dbg("Exit");
	return TRUE;
}

void atmodem_sim_exit(TcorePlugin *plugin, CoreObject *co_sim)
{
	dbg("Entry");
}
