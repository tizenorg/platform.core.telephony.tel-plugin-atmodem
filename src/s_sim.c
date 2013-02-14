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

#include "s_common.h"
#include "s_sim.h"

#include "atchannel.h"
#include "at_tok.h"

extern struct ATResponse *sp_response;
extern char *s_responsePrefix;
extern enum ATCommandType s_type;

#define SWAPBYTES16(x) \
{ \
    unsigned short int data = *(unsigned short int*)&(x); \
    data = ((data & 0xff00) >> 8) |    \
           ((data & 0x00ff) << 8);     \
    *(unsigned short int*)&(x) = data ;      \
}

enum s_sim_file_type_e {
	SIM_FTYPE_DEDICATED = 0x00, /**< Dedicated */
	SIM_FTYPE_TRANSPARENT = 0x01, /**< Transparent -binary type*/
	SIM_FTYPE_LINEAR_FIXED = 0x02, /**< Linear fixed - record type*/
	SIM_FTYPE_CYCLIC = 0x04, /**< Cyclic - record type*/
	SIM_FTYPE_INVALID_TYPE = 0xFF /**< Invalid type */
};

enum s_sim_sec_op_e {
	SEC_PIN1_VERIFY,
	SEC_PIN2_VERIFY,
	SEC_PUK1_VERIFY,
	SEC_PUK2_VERIFY,
	SEC_SIM_VERIFY,
	SEC_ADM_VERIFY,
	SEC_PIN1_CHANGE,
	SEC_PIN2_CHANGE,
	SEC_PIN1_ENABLE,
	SEC_PIN1_DISABLE,
	SEC_PIN2_ENABLE,
	SEC_PIN2_DISABLE, //10
	SEC_SIM_ENABLE,
	SEC_SIM_DISABLE,
	SEC_NET_ENABLE,
	SEC_NET_DISABLE,
	SEC_NS_ENABLE,
	SEC_NS_DISABLE,
	SEC_SP_ENABLE,
	SEC_SP_DISABLE,
	SEC_CP_ENABLE,
	SEC_CP_DISABLE, //20
	SEC_FDN_ENABLE,
	SEC_FDN_DISABLE,
	SEC_PIN1_STATUS,
	SEC_PIN2_STATUS,
	SEC_FDN_STATUS,
	SEC_NET_STATUS,
	SEC_NS_STATUS,
	SEC_SP_STATUS,
	SEC_CP_STATUS,
	SEC_SIM_STATUS
};

struct s_sim_property {
	gboolean b_valid; /**< Valid or not */
	enum tel_sim_file_id file_id; /**< File identifier */
	enum s_sim_file_type_e file_type; /**< File type and structure */
	int rec_length; /**< Length of one record in file */
	int rec_count; /**< Number of records in file */
	int data_size; /**< File size */
	int current_index; /**< current index to read */
	enum tel_sim_status first_recv_status;
	enum s_sim_sec_op_e current_sec_op; /**< current index to read */
	struct tresp_sim_read files;
	struct ATReqMetaInfo metainfo;
};

enum s_sim_sec_locktype_e{
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
	SEC_LOCL_TYPE_PUK2,	/*  Lock PUK2 (... ) */
	SEC_LOCK_TYPE_ACL,	/* ACL */

	SEC_LOCK_TYPE_NO_SIM,		/* SIM is not inserted */
	SEC_LOCK_TYPE_UNAVAIL,	/*  SIM is inserted but can not communicate with SIM ( SIM interface error ) */
	SEC_SIM_INIT_COMPLETED,	/*  SIM Initialize Completed */
	SEC_PB_INIT_COMPLETED,	/*  Phonebook Initialize Completed*/
	SEC_SIM_INIT_CRASH,		/*  SIM Crash request from SMC lab*/

	SEC_LOCK_TYPE_MAX
};

enum s_sim_sec_lockkey_e{
	SEC_LOCK_KEY_NONE,
	SEC_LOCK_KEY_UNLOCKED,		/* Not necessary */
	SEC_LOCK_KEY_PIN,		/* PIN required as a password */
	SEC_LOCK_KEY_PUK,		/* 0PUK required as a password */
	SEC_LOCK_KEY_PIN2,		/* PIN2 required as a password */
	SEC_LOCK_KEY_PUK2,		/*  PUK2 required as a password */
	SEC_LOCK_KEY_PERM_BLOCKED,    /* PIN Permanent Blocked */
	SEC_LOCK_KEY_PIN2_DISABLE,     /* PIN2 Lock Disabled*/
	SEC_LOCK_KEY_MAX
};



static void _next_from_get_file_info(CoreObject *o, UserRequest *ur, enum tel_sim_file_id ef, enum tel_sim_access_result rt);
static void _next_from_get_file_data(CoreObject *o, UserRequest *ur, enum tel_sim_access_result rt, int decode_ret);
static gboolean _get_sim_type(CoreObject *o);
static TReturn _get_file_info(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef);
static gboolean _get_file_data(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int offset, const int length);
static gboolean _get_file_record(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int index, const int length);
static void _sim_status_update(CoreObject *o, enum tel_sim_status sim_status);

static gboolean _convert_SCPIN_noti(char* line, enum s_sim_sec_locktype_e* lock_type, enum s_sim_sec_lockkey_e* lock_key);

static gboolean _convert_SCPIN_noti(char* line, enum s_sim_sec_locktype_e* lock_type, enum s_sim_sec_lockkey_e* lock_key)
{
	char *type =NULL, *key = NULL;
	int err;
	if(line == NULL)
		return FALSE;

	dbg("incoming string : %s\n", line);

	//rip off %SCPIN:
	at_tok_start(&line);

	// 1. find type string
	err = at_tok_nextstr(&line, &type);
	if(err<0){
		// no type string found.
		type = NULL;
	}
	if(type !=NULL){
		// 2. find key string
		err = at_tok_nextstr(&line, &key);
	}
	if(err<0){
		// no key found
		key = NULL;
	}

	dbg("type : %s, key : %s\n", type, key);

// 3. convert string into enum
	if(type!=NULL)
	{
		if(strStartsWith (type, "NO_SIM"))
			*lock_type = SEC_LOCK_TYPE_NO_SIM;
		else if(strStartsWith (type, "UNAVAIL"))
			*lock_type = SEC_LOCK_TYPE_UNAVAIL;
		else if(strStartsWith (type, "NO_LOCK"))
			*lock_type =  SEC_LOCK_TYPE_READY;
		else if(strStartsWith (type, "LOCK_PS"))
			*lock_type =  SEC_LOCK_TYPE_PS;
		else if(strStartsWith (type, "LOCK_PF"))
			*lock_type = SEC_LOCK_TYPE_PF ;
		else if(strStartsWith (type, "LOCK_SC"))
			*lock_type =  SEC_LOCK_TYPE_SC;
		else if(strStartsWith (type, "LOCK_FD"))
			*lock_type =  SEC_LOCK_TYPE_FD;
		else if(strStartsWith (type, "LOCK_PN"))
			*lock_type = SEC_LOCK_TYPE_PN ;
		else if(strStartsWith (type, "LOCK_PU"))
			*lock_type = SEC_LOCK_TYPE_PU ;
		else if(strStartsWith (type, "LOCK_PP"))
			*lock_type =  SEC_LOCK_TYPE_PP;
		else if(strStartsWith (type, "LOCK_PC"))
			*lock_type =  SEC_LOCK_TYPE_PC;
		else if(strStartsWith (type, "LOCK_SC2"))
			*lock_type = SEC_LOCK_TYPE_SC2 ;
		else if(strStartsWith (type, "LOCK_ACL"))
			*lock_type = SEC_LOCK_TYPE_ACL;
		else if(strStartsWith (type, "LOCK_PUK2"))
			*lock_type = SEC_LOCL_TYPE_PUK2;
		else if(strStartsWith (type, "INIT_COMP"))
			*lock_type = SEC_SIM_INIT_COMPLETED;
		else if(strStartsWith (type, "INIT_ERROR"))
			*lock_type = SEC_SIM_INIT_CRASH;
		else
			*lock_type = SEC_LOCK_TYPE_NONE;
	}
	else
		type = SEC_LOCK_TYPE_NONE;

	if(key!=NULL)
	{
		if(strStartsWith (type, "PIN"))
			*lock_key = SEC_LOCK_KEY_PIN;
		else if(strStartsWith (type, "PUK"))
			*lock_key = SEC_LOCK_KEY_PUK;
		else if(strStartsWith (type, "PIN2"))
			*lock_key =  SEC_LOCK_KEY_PIN2;
		else if(strStartsWith (type, "PUK2"))
			*lock_key =  SEC_LOCK_KEY_PUK2;
		else if(strStartsWith (type, "BLOCKED"))
			*lock_key = SEC_LOCK_KEY_PERM_BLOCKED ;
		else if(strStartsWith (type, "UNLOCKED"))
			*lock_key = SEC_LOCK_KEY_UNLOCKED ;
		else if(strStartsWith (type, "PIN2_DISABLE"))
			*lock_key =  SEC_LOCK_KEY_PIN2_DISABLE;
		else
			*lock_key = SEC_LOCK_KEY_NONE;
	}
	else
		*lock_key = SEC_LOCK_KEY_NONE;


	// 4. apply exceptional case.
	//if type is READY, key has no meanig
	if(*lock_type ==  SEC_LOCK_TYPE_READY)
		*lock_key = SEC_LOCK_KEY_UNLOCKED;

	// no sim, unvail, init_comp, init_error have no key info
	if((*lock_type == SEC_LOCK_TYPE_NO_SIM)||(*lock_type == SEC_LOCK_TYPE_UNAVAIL)||
			(*lock_type == SEC_SIM_INIT_COMPLETED)||(*lock_type == SEC_SIM_INIT_CRASH))
		*lock_key = SEC_LOCK_KEY_NONE;

	dbg("type : %d, key : %d\n", *lock_type, *lock_key);

	return TRUE;
}

static enum tcore_response_command _find_resp_command(UserRequest *ur)
{
	enum tcore_request_command command;
	command = tcore_user_request_get_command(ur);
	switch(command){
		case TREQ_SIM_VERIFY_PINS:
			return TRESP_SIM_VERIFY_PINS;
			break;
		case TREQ_SIM_VERIFY_PUKS:
			return TRESP_SIM_VERIFY_PUKS;
			break;
		case TREQ_SIM_CHANGE_PINS:
			return TRESP_SIM_CHANGE_PINS;
			break;
		case TREQ_SIM_GET_FACILITY_STATUS:
			return TRESP_SIM_GET_FACILITY_STATUS;
			break;
		case TREQ_SIM_DISABLE_FACILITY:
			return TRESP_SIM_DISABLE_FACILITY;
			break;
		case TREQ_SIM_ENABLE_FACILITY:
			return TRESP_SIM_ENABLE_FACILITY;
			break;
		case TREQ_SIM_TRANSMIT_APDU:
			return TRESP_SIM_TRANSMIT_APDU;
			break;
		case TREQ_SIM_GET_ATR:
			return TRESP_SIM_GET_ATR;
			break;
		case TREQ_SIM_GET_ECC:
			return TRESP_SIM_GET_ECC;
			break;
		case TREQ_SIM_GET_LANGUAGE:
			return TRESP_SIM_GET_LANGUAGE;
			break;
		case TREQ_SIM_SET_LANGUAGE:
			return TRESP_SIM_SET_LANGUAGE;
			break;
		case TREQ_SIM_GET_ICCID:
			return TRESP_SIM_GET_ICCID;
			break;
		case TREQ_SIM_GET_MAILBOX:
			return TRESP_SIM_GET_MAILBOX;
			break;
		case TREQ_SIM_GET_CALLFORWARDING:
			return TRESP_SIM_GET_CALLFORWARDING;
			break;
		case TREQ_SIM_GET_MESSAGEWAITING:
			return TRESP_SIM_GET_MESSAGEWAITING;
			break;
		case TREQ_SIM_GET_CPHS_INFO:
			return TRESP_SIM_GET_CPHS_INFO;
			break;
		case TREQ_SIM_GET_MSISDN:
			return TRESP_SIM_GET_MSISDN;
			break;
		case TREQ_SIM_GET_SPN:
			return TRESP_SIM_GET_SPN;
			break;
		case TREQ_SIM_GET_SPDI:
			return TRESP_SIM_GET_SPDI;
			break;
		case TREQ_SIM_GET_OPL:
			return TRESP_SIM_GET_OPL;
			break;
		case TREQ_SIM_GET_PNN:
			return TRESP_SIM_GET_PNN;
			break;
		case TREQ_SIM_GET_CPHS_NETNAME:
			return TRESP_SIM_GET_CPHS_NETNAME;
			break;
		case TREQ_SIM_GET_OPLMNWACT:
			return TRESP_SIM_GET_OPLMNWACT;
			break;
		case TREQ_SIM_REQ_AUTHENTICATION:
			return TRESP_SIM_REQ_AUTHENTICATION;
			break;
		default:
			break;
	}
	return TRESP_UNKNOWN;
}

static int _sim_get_current_pin_facility(struct s_sim_property *sp)
{
	int ret_type = 0;
	dbg("current sp->current_sec_op[%d]", sp->current_sec_op);
	switch(sp->current_sec_op){
		case SEC_PIN1_VERIFY :
		case SEC_PIN1_CHANGE :
			ret_type = SIM_PTYPE_PIN1;
			break;
		case SEC_PIN2_VERIFY :
		case SEC_PIN2_CHANGE :
			ret_type = SIM_PTYPE_PIN2;
			break;
		case SEC_PUK1_VERIFY :
			ret_type = SIM_PTYPE_PUK1;
			break;
		case SEC_PUK2_VERIFY :
			ret_type = SIM_PTYPE_PUK2;
			break;
		case SEC_SIM_VERIFY :
			ret_type = SIM_PTYPE_SIM;
			break;
		case SEC_ADM_VERIFY :
			ret_type = SIM_PTYPE_ADM;
			break;

		case SEC_PIN1_ENABLE :
		case SEC_PIN1_DISABLE :
		case SEC_PIN1_STATUS :
			ret_type = SIM_FACILITY_SC;
			break;
		case SEC_SIM_ENABLE :
		case SEC_SIM_DISABLE :
		case SEC_SIM_STATUS :
			ret_type = SIM_FACILITY_PS;
			break;
		case SEC_NET_ENABLE :
		case SEC_NET_DISABLE :
		case SEC_NET_STATUS :
			ret_type = SIM_FACILITY_PN;
			break;
		case SEC_NS_ENABLE :
		case SEC_NS_DISABLE :
		case SEC_NS_STATUS :
			ret_type = SIM_FACILITY_PU;
			break;
		case SEC_SP_ENABLE :
		case SEC_SP_DISABLE :
		case SEC_SP_STATUS :
			ret_type = SIM_FACILITY_PP;
			break;
		case SEC_CP_ENABLE :
		case SEC_CP_DISABLE :
		case SEC_CP_STATUS :
			ret_type = SIM_FACILITY_PC;
			break;
		case SEC_FDN_ENABLE :
		case SEC_FDN_DISABLE :
		case SEC_FDN_STATUS :
			ret_type = SIM_FACILITY_FD;
			break;

		default:
			dbg("not handled current op[%d]",sp->current_sec_op )
			break;
	}
	return ret_type;
}

static enum tel_sim_access_result _decode_status_word(unsigned short status_word1, unsigned short status_word2)
{
	enum tel_sim_access_result rst = SIM_ACCESS_FAILED;

	if (status_word1 == 0x93 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg(" error - SIM application toolkit busy [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x94 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg(" error - No EF Selected [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x94 && status_word2 == 0x02) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg("error - Out of Range - Invalid address or record number[%x][%x]",
				status_word1, status_word2);
	}
	else if (status_word1 == 0x94 && status_word2 == 0x04) {
		rst = SIM_ACCESS_FILE_NOT_FOUND;
		/*Failed SIM request command*/
		dbg(" error - File ID not found [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x94 && status_word2 == 0x08) {
		rst = SIM_ACCESS_FAILED; /* MOdem not support */
		/*Failed SIM request command*/
		dbg(" error - File is inconsistent with command - Modem not support or USE IPC [%x][%x]",
				status_word1, status_word2);
	}
	else if (status_word1 == 0x98 && status_word2 == 0x02) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error - CHV not initialized [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x98 && status_word2 == 0x04) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error - Access condition not fullfilled [%x][%x]", status_word1, status_word2);
		dbg(" error -Unsuccessful CHV verification - at least one attempt left [%x][%x]",
				status_word1, status_word2);
		dbg(" error - Unsuccessful Unblock CHV - at least one attempt left [%x][%x]",
				status_word1, status_word2);
		dbg(" error - Authentication failure [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x98 && status_word2 == 0x08) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error - Contradiction with CHV status [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x98 && status_word2 == 0x10) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error - Contradiction with invalidation  status [%x][%x]",
				status_word1, status_word2);
	}
	else if (status_word1 == 0x98 && status_word2 == 0x40) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error -Unsuccessful CHV verification - no attempt left [%x][%x]",
				status_word1, status_word2);
		dbg(" error - Unsuccessful Unblock CHV - no attempt left [%x][%x]",
				status_word1, status_word2);
		dbg(" error - CHV blocked [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x67 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		dbg(" error -Incorrect Parameter 3 [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x6B && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		dbg(" error -Incorrect Parameter 1 or 2 [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x6D && status_word2 == 0x00) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg(" error -Unknown instruction given as command [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x6E && status_word2 == 0x00) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg(" error -Unknown instruction given as command [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x69 && status_word2 == 0x82) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg(" error -Access denied [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x6A && status_word2 == 0x87) {
		rst = SIM_ACCESS_FAILED;
		dbg(" error -Incorrect parameters [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x6A && status_word2 == 0x82) {
		rst = SIM_ACCESS_FILE_NOT_FOUND; // not sure of the SW1 and SW2 meaning here
		dbg(" error -File Not found [%x][%x]", status_word1, status_word2);
	}
	else if (status_word1 == 0x6A && status_word2 == 0x83) {
		rst = SIM_ACCESS_FILE_NOT_FOUND; // not sure of the SW1 and SW2 meaning here
		dbg(" error -Record Not found [%x][%x]", status_word1, status_word2);
	}
	else {
		rst = SIM_ACCESS_CARD_ERROR;
		dbg(" error -Unknown state [%x][%x]", status_word1, status_word2);
	}
	return rst;
}

static gboolean _sim_check_identity(CoreObject *o, struct tel_sim_imsi *imsi)
{
	Server *s = NULL;
	Storage *strg = NULL;
	char* old_imsi = NULL;
	char new_imsi[15+1] = {0,};

	s = tcore_plugin_ref_server(tcore_object_ref_plugin(o));
	if(!s){
		dbg("there is no valid server at this point");
		return FALSE;
	}

	strg = (Storage*)tcore_server_find_storage(s, "vconf");
	if(!strg){
		dbg("there is no valid storage plugin");
		return FALSE;
	}

	memcpy(&new_imsi, imsi->plmn, strlen(imsi->plmn));
	memcpy(&new_imsi[strlen(imsi->plmn)], imsi->msin, strlen(imsi->msin));
	new_imsi[strlen(imsi->plmn)+strlen(imsi->msin)] = '\0';

	old_imsi = tcore_storage_get_string(strg, STORAGE_KEY_TELEPHONY_IMSI);
	dbg("old_imsi[%s],newImsi[%s]", old_imsi, new_imsi);

	if (old_imsi != NULL) {
		if (strncmp(old_imsi, new_imsi, 15) != 0) {
			dbg("NEW SIM");
			if (tcore_storage_set_string(strg, STORAGE_KEY_TELEPHONY_IMSI, (const char*) &new_imsi) == FALSE )
				dbg("[FAIL] UPDATE STORAGE_KEY_TELEPHONY_IMSI");
			tcore_sim_set_identification(o, TRUE);
		}
		else {
			dbg("SAME SIM");
			tcore_sim_set_identification(o, FALSE);
		}
	}
	else {
		dbg("OLD SIM VALUE IS NULL. NEW SIM");
		if (tcore_storage_set_string(strg, STORAGE_KEY_TELEPHONY_IMSI, (const char*) &new_imsi) == FALSE)
			dbg("[FAIL] UPDATE STORAGE_KEY_TELEPHONY_IMSI");
		tcore_sim_set_identification(o, TRUE);
	}
	return 1;
}

static void  _next_from_get_file_info(CoreObject *o,  UserRequest *ur, enum tel_sim_file_id ef, enum tel_sim_access_result rt )
{
	struct tresp_sim_read resp = {0,};
	struct s_sim_property *file_meta = NULL;

	dbg("EF[0x%x] access Result[%d]", ef, rt);

	resp.result = rt;
	memset(&resp.data, 0x00, sizeof(resp.data));

	if ((ef != SIM_EF_ELP || ef != SIM_EF_LP || ef != SIM_EF_USIM_PL)
			&& (rt != SIM_ACCESS_SUCCESS)) {
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read),
				&resp);
		return;
	}

	file_meta = (struct s_sim_property*)tcore_user_request_ref_metainfo(ur, NULL);

	switch (ef) {
		case SIM_EF_ELP:
			if (rt == SIM_ACCESS_SUCCESS) {
				dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
				/*				if (po->language_file == 0x00)
				 po->language_file = SIM_EF_ELP;*/
				_get_file_data(o, ur, ef, 0, file_meta->data_size);
			}
			else {
				if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
					dbg(" [SIM DATA]SIM_EF_ELP(2F05) access fail. Request SIM_EF_LP(0x6F05) info");
					/* The ME requests the Language Preference (EFLP) if EFELP is not available  */
					_get_file_info(o, ur, SIM_EF_LP);
				}
				else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
					dbg(
							" [SIM DATA]fail to get Language information in USIM(EF-LI(6F05),EF-PL(2F05)). Request SIM_EF_ECC(0x6FB7) info");
					/* EFELPand EFLI not present at this point. */
					/*					po->language.lang_cnt = 0;*/
					tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_read), &resp);
					return;
				}
			}
			break;

		case SIM_EF_LP: //same with SIM_EF_USIM_LI
			if (rt == SIM_ACCESS_SUCCESS) {
				dbg("[SIM DATA] exist EFLP/LI(0x6F05)");
				/*				if (po->language_file == 0x00)
				 po->language_file = SIM_EF_LP;*/
				_get_file_data(o, ur, ef, 0, file_meta->data_size);
			}
			else {
				dbg("[SIM DATA]SIM_EF_LP/LI(6F05) access fail. Current CardType[%d]",
						tcore_sim_get_type(o));
				if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
					/* EFELPand EFLP not present at this point.*/
					/*					po->language.lang_cnt = 0;*/
					tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_read), &resp);
					return;
				}
				/*  if EFLI is not present, then the language selection shall be as defined in EFPL at the MF level	*/
				else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
					dbg("[SIM DATA] try USIM EFPL(0x2F05)");
					_get_file_info(o, ur, SIM_EF_ELP);
				}
			}
			break;

		case SIM_EF_USIM_PL:
			if (rt == SIM_ACCESS_SUCCESS) {
				dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
				/*				if (po->language_file == 0x00)
				 po->language_file = SIM_EF_ELP;*/
				_get_file_data(o, ur, SIM_EF_ELP, 0, file_meta->data_size);
			}
			else {
				/* EFELIand EFPL not present, so set language count as zero and select ECC */
				dbg(
						" [SIM DATA]SIM_EF_USIM_PL(2A05) access fail. Request SIM_EF_ECC(0x6FB7) info");
				/*				po->language.lang_cnt = 0;*/
				tcore_user_request_send_response(ur, _find_resp_command(ur),
						sizeof(struct tresp_sim_read), &resp);
				return;
			}
			break;

		case SIM_EF_ECC:
			if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
				_get_file_data(o, ur, ef, 0, file_meta->data_size);
			}
			else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
				if (file_meta->rec_count > SIM_ECC_RECORD_CNT_MAX)
					file_meta->rec_count = SIM_ECC_RECORD_CNT_MAX;

				file_meta->current_index++;
				_get_file_record(o, ur, ef, file_meta->current_index, file_meta->rec_length);
			}
			break;

		case SIM_EF_ICCID:
		case SIM_EF_IMSI:
		case SIM_EF_SPN:
		case SIM_EF_SPDI:
		case SIM_EF_CPHS_CPHS_INFO:
		case SIM_EF_CPHS_OPERATOR_NAME_STRING:
		case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
			_get_file_data(o, ur, ef, 0, file_meta->data_size);
			break;

		case SIM_EF_OPL:
		case SIM_EF_PNN:
			file_meta->current_index++;
			_get_file_record(o, ur, ef, file_meta->current_index, file_meta->rec_length);
			break;

		case SIM_EF_SST:
		case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
		case SIM_EF_CPHS_VOICE_MSG_WAITING:
		case SIM_EF_CPHS_DYNAMICFLAGS:
		case SIM_EF_CPHS_DYNAMIC2FLAG:
		case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
		case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		case SIM_EF_USIM_CFIS:
		case SIM_EF_USIM_MWIS:
		case SIM_EF_USIM_MBI:
		case SIM_EF_MBDN:
		case SIM_EF_CPHS_MAILBOX_NUMBERS:
		case SIM_EF_CPHS_INFORMATION_NUMBERS:
		default:
			dbg( "error - File id for get file info [0x%x]", ef);
			break;
	}
	return;
}

static void _next_from_get_file_data(CoreObject *o, UserRequest *ur, enum tel_sim_access_result rt, int decode_ret)
{
	struct s_sim_property *file_meta = NULL;
	file_meta = (struct s_sim_property*)tcore_user_request_ref_metainfo(ur, NULL);

	dbg("[SIM]EF[0x%x] read rt[%d] Decode rt[%d]", file_meta->file_id, rt, decode_ret);

	switch (file_meta->file_id) {
		case SIM_EF_ELP:
		case SIM_EF_USIM_PL:
		case SIM_EF_LP:
		case SIM_EF_USIM_LI:
			if (decode_ret == TRUE) {
				if (file_meta->file_id == SIM_EF_LP || file_meta->file_id == SIM_EF_USIM_LI) {
/*					po->language_file = SIM_EF_LP;*/
				} else if (file_meta->file_id == SIM_EF_ELP || file_meta->file_id == SIM_EF_USIM_PL) {
/*					po->language_file = SIM_EF_ELP;*/
				}
				tcore_user_request_send_response(ur, _find_resp_command(ur),	sizeof(struct tresp_sim_read), &file_meta->files);
			} else {
				/* 2G */
				/*  The ME requests the Extended Language Preference. The ME only requests the Language Preference (EFLP) if at least one of the following conditions holds:
				 -	EFELP is not available;
				 -	EFELP does not contain an entry corresponding to a language specified in ISO 639[30];
				 -	the ME does not support any of the languages in EFELP.
				 */
				/* 3G */
				/*  The ME only requests the Language Preference (EFPL) if at least one of the following conditions holds:
				 -	if the EFLI has the value 'FFFF' in its highest priority position
				 -	if the ME does not support any of the language codes indicated in EFLI , or if EFLI is not present
				 */
				if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
					if (file_meta->file_id == SIM_EF_LP)
						tcore_user_request_send_response(ur, _find_resp_command(ur),	sizeof(struct tresp_sim_read), &file_meta->files);
					else
						_get_file_info(o, ur, SIM_EF_LP);
				} else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
					if (file_meta->file_id == SIM_EF_LP || file_meta->file_id == SIM_EF_USIM_LI)
						_get_file_info(o, ur, SIM_EF_ELP);
					else
						tcore_user_request_send_response(ur, _find_resp_command(ur),	sizeof(struct tresp_sim_read), &file_meta->files);
				}
			}
			break;

		case SIM_EF_ECC:
			if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
				file_meta->files.data.ecc.ecc_count++;
				if (file_meta->current_index == file_meta->rec_count) {
					tcore_user_request_send_response(ur, _find_resp_command(ur),	sizeof(struct tresp_sim_read), &file_meta->files);
				} else {
					file_meta->current_index++;
					_get_file_record(o, ur, file_meta->file_id, file_meta->current_index, file_meta->rec_length );
				}
			} else if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
				tcore_user_request_send_response(ur, _find_resp_command(ur),	sizeof(struct tresp_sim_read), &file_meta->files);
			} else {
				dbg("[SIM DATA]Invalid CardType[%d] Unable to handle", tcore_sim_get_type(o));
			}
			break;

		case SIM_EF_IMSI:
			_sim_status_update(o, SIM_STATUS_INIT_COMPLETED);
			break;

		case SIM_EF_OPL:
			file_meta->files.data.opl.opl_count++;
			dbg("file_meta->files.data.opl.opl_count[%d], current index[%d], rec_cnt[%d]",
					file_meta->files.data.opl.opl_count, file_meta->current_index,file_meta->rec_count);
			if (file_meta->current_index == file_meta->rec_count) {
				tcore_user_request_send_response(ur, _find_resp_command(ur),	sizeof(struct tresp_sim_read), &file_meta->files);
			} else {
				file_meta->current_index++;
				_get_file_record(o, ur, file_meta->file_id, file_meta->current_index, file_meta->rec_length );
			}
			break;
		case SIM_EF_PNN:
			file_meta->files.data.pnn.pnn_count++;
			if (file_meta->current_index == file_meta->rec_count) {
				tcore_user_request_send_response(ur, _find_resp_command(ur),	sizeof(struct tresp_sim_read), &file_meta->files);
			} else {
				file_meta->current_index++;
				_get_file_record(o, ur, file_meta->file_id, file_meta->current_index, file_meta->rec_length );
			}
			break;

		case SIM_EF_ICCID:
		case SIM_EF_SPN:
		case SIM_EF_SPDI:
		case SIM_EF_CPHS_CPHS_INFO:
		case SIM_EF_CPHS_OPERATOR_NAME_STRING:
		case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
			tcore_user_request_send_response(ur, _find_resp_command(ur),	sizeof(struct tresp_sim_read), &file_meta->files);
			break;

		case SIM_EF_SST:
		case SIM_EF_USIM_CFIS:
		case SIM_EF_USIM_MWIS:
		case SIM_EF_USIM_MBI:
		case SIM_EF_MBDN:
		case SIM_EF_CPHS_MAILBOX_NUMBERS:
		case SIM_EF_CPHS_INFORMATION_NUMBERS:
		case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
		case SIM_EF_CPHS_VOICE_MSG_WAITING:
		case SIM_EF_CPHS_DYNAMICFLAGS:
		case SIM_EF_CPHS_DYNAMIC2FLAG:
		case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
		case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		default:
			dbg("File id not handled [0x%x]", file_meta->file_id);
			break;
	}
}

static void _sim_status_update(CoreObject *o, enum tel_sim_status sim_status)
{
	struct tnoti_sim_status noti_data = {0,};

	dbg("tcore_sim_set_status and send noti w/ [%d]", sim_status);
	tcore_sim_set_status(o, sim_status);
	noti_data.sim_status = sim_status;
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SIM_STATUS,
			sizeof(struct tnoti_sim_status), &noti_data);
}

static void on_confirmation_sim_message_send( TcorePending *p, gboolean result, void *user_data )
{
	UserRequest* ur = NULL;
	struct ATReqMetaInfo* metainfo = NULL;
	unsigned int info_len =0;
	struct s_sim_property *file_meta = NULL;
	dbg("on_confirmation_sim_message_send - msg out from queue. alloc ATRsp buffer & write rspPrefix if needed\n");

//alloc new sp_response
	ReleaseResponse(); //release leftover
//alloc new sp_response

	sp_response = at_response_new();

	ur = tcore_pending_ref_user_request(p);

	dbg("********************************tcore_user_request_get_command[0x%x]", tcore_user_request_get_command(ur));

	file_meta = (struct s_sim_property *)tcore_user_request_ref_metainfo(ur,&info_len);
	metainfo = &(file_meta->metainfo);

	dbg("file_meta->type[%d]", file_meta->metainfo.type);
	dbg("metainfo->type[%d]", metainfo->type);

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

static void _response_get_sim_type(TcorePending *p, int data_len, const void *data, void *user_data)
{
	struct s_sim_property *sp = NULL;
	CoreObject *co_sim = NULL;
	enum tel_sim_type sim_type = SIM_TYPE_UNKNOWN;
	char* line=NULL;
	int ret = 0;

	if(sp_response->success > 0)
	{
		line = sp_response->p_intermediates->line;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,(int *)&sim_type);
		if (ret < 0)
			AT_TOK_ERROR(line);
	}
	else
	{
		sim_type = SIM_TYPE_UNKNOWN;
	}

	dbg("resp sim type[%d]", sim_type);

	ReleaseResponse();

	co_sim = tcore_pending_ref_core_object(p);
	tcore_sim_set_type(co_sim, sim_type);
	sp = tcore_sim_ref_userdata(co_sim);
	_sim_status_update(co_sim, sp->first_recv_status);
}

static void _response_get_file_info(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *co_sim = NULL;
	UserRequest *ur = NULL;
	struct s_sim_property *file_meta = NULL;
	enum tel_sim_access_result rt;

	char *line = NULL;
	int ret = 0;
	int sw1 = 0;
	int sw2 = 0;
	//char *hexData;
	//char *recordData;

	co_sim = tcore_pending_ref_core_object(p);
	if(!co_sim){
		dbg("error -  core object is null");
		return;
	}
	ur = tcore_pending_ref_user_request(p);
	file_meta = (struct s_sim_property*)tcore_user_request_ref_metainfo(ur, NULL);

	if(sp_response->success > 0)
	{
		line = sp_response->p_intermediates->line;
		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&sw1);
		if (ret < 0)
			AT_TOK_ERROR(line);
		ret = at_tok_nextint(&line,&sw2);
		if (ret < 0)
			AT_TOK_ERROR(line);

		/*1. SIM access success case*/
		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			unsigned char tag_len = 0; /*	1 or 2 bytes ??? */
			unsigned short record_len = 0;
			char num_of_records = 0;
			unsigned char file_id_len = 0;
			unsigned short file_id = 0;
			unsigned short file_size = 0;
			unsigned short file_type = 0;
			unsigned short arr_file_id = 0;
			int arr_file_id_rec_num = 0;

			/*	handling only last 3 bits */
			unsigned char file_type_tag = 0x07;
			unsigned char *ptr_data;

			char *hexData;
			char *recordData;
			ret = at_tok_nextstr(&line,&hexData);
			if (ret < 0)
				AT_TOK_ERROR(line);

			recordData = util_hexStringToBytes(hexData);
			util_hex_dump("    ", strlen(hexData)/2, recordData);

			ptr_data = (unsigned char *)recordData;
			if (tcore_sim_get_type(co_sim) == SIM_TYPE_USIM) {
				/*
				 ETSI TS 102 221 v7.9.0
				 - Response Data
				 '62'	FCP template tag
				 - Response for an EF
				 '82'	M	File Descriptor
				 '83'	M	File Identifier
				 'A5'	O	Proprietary information
				 '8A'	M	Life Cycle Status Integer
				 '8B', '8C' or 'AB'	C1	Security attributes
				 '80'	M	File size
				 '81'	O	Total file size
				 '88'	O	Short File Identifier (SFI)
				 */

				/* rsim.res_len  has complete data length received  */

				/* FCP template tag - File Control Parameters tag*/
				if (*ptr_data == 0x62) {
					/* parse complete FCP tag*/
					/* increment to next byte */
					ptr_data++;
					tag_len = *ptr_data++;
					/* FCP file descriptor - file type, accessibility, DF, ADF etc*/
					if (*ptr_data == 0x82) {
						/* increment to next byte */
						ptr_data++;
						/*2 or 5 value*/
						ptr_data++;
						/*	unsigned char file_desc_len = *ptr_data++;*/
						/*	dbg("file descriptor length: [%d]", file_desc_len);*/
						/* TBD:  currently capture only file type : ignore sharable, non sharable, working, internal etc*/
						/* consider only last 3 bits*/
						file_type_tag = file_type_tag & (*ptr_data);

						switch (file_type_tag) {
							/* increment to next byte */
							ptr_data++;
							case 0x1:
								dbg("Getting FileType: [Transparent file type]");
								/* increment to next byte */
								ptr_data++;
								file_type = SIM_FTYPE_TRANSPARENT;
								/*	data coding byte - value 21 */
								ptr_data++;
								break;

							case 0x2:
								dbg("Getting FileType: [Linear fixed file type]");
								/* increment to next byte */
								ptr_data++;
								/*	data coding byte - value 21 */
								ptr_data++;
								/*	2bytes */
								memcpy(&record_len, ptr_data, 2);
								/* swap bytes */
								SWAPBYTES16(record_len);
								ptr_data = ptr_data + 2;
								num_of_records = *ptr_data++;
								/* Data lossy conversation from enum (int) to unsigned char */
								file_type = SIM_FTYPE_LINEAR_FIXED;
								break;

							case 0x6:
								dbg(" Cyclic fixed file type");
								/* increment to next byte */
								ptr_data++;
								/*	data coding byte - value 21 */
								ptr_data++;
								/*	2bytes */
								memcpy(&record_len, ptr_data, 2);
								/* swap bytes  */
								SWAPBYTES16(record_len);
								ptr_data = ptr_data + 2;
								num_of_records = *ptr_data++;
								file_type = SIM_FTYPE_CYCLIC;
								break;

						default:
							dbg("not handled file type [0x%x]", *ptr_data);
							break;
						}
					} else {
						dbg("INVALID FCP received - DEbug!");
						return;
					}

					/*File identifier - file id?? */ // 0x84,0x85,0x86 etc are currently ignored and not handled
					if (*ptr_data == 0x83) {
						/* increment to next byte */
						ptr_data++;
						file_id_len = *ptr_data++;
						memcpy(&file_id, ptr_data, file_id_len);
						/* swap bytes	 */
						SWAPBYTES16(file_id);
						ptr_data = ptr_data + 2;
						dbg("Getting FileID=[0x%x]", file_id);
					} else {
						dbg("INVALID FCP received - DEbug!");
						free(recordData);
						ReleaseResponse();
						return;
					}

					/*	proprietary information  */
					if (*ptr_data == 0xA5) {
						unsigned short prop_len;
						/* increment to next byte */
						ptr_data++;
						/* length */
						prop_len = *ptr_data;
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
								dbg("<IPC_RX> operation state -deactivated");
								ptr_data++;
								break;
							case 0x05:
							case 0x07:
								dbg("<IPC_RX> operation state -activated");
								ptr_data++;
								break;
							default:
								dbg("<IPC_RX> DEBUG! LIFE CYCLE STATUS =[0x%x]",*ptr_data);
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
							SWAPBYTES16(arr_file_id);
							ptr_data = ptr_data + 2;
							arr_file_id_rec_num = *ptr_data++;
						} else {
							/* if tag length is not 3 */
							/* ignoring bytes	*/
							//	ptr_data = ptr_data + 4;
							dbg("Useless security attributes, so jump to next tag");
							ptr_data = ptr_data + (*ptr_data + 1);
						}
					} else {
						dbg("INVALID FCP received[0x%x] - DEbug!", *ptr_data);
						free(recordData);
						ReleaseResponse();
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
						SWAPBYTES16(file_size);
						ptr_data = ptr_data + 2;
					} else {
						dbg("INVALID FCP received - DEbug!");
						free(recordData);
						ReleaseResponse();
						return;
					}

					/* total file size including structural info*/
					if (*ptr_data == 0x81) {
						int len;
						/* increment to next byte */
						ptr_data++;
						/* length */
						len = *ptr_data;
						/* ignored bytes */
						ptr_data = ptr_data + 3;
					} else {
						dbg("INVALID FCP received - DEbug!");
						/* 0x81 is optional tag?? check out! so do not return -1 from here! */
						/* return -1; */
					}
					/*short file identifier ignored*/
					if (*ptr_data == 0x88) {
						dbg("0x88: Do Nothing");
						/*DO NOTHING*/
					}
				} else {
					dbg("INVALID FCP received - DEbug!");
					free(recordData);
					ReleaseResponse();
					return;
				}
			} else if (tcore_sim_get_type(co_sim) == SIM_TYPE_GSM) {
				unsigned char gsm_specific_file_data_len = 0;
				/*	ignore RFU byte1 and byte2 */
				ptr_data++;
				ptr_data++;
				/*	file size */
				//file_size = p_info->response_len;
				memcpy(&file_size, ptr_data, 2);
				/* swap bytes */
				SWAPBYTES16(file_size);
				/*	parsed file size */
				ptr_data = ptr_data + 2;
				/*  file id  */
				memcpy(&file_id, ptr_data, 2);
				SWAPBYTES16(file_id);
				dbg(" FILE id --> [%x]", file_id);
				ptr_data = ptr_data + 2;
				/* save file type - transparent, linear fixed or cyclic */
				file_type_tag = (*(ptr_data + 7));

				switch (*ptr_data) {
					case 0x0:
						/* RFU file type */
						dbg(" RFU file type- not handled - Debug!");
						break;
					case 0x1:
						/* MF file type */
						dbg(" MF file type - not handled - Debug!");
						break;
					case 0x2:
						/* DF file type */
						dbg(" DF file type - not handled - Debug!");
						break;
					case 0x4:
						/* EF file type */
						dbg(" EF file type [%d] ", file_type_tag);
						/*	increment to next byte */
						ptr_data++;

						if (file_type_tag == 0x00 || file_type_tag == 0x01) {
							/* increament to next byte as this byte is RFU */
							ptr_data++;
							file_type =
									(file_type_tag == 0x00) ? SIM_FTYPE_TRANSPARENT : SIM_FTYPE_LINEAR_FIXED;
						} else {
							/* increment to next byte */
							ptr_data++;
							/*	For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
							/* the INCREASE command is allowed on the selected cyclic file. */
							file_type = SIM_FTYPE_CYCLIC;
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
						ptr_data++;
						/*	byte 14 - structure of EF - transparent or linear or cyclic , already saved above */
						ptr_data++;
						/* byte 15 - length of record for linear and cyclic , for transparent it is set to 0x00. */
						record_len = *ptr_data;
						dbg("record length[%d], file size[%d]", record_len, file_size);

						if (record_len != 0)
							num_of_records = (file_size / record_len);

						dbg("Number of records [%d]", num_of_records);
						break;

					default:
						dbg(" not handled file type");
						break;
				}
			}
			else
			{
				dbg(" Card Type - UNKNOWN  [%d]", tcore_sim_get_type(co_sim));
			}

			dbg("req ef[0x%x] resp ef[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]",
					file_meta->file_id, file_id, file_size, file_type, num_of_records, record_len);

			file_meta->file_type = file_type;
			file_meta->data_size = file_size;
			file_meta->rec_length = record_len;
			file_meta->rec_count = num_of_records;
			file_meta->current_index = 0; //reset for new record type EF
			rt = SIM_ACCESS_SUCCESS;
			free(recordData);
		}
		else
		{
			/*2. SIM access fail case*/
			dbg("error to get ef[0x%x]", file_meta->file_id);
			rt = _decode_status_word(sw1, sw2);
		}

		ReleaseResponse();

		ur = tcore_user_request_ref(ur);
		_next_from_get_file_info(co_sim, ur, file_meta->file_id, rt);
	}
	else
	{
		ReleaseResponse();
		dbg("error to get ef[0x%x]", file_meta->file_id);
		rt = SIM_ACCESS_FAILED;;

		ur = tcore_user_request_ref(ur);
		_next_from_get_file_info(co_sim, ur, file_meta->file_id, rt);
	}
}

static void _response_get_file_data(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	enum tel_sim_access_result rt;
	struct tel_sim_imsi imsi;
	struct s_sim_property *file_meta = NULL;
	gboolean dr = FALSE;

	char *line = NULL;
	int ret = 0;
	int sw1 = 0;
	int sw2 = 0;

	dbg("[SIM_READ_BINARY] or [SIM_READ_RECORD]");

	dbg("sizeof struct tresp_sim_read = [%d]", sizeof(struct tresp_sim_read));

	co_sim = tcore_pending_ref_core_object(p);
	if(!co_sim){
		dbg("error -  core object is null");
		return;
	}
	ur = tcore_pending_ref_user_request(p);
	file_meta = (struct s_sim_property*)tcore_user_request_ref_metainfo(ur, NULL);

	if(sp_response->success > 0)
	{
		line = sp_response->p_intermediates->line;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&sw1);
		if (ret < 0)
			AT_TOK_ERROR(line);
		ret = at_tok_nextint(&line,&sw2);
		if (ret < 0)
			AT_TOK_ERROR(line);

		if((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91)	{
			char *hexStr;
			char *fileData;

			ret = at_tok_nextstr(&line,&hexStr);
			if (ret < 0)
				AT_TOK_ERROR(line);

			fileData = util_hexStringToBytes(hexStr);
			util_hex_dump("    ", strlen(hexStr)/2, fileData);

			rt = SIM_ACCESS_SUCCESS;
			file_meta->files.result = rt;

			switch (file_meta->file_id)
			{
					case SIM_EF_IMSI:
						dr = tcore_sim_decode_imsi(&imsi, (unsigned char *)fileData, strlen(fileData));
						if (dr == FALSE) {
							dbg("imsi decoding failed");
						} else {
							_sim_check_identity(co_sim,&imsi);
							tcore_sim_set_imsi(co_sim,&imsi);
						}
						break;

					case SIM_EF_ICCID:
						dr = tcore_sim_decode_iccid(&file_meta->files.data.iccid, (unsigned char *)fileData, strlen(fileData));
						break;

					case SIM_EF_ELP:/*  2G EF -  2 bytes decoding*/
					case SIM_EF_USIM_LI: /* 3G EF - 2 bytes decoding*/
					case SIM_EF_USIM_PL:/*  3G EF - same as EFELP, so 2  byte decoding*/
					case SIM_EF_LP:/*  1 byte encoding*/
						if (tcore_sim_get_type(co_sim) == SIM_TYPE_GSM && file_meta->file_id == SIM_EF_LP) {
							 /*2G LP(0x6F05) has 1 byte for each language*/
							dr = tcore_sim_decode_lp(&file_meta->files.data.language, (unsigned char *)fileData, strlen(fileData));
						} else {
							 /*3G LI(0x6F05)/PL(0x2F05), 2G ELP(0x2F05) has 2 bytes for each language*/
							dr = tcore_sim_decode_li(file_meta->file_id, &file_meta->files.data.language, (unsigned char *)fileData, strlen(fileData));
						}
						break;

					case SIM_EF_SPN:
						dr = tcore_sim_decode_spn(&file_meta->files.data.spn, (unsigned char *)fileData, strlen(fileData));
						break;

					case SIM_EF_SPDI:
						dr = tcore_sim_decode_spdi(&file_meta->files.data.spdi, (unsigned char *)fileData, strlen(fileData));
						break;

					case SIM_EF_ECC:
						if(tcore_sim_get_type(co_sim) == SIM_TYPE_GSM) {
							dr = tcore_sim_decode_ecc(&file_meta->files.data.ecc, (unsigned char *)fileData, strlen(fileData));
						} else if(tcore_sim_get_type(co_sim) == SIM_TYPE_USIM){
							dr = tcore_sim_decode_uecc(&file_meta->files.data.ecc.ecc[file_meta->current_index-1], (unsigned char *)fileData, strlen(fileData));
						} else {
							dbg("err not handled tcore_sim_get_type(o)[%d] in here",tcore_sim_get_type(co_sim));
						}
						break;

					case SIM_EF_OPL:
						dr = tcore_sim_decode_opl(&file_meta->files.data.opl.opl[file_meta->current_index-1], (unsigned char *)fileData, strlen(fileData));
						break;

					case SIM_EF_PNN:
						dr = tcore_sim_decode_pnn(&file_meta->files.data.pnn.pnn[file_meta->current_index-1], (unsigned char *)fileData, strlen(fileData));
						break;

					case SIM_EF_OPLMN_ACT:
						dr = tcore_sim_decode_oplmnwact(&file_meta->files.data.opwa, (unsigned char *)fileData, strlen(fileData));
						break;

					case SIM_EF_CPHS_OPERATOR_NAME_STRING:
						dr = tcore_sim_decode_ons((unsigned char*)&file_meta->files.data.cphs_net.full_name, (unsigned char *)fileData, strlen(fileData));
						break;

					case SIM_EF_CPHS_CPHS_INFO:
						dr = tcore_sim_decode_cphs_info(&file_meta->files.data.cphs, (unsigned char *)fileData, strlen(fileData));
						break;

					case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
						dr = tcore_sim_decode_short_ons((unsigned char*)&file_meta->files.data.cphs_net.short_name, (unsigned char *)fileData,	strlen(fileData));
						break;

					case SIM_EF_CPHS_INFORMATION_NUMBERS:
					case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
					case SIM_EF_USIM_MBI:
					case SIM_EF_MBDN:
					case SIM_EF_SST:
					case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
					case SIM_EF_CPHS_VOICE_MSG_WAITING:
					case SIM_EF_CPHS_MAILBOX_NUMBERS:
					case SIM_EF_USIM_MWIS:
					case SIM_EF_USIM_CFIS:
					case SIM_EF_CPHS_SERVICE_STRING_TABLE:
					case SIM_EF_CPHS_DYNAMICFLAGS:
					case SIM_EF_CPHS_DYNAMIC2FLAG:
					default:
						dbg("File Decoding Failed - not handled File[0x%x]", file_meta->file_id);
						dr = 0;
						break;
				}

			free(fileData);
		}
		else
		{
			rt =  _decode_status_word(sw1, sw2);
			file_meta->files.result = rt;
		}

		ReleaseResponse();
	}
	else
	{
		ReleaseResponse();
		rt = SIM_ACCESS_FAILED;;
		file_meta->files.result = rt;
	}

	ur = tcore_user_request_ref(ur);
	_next_from_get_file_data(tcore_pending_ref_core_object(p), ur, rt, dr);
}

static gboolean _get_sim_type(CoreObject *o)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;

	char *cmd_str = NULL;
	struct s_sim_property file_meta={0,};
	TReturn trt = 0;
	UserRequest *ur = NULL;

	if (!o)
		return FALSE;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	file_meta.metainfo.type = SINGLELINE;
	memcpy(file_meta.metainfo.responsePrefix,"%SCCT:",strlen("%SCCT:"));

	ur = tcore_user_request_new(NULL, NULL);

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), &file_meta);
	dbg("trt[%d]",trt);


	// AT+CPIN=<pin>[,<newpin>]
	cmd_str = g_strdup("AT%SCCT\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, _response_get_sim_type, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);

	free(cmd_str);

	return TRUE;
}

static TReturn _get_file_info(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	//size_t size = 0;
	struct s_sim_property file_meta={0,};
	TReturn trt = 0;

	char *cmd_str = NULL;

	if (!o)
		return TCORE_RETURN_EINVAL;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	file_meta.file_id = ef;
	file_meta.metainfo.type = SINGLELINE;
	memcpy(file_meta.metainfo.responsePrefix,"+CRSM:",strlen("+CRSM:"));

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), &file_meta);
	dbg("trt[%d]",trt);

	// AT+CRSM=<command>,<fildid>,<p1>,<p2+C29,<p3>
	cmd_str = g_strdup_printf("AT+CRSM=192, %d%s", ef, "\r");

	dbg("new pending(IPC_SEC_RSIM_ACCESS GET - SELECT EF[0x%x])",ef);
	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, _response_get_file_info, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);
	free(cmd_str);

	return TCORE_RETURN_SUCCESS;
}

static gboolean _get_file_data(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int offset, const int length)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	//size_t size = 0;

	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;
	int p1;
	int p2;
	int p3;

	if (!o)
		return FALSE;

	dbg("new pending(IPC_SEC_RSIM_ACCESS GET - READ BIN)");

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

// offset for reading the TRANSPARENT data
	p1 = (unsigned char)(offset & 0xFF00) >> 8;
	p2 = (unsigned char)offset & 0x00FF; //offset low
	p3 = (unsigned char)length;
	dbg("EF[0x%x]", ef);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = SINGLELINE;
	memcpy(metainfo.responsePrefix,"+CRSM:",strlen("+CRSM:"));
	info_len = sizeof(struct ATReqMetaInfo);

	// AT+CRSM=<command>,<fildid>,<p1>,<p2+C29,<p3>
	cmd_str = g_strdup_printf("AT+CRSM=176, %d%s", ef, "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, _response_get_file_data, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);
	free(cmd_str);
	return TRUE;
}

static gboolean _get_file_record(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int index, const int length)
{
	dbg("need to be implemented to use ATCMD");

	return TRUE;
}

static gboolean on_event_pin_status(CoreObject *o, const void *event_info, void *user_data)
{
	UserRequest *ur;
	char *line = (char *) event_info;
	//struct tnoti_sim_status noti_data;
	struct s_sim_property *sp = NULL;
	enum tel_sim_status sim_status = SIM_STATUS_INITIALIZING;
	enum s_sim_sec_locktype_e locktype = SEC_LOCK_TYPE_NONE;
	enum s_sim_sec_lockkey_e lockkey = SEC_LOCK_KEY_NONE;

	dbg("PIN_STATUS NOTI : %s", line);

	_convert_SCPIN_noti(line,&locktype, &lockkey);

	sp = tcore_sim_ref_userdata(o);


	switch (locktype) {
		case SEC_LOCK_TYPE_READY:
			if (lockkey == SEC_LOCK_KEY_UNLOCKED) {
				sim_status = SIM_STATUS_INITIALIZING;
				dbg(" Inside PIN disabled at BOOT UP");
			}
			else {
				dbg(" not handled case p_status->lock_key[%d]", lockkey);
			}
			break;

		case SEC_LOCK_TYPE_PS:
			sim_status = SIM_STATUS_LOCK_REQUIRED;
			dbg( " SIM LOCK required");
			break;

		case SEC_LOCK_TYPE_PF:
			sim_status = SIM_STATUS_CARD_ERROR;
			dbg( "PF required ");
			break;

		case SEC_LOCK_TYPE_SC:
			switch (lockkey) {
				case SEC_LOCK_KEY_UNLOCKED:
					break;
				case SEC_LOCK_KEY_PIN:
					sim_status = SIM_STATUS_PIN_REQUIRED;
					dbg( " PIN1 required");
					break;
				case SEC_LOCK_KEY_PUK:
					sim_status = SIM_STATUS_PUK_REQUIRED;
					dbg( " PUK required");
					break;
				case SEC_LOCK_KEY_PERM_BLOCKED:
					sim_status = SIM_STATUS_CARD_BLOCKED;
					dbg( " Card permanently blocked");
					break;
				default:
					dbg(" SEC_SIM_LOCK_SC -not handled SEC Lock key ");
					break;
			}
			break;

		case SEC_LOCK_TYPE_FD:
			dbg(" SEC_LOCK_TYPE_FD -not handled Notification");
			break;

		case SEC_LOCK_TYPE_PN:
			switch (lockkey) {
				case SEC_LOCK_KEY_PIN:
					dbg(" ADMIN-NCK required");
					sim_status = SIM_STATUS_NCK_REQUIRED;
					break;
				default:
					dbg(" SIM_LOCK_PN/PU/PP/PC -not handled SEC Lock key =[%d]",
							lockkey);
					break;
			}
			break;

		case SEC_LOCK_TYPE_PU:
			dbg("Lock Personalization p_status->lock_key =[%d]", lockkey);
			switch (lockkey) {
				case SEC_LOCK_KEY_PIN:
					dbg(" ADMIN-NSCK required");
					sim_status = SIM_STATUS_NSCK_REQUIRED;
					break;
				default:
					dbg(" SIM_LOCK_PN/PU/PP/PC -not handled SEC Lock key =[%d]",
							lockkey);
					break;
			}
			break;

		case SEC_LOCK_TYPE_PP:
			switch (lockkey) {
				dbg("Lock Personalization p_status->lock_key =[%d]", lockkey);
			case SEC_LOCK_KEY_PIN:
				dbg(" ADMIN-SPCK required");
				sim_status = SIM_STATUS_SPCK_REQUIRED;
				break;
			default:
				dbg(" SIM_LOCK_PN/PU/PP/PC -not handled SEC Lock key =[%d]",
						lockkey);
				break;
			}
			break;

		case SEC_LOCK_TYPE_PC:
			switch (lockkey) {
				dbg("Lock Personalization p_status->lock_key =[%d]", lockkey);
			case SEC_LOCK_KEY_PIN:
				dbg(" ADMIN-CCK required");
				sim_status = SIM_STATUS_CCK_REQUIRED;
				break;
			default:
				dbg(" SIM_LOCK_PN/PU/PP/PC -not handled SEC Lock key =[%d]",
						lockkey);
				break;
			}
			break;

		case SEC_LOCK_TYPE_SC2:
			dbg("SEC_LOCK_TYPE_SC2: NOT Handled - Debug");
			break;

		case SEC_LOCL_TYPE_PUK2:
			dbg("SEC_LOCL_TYPE_PUK2: NOT Handled - Debug");
			break;

		case SEC_LOCK_TYPE_NO_SIM:
			sim_status = SIM_STATUS_CARD_NOT_PRESENT;
			dbg( "NO SIM");
			break;

		case SEC_LOCK_TYPE_UNAVAIL:
		case SEC_SIM_INIT_CRASH: //SMC Lab requirement
			sim_status = SIM_STATUS_CARD_ERROR;
			dbg( "SIM unavailable");
			break;

		case SEC_SIM_INIT_COMPLETED:
			dbg( "[SIM DATA] MODEM SIM INIT COMPLETED");
			sim_status = SIM_STATUS_INIT_COMPLETED;
			break;

		case SEC_PB_INIT_COMPLETED:
			dbg("[SIM DATA] MODEM SIM PB INIT COMPLETED. not handled here! s_phonebook should handle!");
			return TRUE;
			break;

		default:
			dbg(" not handled SEC lock type ");
			break;
	}

	dbg("[SIM]Current co->sim_status[%d] and from modem[0x%x]",tcore_sim_get_status(o), sim_status);

	switch (sim_status) {
		case SIM_STATUS_INIT_COMPLETED:
			ur = tcore_user_request_new(NULL, NULL); //this is for using ur metainfo set/ref functionality.
			_get_file_info(o, ur, SIM_EF_IMSI);
			break;

		case SIM_STATUS_INITIALIZING:
		case SIM_STATUS_PIN_REQUIRED:
		case SIM_STATUS_PUK_REQUIRED:
		case SIM_STATUS_CARD_BLOCKED:
		case SIM_STATUS_NCK_REQUIRED:
		case SIM_STATUS_NSCK_REQUIRED:
		case SIM_STATUS_SPCK_REQUIRED:
		case SIM_STATUS_CCK_REQUIRED:
		case SIM_STATUS_LOCK_REQUIRED:
			if( sp->first_recv_status == SIM_STATUS_UNKNOWN ) {
				dbg("first received sim status[%d]",sim_status);
				sp->first_recv_status = sim_status;
				_get_sim_type(o);
			}
			break;

		case SIM_STATUS_CARD_REMOVED:
		case SIM_STATUS_CARD_NOT_PRESENT:
		case SIM_STATUS_CARD_ERROR:
			if (sim_status == SIM_STATUS_CARD_NOT_PRESENT && tcore_sim_get_status(o) != SIM_STATUS_UNKNOWN)	{
				dbg("[SIM]SIM CARD REMOVED!!");
				sim_status = SIM_STATUS_CARD_REMOVED;
			}
			_sim_status_update(o,sim_status);
			break;

		default:
			dbg("not handled status[%d]", sim_status);
			break;
	}

	return TRUE;
}

static void on_response_verify_pins(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	struct tresp_sim_verify_pins resp = {0,};

	char* line=NULL;
	int ret;
	int error;

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);

	ur = tcore_pending_ref_user_request(p);
	if(!ur)
		dbg("error - current ur is NULL");

	printResponse();

	if(sp_response->success > 0)
	{
		ReleaseResponse();

		resp.result = SIM_PIN_OPERATION_SUCCESS;
		resp.pin_type = _sim_get_current_pin_facility(sp);
		tcore_user_request_send_response(ur, TRESP_SIM_VERIFY_PINS,	sizeof(struct tresp_sim_verify_pins), &resp);
	}
	else
	{
		//failure case - consider this later
		line = sp_response->finalResponse;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&error);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ReleaseResponse();

		// ur = user_request_dup(ur);
		// _get_retry_count(co_sim, ur);

		resp.result = SIM_INCORRECT_PASSWORD;
		resp.pin_type = _sim_get_current_pin_facility(sp);
		resp.retry_count = 3;
		tcore_user_request_send_response(ur, TRESP_SIM_VERIFY_PINS,	sizeof(struct tresp_sim_verify_pins), &resp);

	}
}

static void on_response_verify_puks(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	struct tresp_sim_verify_puks resp = {0,};

	char* line=NULL;
	int ret;
	int error;

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);

	ur = tcore_pending_ref_user_request(p);
	if(!ur)
		dbg("error - current ur is NULL");

	printResponse();

	if(sp_response->success > 0)
	{
		ReleaseResponse();

		resp.result = SIM_PIN_OPERATION_SUCCESS;
		resp.pin_type = _sim_get_current_pin_facility(sp);
		tcore_user_request_send_response(ur, TRESP_SIM_VERIFY_PINS,	sizeof(struct tresp_sim_verify_pins), &resp);
	}
	else
	{
		//failure case - consider this later
		line = sp_response->finalResponse;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&error);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ReleaseResponse();

		// ur = user_request_dup(ur);
		// _get_retry_count(co_sim, ur);

		resp.result = SIM_INCORRECT_PASSWORD;
		resp.pin_type = _sim_get_current_pin_facility(sp);
		tcore_user_request_send_response(ur, TRESP_SIM_VERIFY_PUKS,	sizeof(struct tresp_sim_verify_puks), &resp);

	}
}

static void on_response_change_pins(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	struct tresp_sim_change_pins resp = {0,};

	char* line=NULL;
	int ret;
	int error;

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);

	ur = tcore_pending_ref_user_request(p);
	if(!ur)
		dbg("error - current ur is NULL");

	printResponse();

	if(sp_response->success > 0)
	{
		ReleaseResponse();

		resp.result = SIM_PIN_OPERATION_SUCCESS;
		resp.pin_type = _sim_get_current_pin_facility(sp);
		tcore_user_request_send_response(ur, TRESP_SIM_VERIFY_PINS,	sizeof(struct tresp_sim_verify_pins), &resp);
	}
	else
	{
		//failure case - consider this later
		line = sp_response->finalResponse;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&error);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ReleaseResponse();

		// ur = user_request_dup(ur);
		// _get_retry_count(co_sim, ur);

		resp.result = SIM_INCORRECT_PASSWORD;
		resp.pin_type = _sim_get_current_pin_facility(sp);
		tcore_user_request_send_response(ur, TRESP_SIM_CHANGE_PINS,	sizeof(struct tresp_sim_change_pins), &resp);
	}
}

static void on_response_get_facility_status(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sec_meta = NULL;
	struct tresp_sim_get_facility_status resp = {0,};

	char *line = NULL;
	int ret;

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	sec_meta = (struct s_sim_property*)tcore_user_request_ref_metainfo(ur, NULL);

	resp.result = SIM_PIN_OPERATION_SUCCESS;
	resp.type = _sim_get_current_pin_facility(sec_meta);

	printResponse();

	if(sp_response->success > 0)
	{
		line = sp_response->p_intermediates->line;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,(int *)&resp.b_enable);
		if (ret < 0)
			AT_TOK_ERROR(line);
	}
	else
	{
		resp.result = SIM_INCOMPATIBLE_PIN_OPERATION;
	}

	ReleaseResponse();

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SIM_GET_FACILITY_STATUS,
				sizeof(struct tresp_sim_get_facility_status), &resp);
	}
}

static void on_response_enable_facility(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sec_meta = NULL;
	struct tresp_sim_enable_facility resp = {0,};
	struct s_sim_property *sp = NULL;

	char *line = NULL;
	int ret;

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	sp = tcore_sim_ref_userdata(co_sim);
	sec_meta = (struct s_sim_property*)tcore_user_request_ref_metainfo(ur, NULL);

	resp.result = SIM_PIN_OPERATION_SUCCESS;
	resp.type = _sim_get_current_pin_facility(sec_meta);

	printResponse();

	if(sp_response->success > 0)
	{
		line = sp_response->p_intermediates->line;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,(int *)&resp.result);
		if (ret < 0)
			AT_TOK_ERROR(line);
	}
	else
	{
		resp.result = SIM_INCOMPATIBLE_PIN_OPERATION;
	}

	ReleaseResponse();

	if (ur) {
		resp.type = _sim_get_current_pin_facility(sp);
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_enable_facility), &resp);
	}
}

static void on_response_disable_facility(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sec_meta = NULL;
	struct tresp_sim_disable_facility resp = {0,};
	struct s_sim_property *sp = NULL;

	char *line = NULL;
	int ret;

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	sp = tcore_sim_ref_userdata(co_sim);
	sec_meta = (struct s_sim_property*)tcore_user_request_ref_metainfo(ur, NULL);

	resp.result = SIM_PIN_OPERATION_SUCCESS;
	resp.type = _sim_get_current_pin_facility(sec_meta);

	printResponse();

	if(sp_response->success > 0)
	{
		line = sp_response->p_intermediates->line;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,(int *)&resp.result);
		if (ret < 0)
			AT_TOK_ERROR(line);
	}
	else
	{
		resp.result = SIM_INCOMPATIBLE_PIN_OPERATION;
	}

	ReleaseResponse();

	if (ur) {
		resp.type = _sim_get_current_pin_facility(sp);
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_disable_facility), &resp);
	}
}

static TReturn s_verify_pins(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;

	struct s_sim_property *sp = NULL;
	const struct treq_sim_verify_pins *req_data;
	TReturn trt = 0;

	char *cmd_str = NULL;

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);
	req_data = tcore_user_request_ref_data(ur, NULL);
	sp = tcore_sim_ref_userdata(o);

	if (req_data->pin_type == SIM_PTYPE_PIN1) {
		sp->current_sec_op = SEC_PIN1_VERIFY;
	}
	else if (req_data->pin_type == SIM_PTYPE_PIN2) {
		sp->current_sec_op = SEC_PIN2_VERIFY;
	}
	else if (req_data->pin_type == SIM_PTYPE_SIM) {
		sp->current_sec_op = SEC_SIM_VERIFY;
	}
	else if (req_data->pin_type == SIM_PTYPE_ADM) {
		sp->current_sec_op = SEC_ADM_VERIFY;
	}
	else {
		return TCORE_RETURN_EINVAL;
	}

	sp->metainfo.type = NO_RESULT;
	sp->metainfo.responsePrefix[0] = '\0';

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), sp);
	dbg("trt[%d]",trt);


	// AT+CPIN=<pin>[,<newpin>]
	cmd_str = g_strdup_printf("AT+CPIN=\"%s\"%s", req_data->pin, "\r");
	dbg("new pending(verify - pins), %s", cmd_str);

	pending = tcore_pending_new(o,ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, on_response_verify_pins, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);

	free(cmd_str);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_verify_puks(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;

	const struct treq_sim_verify_puks *req_data;
	struct s_sim_property *sp = NULL;
	TReturn trt = 0;

	char *cmd_str = NULL;

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);
	req_data = tcore_user_request_ref_data(ur, NULL);
	sp = tcore_sim_ref_userdata(o);


	if(req_data->puk_type == SIM_PTYPE_PUK1){
		sp->current_sec_op = SEC_PUK1_VERIFY;
	}
	else if(req_data->puk_type == SIM_PTYPE_PUK2){
		sp->current_sec_op = SEC_PUK2_VERIFY;
	}
	else {
		return TCORE_RETURN_EINVAL;
	}

	sp->metainfo.type = NO_RESULT;
	sp->metainfo.responsePrefix[0] = '\0';

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), sp);
	dbg("trt[%d]",trt);

	// AT+CPIN=<pin>[,<newpin>]
	cmd_str = g_strdup_printf("AT+CPIN=\"%s\", \"%s\"%s", req_data->puk, req_data->pin, "\r");

	dbg("new pending(IPC_SEC_PIN_STATUS SET - verify puks)");
	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, on_response_verify_puks, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);

	free(cmd_str);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_change_pins(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;

	const struct treq_sim_change_pins *req_data;
	struct s_sim_property *sp = NULL;
	TReturn trt = 0;

	char *cmd_str = NULL;

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);
	req_data = tcore_user_request_ref_data(ur, NULL);
	sp = tcore_sim_ref_userdata(o);

	if(req_data->type == SIM_PTYPE_PIN1) {
		sp->current_sec_op = SEC_PIN1_CHANGE;
	}
	else if(req_data->type == SIM_PTYPE_PIN2) {
		sp->current_sec_op = SEC_PIN2_CHANGE;
	}
	else {
		return TCORE_RETURN_EINVAL;
	}

	sp->metainfo.type = NO_RESULT;
	sp->metainfo.responsePrefix[0] = '\0';

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), sp);
	dbg("trt[%d]",trt);

	// AT+CPIN=<pin>[,<newpin>]
	cmd_str = g_strdup_printf("AT+CPIN=\"%s\", \"%s\"%s", req_data->old_pin, req_data->new_pin, "\r");

	dbg("new pending(IPC_SEC_CHANGE_LOCKING_PW SET)");
	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, on_response_change_pins, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);

	free(cmd_str);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_get_facility_status(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	struct s_sim_property sec_meta = {0,};
	TReturn trt = 0;

	const struct treq_sim_get_facility_status *req_data;
	char *fac = "SC";
	int mode = 2;		// 2:query, 0: unlock, 1:lock

	char *cmd_str = NULL;
//	struct ATReqMetaInfo metainfo;

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if(req_data->type == SIM_FACILITY_PS)
		fac = "PS";
	else if(req_data->type == SIM_FACILITY_SC)
		fac = "SC";
	else if(req_data->type == SIM_FACILITY_FD)
		fac = "FD";
	else if(req_data->type == SIM_FACILITY_PN)
		fac = "PN";
	else if(req_data->type == SIM_FACILITY_PU)
		fac = "PU";
	else if(req_data->type == SIM_FACILITY_PP)
		fac = "PP";
	else if(req_data->type == SIM_FACILITY_PC)
		fac = "PC";
	else
		return TCORE_RETURN_EINVAL;

	sec_meta.current_sec_op = req_data->type;
	sec_meta.metainfo.type = SINGLELINE;
	memcpy(sec_meta.metainfo.responsePrefix,"+CLCK:",strlen("+CLCK:"));

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), &sec_meta);
	dbg("trt[%d]",trt);

	// AT+CLCK=<fac>,<mode>,<password>
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d%s", fac, mode, "\r");

	dbg("new pending(IPC_SEC_PHONE_LOCK GET)");
	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, on_response_get_facility_status, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);

	free(cmd_str);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_enable_facility(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	struct s_sim_property sec_meta = {0,};
	const struct treq_sim_enable_facility *req_data;
	struct s_sim_property *sp = NULL;
	char *fac = "SC";
	int mode = 1;		// 2:query, 0: unlock, 1:lock

	char *cmd_str = NULL;
//	struct ATReqMetaInfo metainfo;

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);
	req_data = tcore_user_request_ref_data(ur, NULL);
	sp = tcore_sim_ref_userdata(o);

	if (req_data->type == SIM_FACILITY_PS)
		fac = "PS";
	else if (req_data->type == SIM_FACILITY_SC)
		fac = "SC";
	else if (req_data->type == SIM_FACILITY_FD)
		fac = "FD";
	else if (req_data->type == SIM_FACILITY_PN)
		fac = "PN";
	else if (req_data->type == SIM_FACILITY_PU)
		fac = "PU";
	else if (req_data->type == SIM_FACILITY_PP)
		fac = "PP";
	else if (req_data->type == SIM_FACILITY_PC)
		fac = "PC";
	else
		return TCORE_RETURN_EINVAL;

	sp->current_sec_op = SEC_SIM_ENABLE;

	sec_meta.current_sec_op = req_data->type;
	sec_meta.metainfo.type = SINGLELINE;
	memcpy(sec_meta.metainfo.responsePrefix,"+CLCK:",strlen("+CLCK:"));

	tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), &sec_meta);

	// AT+CLCK=<fac>,<mode>,<password>
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, %s%s", fac, mode, req_data->password,"\r");
	dbg("new pending(enable_facility), %s", cmd_str);

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, on_response_enable_facility, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);

	free(cmd_str);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_disable_facility(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	struct s_sim_property sec_meta = {0,};
	const struct treq_sim_enable_facility *req_data;
	struct s_sim_property *sp = NULL;
	char *fac = "SC";
	int mode = 0;		// 2:query, 0: unlock, 1:lock

	char *cmd_str = NULL;
	//	struct ATReqMetaInfo metainfo;

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);
	req_data = tcore_user_request_ref_data(ur, NULL);
	sp = tcore_sim_ref_userdata(o);

	if (req_data->type == SIM_FACILITY_PS)
		fac = "PS";
	else if (req_data->type == SIM_FACILITY_SC)
		fac = "SC";
	else if (req_data->type == SIM_FACILITY_FD)
		fac = "FD";
	else if (req_data->type == SIM_FACILITY_PN)
		fac = "PN";
	else if (req_data->type == SIM_FACILITY_PU)
		fac = "PU";
	else if (req_data->type == SIM_FACILITY_PP)
		fac = "PP";
	else if (req_data->type == SIM_FACILITY_PC)
		fac = "PC";
	else
		return TCORE_RETURN_EINVAL;

	sp->current_sec_op = SEC_SIM_ENABLE;

	sec_meta.current_sec_op = req_data->type;
	sec_meta.metainfo.type = SINGLELINE;
	memcpy(sec_meta.metainfo.responsePrefix,"+CLCK:",strlen("+CLCK:"));

	tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), &sec_meta);

	// AT+CLCK=<fac>,<mode>,<password>
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, %s%s", fac, mode, req_data->password,"\r");
	dbg("new pending(enable_facility), %s", cmd_str);

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, on_response_disable_facility, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(h, pending);

	free(cmd_str);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_read_file(CoreObject *o, UserRequest *ur)
{
	TReturn api_ret = TCORE_RETURN_SUCCESS;
	enum tcore_request_command command;
	command = tcore_user_request_get_command(ur);

	dbg("enter");

	switch (command) {
		case TREQ_SIM_GET_ECC:
			api_ret = _get_file_info(o, ur, SIM_EF_ECC);
			break;

		case TREQ_SIM_GET_LANGUAGE:
			if (tcore_sim_get_type(o) == SIM_TYPE_GSM)
				api_ret = _get_file_info(o, ur, SIM_EF_ELP);
			else if (tcore_sim_get_type(o) == SIM_TYPE_USIM)
				api_ret = _get_file_info(o, ur, SIM_EF_LP);
			else
				api_ret = TCORE_RETURN_ENOSYS;
			break;

		case TREQ_SIM_GET_ICCID:
			api_ret = _get_file_info(o, ur, SIM_EF_ICCID);
			break;

		case TREQ_SIM_GET_MAILBOX:
			if(tcore_sim_get_cphs_status(o))
				api_ret = _get_file_info(o, ur, SIM_EF_CPHS_MAILBOX_NUMBERS);
			else
				api_ret = _get_file_info(o, ur, SIM_EF_MBDN);
			break;

		case TREQ_SIM_GET_CALLFORWARDING:
			if(tcore_sim_get_cphs_status(o))
				api_ret = _get_file_info(o, ur, SIM_EF_CPHS_CALL_FORWARD_FLAGS);
			else
				api_ret = _get_file_info(o, ur, SIM_EF_USIM_CFIS);
			break;

		case TREQ_SIM_GET_MESSAGEWAITING:
			if(tcore_sim_get_cphs_status(o))
				api_ret = _get_file_info(o, ur, SIM_EF_CPHS_VOICE_MSG_WAITING);
			else
				api_ret = _get_file_info(o, ur, SIM_EF_USIM_MWIS);
			break;

		case TREQ_SIM_GET_CPHS_INFO:
			if(tcore_sim_get_cphs_status(o))
				api_ret = _get_file_info(o, ur, SIM_EF_CPHS_CPHS_INFO);
			else
				api_ret = TCORE_RETURN_ENOSYS;
			break;

		case TREQ_SIM_GET_MSISDN:
			api_ret = _get_file_info(o, ur, SIM_EF_MSISDN);
			break;

		case TREQ_SIM_GET_SPN:
			dbg("enter case SPN");
			api_ret = _get_file_info(o, ur, SIM_EF_SPN);
			break;

		case TREQ_SIM_GET_SPDI:
			api_ret = _get_file_info(o, ur, SIM_EF_SPDI);
			break;

		case TREQ_SIM_GET_OPL:
			api_ret = _get_file_info(o, ur, SIM_EF_OPL);
			break;

		case TREQ_SIM_GET_PNN:
			api_ret = _get_file_info(o, ur, SIM_EF_PNN);
			break;

		case TREQ_SIM_GET_CPHS_NETNAME:
			api_ret = _get_file_info(o, ur, SIM_EF_CPHS_OPERATOR_NAME_STRING);
			break;

		case TREQ_SIM_GET_OPLMNWACT:
			api_ret = _get_file_info(o, ur, SIM_EF_OPLMN_ACT);
			break;

		default:
			dbg("error - not handled read treq command[%d]", command);
			api_ret = TCORE_RETURN_EINVAL;
			break;
	}
	return api_ret;
}

static TReturn s_update_file(CoreObject *o, UserRequest *ur)
{
	TReturn api_ret = TCORE_RETURN_ENOSYS;
	return api_ret;
}

static TReturn s_transmit_apdu(CoreObject *o, UserRequest *ur)
{
	dbg("need to be implemented to use ATCMD");

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_get_atr(CoreObject *o, UserRequest *ur)
{
	dbg("need to be implemented to use ATCMD");

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_req_authentication(CoreObject *o, UserRequest *ur)
{
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_sim_operations sim_ops =
{
		.verify_pins = s_verify_pins,
		.verify_puks = s_verify_puks,
		.change_pins = s_change_pins,
		.get_facility_status = s_get_facility_status,
		.enable_facility = s_enable_facility,
		.disable_facility = s_disable_facility,
		.read_file = s_read_file,
		.update_file = s_update_file,
		.transmit_apdu = s_transmit_apdu,
		.get_atr = s_get_atr,
		.req_authentication = s_req_authentication
};

gboolean s_sim_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *o;
	struct s_sim_property *sp = NULL;

	o = tcore_sim_new(p, "sim", &sim_ops, h);
	if (!o)
		return FALSE;

	sp = calloc(sizeof(struct s_sim_property),1);
	if (!sp)
		return FALSE;

	sp->first_recv_status = SIM_STATUS_UNKNOWN;
	tcore_sim_link_userdata(o, sp);

	tcore_object_add_callback(o, EVENT_SIM_PIN_STATUS, on_event_pin_status, NULL);
	return TRUE;
}


void s_sim_exit(TcorePlugin *p)
{
	CoreObject *o;

	o = tcore_plugin_ref_core_object(p, "sim");
	if (!o)
		return;
	tcore_sim_free(o);
}
