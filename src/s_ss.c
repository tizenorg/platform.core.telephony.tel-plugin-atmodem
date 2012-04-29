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
#include <queue.h>
#include <co_call.h>
#include <co_ss.h>
#include <user_request.h>
#include <server.h>

#include "s_common.h"
#include "s_ss.h"
#include "util.h"

#include "atchannel.h"
#include "at_tok.h"

extern struct ATResponse *sp_response;
extern char *s_responsePrefix;
extern enum ATCommandType s_type;


gboolean gcf = FALSE;

enum  telephony_ss_opcode {
  TIZEN_SS_OPCO_REG=0x01,         /* 0x01 : Registration */
  TIZEN_SS_OPCO_DEREG,              /* 0x02 : De-registration( erase ) */
  TIZEN_SS_OPCO_ACTIVATE,        /* 0x03 : Activation */
  TIZEN_SS_OPCO_DEACTIVATE,    /* 0x04 : De-activation */
  TIZEN_SS_OPCO_MAX
} ;


struct ss_confirm_info {
	enum telephony_ss_class class;
	int  flavor_type;
	enum tcore_response_command resp;
	void *data;
	int  data_len;
};

 #define TIZEN_NUM_TYPE_INTERNATIONAL  0x01  
 #define TIZEN_NUM_PLAN_ISDN  0x01            


static gboolean	_ss_request_message( CoreObject *o, 
									 UserRequest *ur,
									 char *cmd, 
									 unsigned int cmd_len, 
									 void* on_resp, 
									 void* user_data );
#if 0
static TReturn	_ss_general_response_result(const int result);
#endif

static TReturn _ss_barring_get( CoreObject *o, 
								UserRequest *ur, 
								enum telephony_ss_class class, 
								enum telephony_ss_barring_mode type, 
								enum tcore_response_command resp );

static TReturn _ss_forwarding_get(	CoreObject *o, 
									UserRequest *ur, 
									enum telephony_ss_class class, 
									enum telephony_ss_forwarding_mode type, 
									enum tcore_response_command resp );

static TReturn _ss_waiting_get( CoreObject *o, 
								UserRequest *ur, 
								enum telephony_ss_class class, 
								enum tcore_response_command resp );


static TReturn s_ss_barring_activate( CoreObject *o, UserRequest *ur );
static TReturn s_ss_barring_deactivate( CoreObject *o, UserRequest *ur );
static TReturn s_ss_barring_change_password( CoreObject *o, UserRequest *ur );
static TReturn s_ss_barring_get_status( CoreObject *o, UserRequest *ur );

static TReturn s_ss_forwarding_activate( CoreObject *o, UserRequest *ur );
static TReturn s_ss_forwarding_deactivate( CoreObject *o, UserRequest *ur );
static TReturn s_ss_forwarding_register( CoreObject *o, UserRequest *ur );
static TReturn s_ss_forwarding_deregister( CoreObject *o, UserRequest *ur );
static TReturn s_ss_forwarding_get_status( CoreObject *o, UserRequest *ur );

static TReturn s_ss_waiting_activate( CoreObject *o, UserRequest *ur );
static TReturn s_ss_waiting_deactivate( CoreObject *o, UserRequest *ur );
static TReturn s_ss_waiting_get_status( CoreObject *o, UserRequest *ur );

static TReturn s_ss_cli_activate( CoreObject *o, UserRequest *ur );
static TReturn s_ss_cli_deactivate( CoreObject *o, UserRequest *ur );
static TReturn s_ss_cli_get_status( CoreObject *o, UserRequest *ur );

static TReturn s_ss_send_ussd( CoreObject *o, UserRequest *ur );

static TReturn s_ss_set_aoc( CoreObject *o, UserRequest *ur );
static TReturn s_ss_get_aoc( CoreObject *o, UserRequest *ur );

static TReturn	s_ss_manage_call_0_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data );
static TReturn	s_ss_manage_call_1_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data );
static TReturn	s_ss_manage_call_1x_send( CoreObject* o, UserRequest* ur, const int id, ConfirmCallback cb, void* user_data );
static TReturn	s_ss_manage_call_2_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data );
static TReturn	s_ss_manage_call_2x_send( CoreObject* o, UserRequest* ur, const int id, ConfirmCallback cb, void* user_data );
static TReturn	s_ss_manage_call_3_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data );
static TReturn	s_ss_manage_call_4_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data );
static TReturn	s_ss_manage_call_4dn_send( CoreObject* o, UserRequest* ur, const char* number, ConfirmCallback cb, void* user_data );
/*
static TReturn	s_ss_manage_call_5_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data );
static TReturn	s_ss_manage_call_6_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data );
*/

static void on_confirmation_call_control_ss_message_send( TcorePending *p, gboolean result, void *user_data );

static void		on_confirmation_ss_message_send( TcorePending *p, gboolean result, void *user_data );


static void		on_notification_ss_info( CoreObject *o, const void *data, void *user_data );

static void		_ss_ussd_response( UserRequest *ur, const char* ussd_str, enum telephony_ss_ussd_type type, enum telephony_ss_ussd_status status );
static void		_ss_ussd_notification( TcorePlugin *p, const char* ussd_str, enum telephony_ss_ussd_status status );
static void		on_notification_ss_ussd( CoreObject *o, const void *data, void *user_data );


static gboolean _ss_request_message( CoreObject *o, 
									 UserRequest *ur,
									 char *cmd, 
									 unsigned int cmd_len, 
									 void* on_resp, 
									 void* user_data )
{
	TcorePending *pending = 0;
	TcorePlugin *p = 0;
	TcoreHal *h = 0;
	UserRequest *ur2 = 0;

	ur2 = tcore_user_request_dup( ur );

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, cmd_len, cmd);
	tcore_pending_set_timeout(pending, 0);

	if ( on_resp )
		tcore_pending_set_response_callback(pending, on_resp, user_data);

	tcore_pending_set_send_callback(pending, on_confirmation_ss_message_send, 0);

	if ( !ur2 ) {
		dbg("[ check ] ur is 0, is this internal request??");
	} else {
		tcore_pending_link_user_request(pending, ur2);
	}

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);
	tcore_hal_send_request(h, pending);

	return TRUE;
}

#if 0
static TReturn _ss_general_response_result(const int ret)
{
	if (ret == 0x8000 || ret == 0x8100) {
		return TCORE_RETURN_SUCCESS;
	}

	return TCORE_RETURN_3GPP_ERROR + ret;
}
#endif

static void _ss_ussd_response( UserRequest *ur, const char* ussd_str, enum telephony_ss_ussd_type type, enum telephony_ss_ussd_status status ) 
{
	struct tresp_ss_ussd resp;

	if ( !ur ) {
		dbg("[ error ] ur : (NULL)");
		return ;
	}

	resp.type = type;
	resp.status = status;
	resp.err = FALSE;

	if ( ussd_str ) {
	
		int len = strlen( ussd_str );

		if ( len < MAX_SS_USSD_LEN ) {
			memcpy( resp.str, ussd_str, len );
			resp.str[ len ] = '\0';
		} else {
			memcpy( resp.str, ussd_str, MAX_SS_USSD_LEN );
			resp.str[ MAX_SS_USSD_LEN - 1 ] = '\0';
		}

		dbg("resp.str : %s", resp.str);

	} else {

		memset( resp.str, '\0', MAX_SS_USSD_LEN );

	}

	tcore_user_request_send_response(ur, TRESP_SS_SEND_USSD, sizeof(struct tresp_ss_ussd), &resp);
}

static void _ss_ussd_notification( TcorePlugin *p, const char* ussd_str, enum telephony_ss_ussd_status status )
{
	CoreObject *o = 0;
	struct tnoti_ss_ussd noti;

	if ( !p ) {
		dbg("[ error ] p : (NULL)");
		return ;
	}

	noti.status = status;

	if ( ussd_str ) {

		int len = strlen( ussd_str );

		if ( len < MAX_SS_USSD_LEN ) {
			memcpy( noti.str, ussd_str, len );
			noti.str[ len ] = '\0';
		} else {
			memcpy( noti.str, ussd_str, MAX_SS_USSD_LEN );
			noti.str[ MAX_SS_USSD_LEN - 1 ] = '\0';
		}

	} else {

		memset( noti.str, '\0', MAX_SS_USSD_LEN );

	}

	o = tcore_plugin_ref_core_object(p, "ss");

	tcore_server_send_notification(	tcore_plugin_ref_server(p),
			o,
			TNOTI_SS_USSD,
			sizeof(struct tnoti_ss_ussd),
			(void*)&noti	);

}

static void	on_notification_ss_ussd( CoreObject *o, const void *data, void *user_data )
{
	enum telephony_ss_ussd_status status;
	UssdSession *ussd_session = 0;
	char *ussd_str = 0, *cmd = 0, *tmp_str=0;
	TcorePlugin *p = 0;
	int err =0, m=0, dcs=0;

	p = tcore_object_ref_plugin(o);

	ussd_session = tcore_ss_ussd_get_session(o);

	cmd = (char*)data;

	// parse ussd status
	at_tok_start(&cmd);
	err = at_tok_nextint(&cmd, &m);
	dbg("m: %d", m);

	switch(m){
		case 0:
			status = SS_USSD_NO_ACTION_REQUIRE;
		break;

		case 1:
			status = SS_USSD_ACTION_REQUIRE;
		break;

		case 2:
			status = SS_USSD_TERMINATED_BY_NET;
		break;		

		case 3:
			status = SS_USSD_OTHER_CLIENT;
		break;	

		case 4:
			status = SS_USSD_NOT_SUPPORT;
		break;

		case 5:
			status = SS_USSD_TIME_OUT;
		break;

		default:
			dbg("unsupported m : %d", m);
			status = SS_USSD_MAX;
		break;
	}

	if(at_tok_hasmore(&cmd))
	{
		err = at_tok_nextstr(&cmd, &tmp_str);		
		err = at_tok_nextint(&cmd, &dcs);

		dbg("ussdstr: %s, dcs :%d", tmp_str, dcs);

	}

	switch ( tcore_util_get_cbs_coding_scheme(dcs) ) {
		case TCORE_DCS_TYPE_7_BIT:
		case TCORE_DCS_TYPE_UNSPECIFIED: {
			ussd_str = tcore_util_unpack_gsm7bit(tmp_str, strlen(tmp_str));
		} break;

		case TCORE_DCS_TYPE_UCS2:
		case TCORE_DCS_TYPE_8_BIT: {
			if ( strlen(tmp_str)  > 0 ) {
				ussd_str = g_new0( char, strlen(tmp_str)  + 1);
				memcpy( ussd_str,tmp_str, strlen(tmp_str) );
				ussd_str[ strlen(tmp_str) ] = '\0';
			}
		} break;					   
		default: {
			dbg("[ error ] unknown dcs type. ussd_session : %x", ussd_session);
			if ( ussd_session ) {

				UserRequest *ur = 0;
				enum telephony_ss_ussd_type type;

				tcore_ss_ussd_get_session_data( ussd_session, (void**)&ur );
				if ( !ur ) {
					dbg("[ error ] ur : (0)");
					return;
				}

				type = (enum telephony_ss_ussd_type)tcore_ss_ussd_get_session_type( ussd_session );

				_ss_ussd_response( ur, ussd_str, type, status );
			} 
			return;
		}
	}

	switch ( status ) {
	case SS_USSD_NO_ACTION_REQUIRE: 
	case SS_USSD_ACTION_REQUIRE:
	case SS_USSD_OTHER_CLIENT:
	case SS_USSD_NOT_SUPPORT:
	case SS_USSD_TIME_OUT: {

	//	UserRequest *ur = 0;

		if ( ussd_session ) {

			UserRequest *ur = 0;
			enum telephony_ss_ussd_type type;

			tcore_ss_ussd_get_session_data( ussd_session, (void**)&ur );
			if ( !ur ) {
				dbg("[ error ] ur : (0)");
				return;
			}

			type = (enum telephony_ss_ussd_type)tcore_ss_ussd_get_session_type( ussd_session );

			_ss_ussd_response( ur, (const char*)ussd_str, type, status );

			g_free( ussd_str );

		} else {

			tcore_ss_ussd_create_session( o, TCORE_SS_USSD_TYPE_NETWORK_INITIATED, 0, 0 );

			_ss_ussd_notification( p, (const char*)ussd_str, status );

			g_free( ussd_str );
		}

	} break;										
	case SS_USSD_TERMINATED_BY_NET: {

		if ( ussd_session ) {
			UserRequest *ur = 0;

			tcore_ss_ussd_get_session_data( ussd_session, (void**)&ur );

			if ( ur )
				tcore_user_request_free( ur );

			tcore_ss_ussd_destroy_session( ussd_session );
		}

	} break;										
	default:
	break;
	}

}

static void	on_notification_ss_info( CoreObject *o, const void *data, void *user_data )
{
	TcorePlugin *p  = 0;
	CoreObject *co = 0;
	char* cmd = 0, *number = 0;
	int code2 =0, err=0, index=0, ton=0;


	p	= tcore_object_ref_plugin( o );
	co	= tcore_plugin_ref_core_object( p, "call" );
	if (!co) {
		dbg("[ error ] plugin_ref_core_object : call");
		return ;
	}

	cmd = (char*)data;
	at_tok_start(&cmd);

	err = at_tok_nextint(&cmd, &code2);
	dbg("code2 : %d",code2);

	if(at_tok_hasmore(&cmd))
		err = at_tok_nextint(&cmd, &index); //cug index - skip
	if(at_tok_hasmore(&cmd)){
		err = at_tok_nextstr(&cmd, &number);
		dbg("number : %s",number);	
		err = at_tok_nextint(&cmd, &ton);
	}

	switch(code2){
		case 0:  //this is a forwarded call (MT call setup)
			tcore_call_information_mt_forwarded_call( co, number );
		break;

		case 2: //call has been put on hold (during a voice call)
			tcore_call_information_held( co, number );
		break;

		case 3: //call has been retrieved (during a voice call)
			tcore_call_information_active( co, number );
		break;

		case 4: //multiparty call entered (during a voice call)
			tcore_call_information_joined( co, number );
		break;

		case 5: //call on hold has been released
			tcore_call_information_released_on_hold( co, number );
		break;

		case 6: //forward check SS message received (can be received whenever)
			tcore_call_information_cf_check_ss_message( co, number );
		break;		

		case 7: //call is being connected (alerting) with the remote party in alerting state in explicit call transfer operation (during a voice call) 
			tcore_call_information_transfer_alert( co, number );
		break;	

		case 8: //call has been connected with the other remote party in explicit call transfer operation (also number and subaddress parameters may be present) (during a voice call or MT call setup)
			tcore_call_information_transfered( co, number );
		break;			

		case 9: //this is a deflected call (MT call setup):
			tcore_call_information_mt_deflected_call( co, number );
		break;		

		default:
			dbg("unsupported cmd2 : %d",code2);	
		break;
	}
}

static void on_confirmation_ss_message_send( TcorePending *p, gboolean result, void *user_data )
{
	UserRequest* ur = NULL;
	struct ATReqMetaInfo* metainfo = NULL;
	unsigned int info_len =0;
	dbg("on_confirmation_ss_message_send - msg out from queue. alloc ATRsp buffer & write rspPrefix if needed\n");

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
}
	
static void on_confirmation_call_control_ss_message_send( TcorePending *p, gboolean result, void *user_data )
{
	UserRequest* ur = NULL;
	struct ATReqMetaInfo* metainfo = NULL;
	unsigned int info_len =0;
	dbg("on_confirmation_call_control_ss_message_send - msg out from queue. alloc ATRsp buffer & write rspPrefix if needed\n");

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
}

static void on_response_ss_barring_set( TcorePending *p, int data_len, const void *data, void *user_data ) 
{
	struct ss_confirm_info *info = 0;
	enum telephony_ss_class class;
	
	CoreObject* o = 0;
	UserRequest *ur;
	struct tresp_ss_general resp;
	UserRequest *ur_dup=0;
	
	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	printResponse();	

	info = (struct ss_confirm_info*)user_data;
	class = info->class;


	if(sp_response->success > 0){
		resp.err = TCORE_RETURN_SUCCESS;
	}
	else{
		resp.err = TCORE_RETURN_FAILURE;
	}

	dbg("on_response_ss_barring_set - rsp.err : %d, ur : %x", resp.err, ur);


	if(sp_response->success > 0)
	{
		ReleaseResponse();

		if ( info->class == SS_CLASS_VOICE ) 
			class = SS_CLASS_ALL_TELE_BEARER;

		ur_dup = tcore_user_request_dup(ur);

		if ( info->flavor_type == SS_BARR_MODE_AB || 
			 info->flavor_type == SS_BARR_MODE_AOB )
			_ss_barring_get( o, ur_dup, class, SS_BARR_MODE_BAOC, info->resp );
		else if ( info->flavor_type == SS_BARR_MODE_AIB )
			_ss_barring_get( o, ur_dup, class, SS_BARR_MODE_BAIC, info->resp );
		else
			_ss_barring_get( o, ur_dup, class, info->flavor_type, info->resp );

	}
	else
	{
		ReleaseResponse();

		if ( ur )
			tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_general), &resp);
		else 
			dbg("[ error ] ur is 0");

	}

	g_free(user_data);


}
static void on_response_ss_barring_change_pwd( TcorePending *p, int data_len, const void *data, void *user_data ) 
{
	struct ss_confirm_info *info = 0;
	UserRequest *ur;
	struct tresp_ss_general resp;

	ur = tcore_pending_ref_user_request(p);
	
	info = (struct ss_confirm_info*)user_data;

	printResponse();

	if(sp_response->success > 0){
		resp.err = TCORE_RETURN_SUCCESS;
	}
	else{
		resp.err = TCORE_RETURN_FAILURE;
	}

	ReleaseResponse();

	dbg("on_response_ss_barring_change_pwd: rsp.err : %d, usr : %x", resp.err, ur);

	if ( ur )
		tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_general), &resp);
	else 
		dbg("[ error ] ur is 0");

	g_free(user_data);

}


static void on_response_ss_barring_get( TcorePending *p, int data_len, const void *data, void *user_data ) 
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;
    	struct ATLine *p_cur;
	int status=0, classx =0, err=0;
		
	struct ss_confirm_info* info = 0;
	struct tresp_ss_barring resp;
	int countRecords=0, countValidRecords =0;

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	printResponse();	

	info = (struct ss_confirm_info*)user_data;

	/* count the calls */
	for (countRecords = 0, p_cur = sp_response->p_intermediates
	        ; p_cur != NULL
	        ; p_cur = p_cur->p_next
	) {
	    countRecords++;
	}
	dbg("total records : %d",countRecords);	


	resp.record_num = countRecords;

	if ( resp.record_num > 0 ) {
//		int i = 0;

		resp.record = g_new0( struct barring_info, resp.record_num );

		for (countValidRecords = 0, p_cur = sp_response->p_intermediates
            		; p_cur != NULL
            		; p_cur = p_cur->p_next)
		{
			err = at_tok_start(&(p_cur->line));
			if (err < 0){
				dbg("start line error. skip this line");				
				goto error;		
			}
			err = at_tok_nextint(&(p_cur->line), &status);// status
			if (err < 0) {
				dbg("status error. skip this line");				
				goto error;		
			}			
	
			if(status == 1){
				resp.record[countValidRecords].status = SS_STATUS_ACTIVATE;
			}
			else	{
				resp.record[countValidRecords].status = SS_STATUS_DEACTIVATE;
			}

			err = at_tok_nextint(&(p_cur->line), &classx); //class
			if (err < 0) {
				dbg("class error. classx not exist - set to requested one : %d", info->class);
				switch(info->class){
				case SS_CLASS_ALL_TELE:
					classx =7;
				break;
				case SS_CLASS_VOICE:
					classx =1;
				break;
				case SS_CLASS_ALL_DATA_TELE:
					classx =2;
				break;
				case SS_CLASS_FAX:
					classx =4;
				break;
				case SS_CLASS_SMS:
					classx = 8;
				break;
				case SS_CLASS_ALL_CS_SYNC:
					classx = 16;
				break;

				default:
					classx =7;
					dbg("unsupported class %d. set to default : 7", info->class);
				break;
				}
			}	

			switch(classx){
				case 1:
					resp.record[countValidRecords].class = SS_CLASS_VOICE;
				break;
				case 2:
					resp.record[countValidRecords].class = SS_CLASS_ALL_DATA_TELE;
				break;		
				case 4:
					resp.record[countValidRecords].class = SS_CLASS_FAX;
				break;					
				case 7:
					resp.record[countValidRecords].class = SS_CLASS_ALL_TELE;
				break;
				case 8:
					resp.record[countValidRecords].class = SS_CLASS_SMS;
				break;					
				case 16:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_SYNC;
				break;					
				case 32:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_ASYNC;
				break;	
				default:
					dbg("unspoorted class : [%d]\n", classx );	
					goto error;
				break;
			}

			resp.record[countValidRecords].mode = (enum telephony_ss_barring_mode)(info->flavor_type);

			countValidRecords++;
			continue;
error:
			dbg("invalid field found. coutinue");
			continue;
		}

		dbg("valid count :%d",countValidRecords);
		resp.record_num = countValidRecords;
		resp.err = TCORE_RETURN_SUCCESS;
		
	}
	else
	{
		dbg("no active status - return to user")
		resp.err = TCORE_RETURN_FAILURE;
	}
	dbg("on_response_ss_barring_get- rsp.err : %d, ur : %x", resp.err, ur);

	ReleaseResponse();

	if ( ur )
		tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_barring), &resp);
	else 
		dbg("[ error ] ur is 0");

	g_free( user_data );
	
}

static void on_response_ss_forwarding_set( TcorePending *p, int data_len, const void *data, void *user_data ) 
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0, *dup_ur=0;
	struct ss_confirm_info *info = 0;
	struct tresp_ss_general resp;

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);	

	info = (struct ss_confirm_info*)user_data;

	printResponse();

	if(sp_response->success > 0){
		resp.err = TCORE_RETURN_SUCCESS;
	}else{
		resp.err = TCORE_RETURN_FAILURE;
	}

	dbg("[ check ] class : 0x%x", info->class );
	dbg("[ check ] flavor_type : 0x%x", info->flavor_type );

	dbg("on_response_ss_forwarding_set - rsp.err : %d, ur : %x", resp.err, ur);

	if ( sp_response->success > 0) {

	ReleaseResponse();

		if ( info->flavor_type == SS_CF_MODE_CF_ALL || 
			 info->flavor_type == SS_CF_MODE_CFC ) {

			if ( ur )
				tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_general), &resp);
			else 
				dbg("[ error ] ur is 0");

		} else {
			dup_ur = tcore_user_request_dup(ur);
			_ss_forwarding_get( o, dup_ur, info->class, info->flavor_type, info->resp );
		}

	} else {
		ReleaseResponse();

		if ( ur )
			tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_general), &resp);
		else 
			dbg("[ error ] ur is 0");

	}
	g_free(user_data);
}

static void on_response_ss_forwarding_get( TcorePending *p, int data_len, const void *data, void *user_data ) 
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;
    	struct ATLine *p_cur;
	int status=0, classx =0, err=0, ton =0, time=0;
	char* num, *subaddr;
		
	struct ss_confirm_info* info = 0;
	struct tresp_ss_forwarding resp;
	int countRecords=0, countValidRecords =0;

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	printResponse();	

	info = (struct ss_confirm_info*)user_data;

	/* count the calls */
	for (countRecords = 0, p_cur = sp_response->p_intermediates
	        ; p_cur != NULL
	        ; p_cur = p_cur->p_next
	) {
	    countRecords++;
	}
	dbg("total records : %d",countRecords);	


	resp.record_num = countRecords;

	if ( resp.record_num > 0 ) {
//		int i = 0;

		resp.record = g_new0( struct forwarding_info, resp.record_num );

		for (countValidRecords = 0, p_cur = sp_response->p_intermediates
            		; p_cur != NULL
            		; p_cur = p_cur->p_next)
		{
			err = at_tok_start(&(p_cur->line));
			if (err < 0){
				dbg("start line error. skip this line");				
				goto error;		
			}
			err = at_tok_nextint(&(p_cur->line), &status);// status
			if (err < 0) {
				dbg("status error. skip this line");				
				goto error;		
			}			
	
			if(status == 1){
				resp.record[countValidRecords].status = SS_STATUS_ACTIVATE;
			}
			else	{
				resp.record[countValidRecords].status = SS_STATUS_DEACTIVATE;
			}

			err = at_tok_nextint(&(p_cur->line), &classx); //class
			if (err < 0) {
				dbg("class error. skip this line");				
				goto error;		
			}	

			switch(classx){
				case 1:
					resp.record[countValidRecords].class = SS_CLASS_VOICE;
				break;
				case 2:
					resp.record[countValidRecords].class = SS_CLASS_ALL_DATA_TELE;
				break;		
				case 4:
					resp.record[countValidRecords].class = SS_CLASS_FAX;
				break;					
				case 7:
					resp.record[countValidRecords].class = SS_CLASS_ALL_TELE;
				break;
				case 8:
					resp.record[countValidRecords].class = SS_CLASS_SMS;
				break;					
				case 16:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_SYNC;
				break;					
				case 32:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_ASYNC;
				break;	
				default:
					dbg("unspoorted class : [%d]\n", classx );	
					goto error;
				break;
			}

			if(at_tok_hasmore(&(p_cur->line)) ==1){ 	//more data present
				err = at_tok_nextstr(&(p_cur->line), &num); //number
				memcpy((resp.record[countValidRecords].number), num, strlen(num));
				resp.record[countValidRecords].number_present = TRUE;
				
				err = at_tok_nextint(&(p_cur->line), &ton); // type of  number - skip
				resp.record[countValidRecords].number_type = ton;

				if(at_tok_hasmore(&(p_cur->line)) ==1){
					err = at_tok_nextstr(&(p_cur->line), &subaddr); //subaddr - skip
					err  =at_tok_nextint(&(p_cur->line), &ton); //ton of subaddr - skip

					if(at_tok_hasmore(&(p_cur->line)) ==1){
						err = at_tok_nextint(&(p_cur->line), &time); //time
						resp.record[countValidRecords].time = (enum telephony_ss_forwarding_no_reply_time)time;
					}

				}
			
			}

			resp.record[countValidRecords].mode = (enum telephony_ss_barring_mode)(info->flavor_type);

			countValidRecords++;
			continue;
error:
			dbg("invalid field found. coutinue");
			continue;
		}

		dbg("valid count :%d",countValidRecords);
		resp.record_num = countValidRecords;
		resp.err = TCORE_RETURN_SUCCESS;

	}
	else
	{
		dbg("no active status - return to user")
		resp.err = TCORE_RETURN_FAILURE;
	}

	ReleaseResponse();
	dbg("on_response_ss_forwarding_get - rsp.err : %d, ur : %x", resp.err, ur);

	if ( ur )
		tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_forwarding), &resp);
	else 
		dbg("[ error ] ur is 0");

	g_free( user_data );
	
}

static void on_response_ss_waiting_set( TcorePending *p, int data_len, const void *data, void *user_data ) 
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;
	struct ss_confirm_info *info = 0;
	struct tresp_ss_general resp;

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	info = (struct ss_confirm_info*)user_data;

	if(sp_response->success > 0){
		resp.err = TCORE_RETURN_SUCCESS;
	}else{
		resp.err = TCORE_RETURN_FAILURE;
	}

	ReleaseResponse();

	dbg("on_response_ss_waiting_set - rsp.err : %d, ur : %x, class : %d", resp.err, ur, info->class );

	if ( resp.err == TCORE_RETURN_SUCCESS ) {

		_ss_waiting_get( o, ur, info->class, info->resp );

	} else {

		if ( ur )
			tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_general), &resp);
		else 
			dbg("[ error ] ur is 0");

	}
	g_free( user_data );
}

static void on_response_ss_waiting_get( TcorePending *p, int data_len, const void *data, void *user_data ) 
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;
    	struct ATLine *p_cur;
	int status=0, classx =0, err=0;
		
	struct ss_confirm_info* info = 0;
	struct tresp_ss_waiting resp;
	int countRecords=0, countValidRecords =0;

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	printResponse();	

	info = (struct ss_confirm_info*)user_data;

	/* count the calls */
	for (countRecords = 0, p_cur = sp_response->p_intermediates
	        ; p_cur != NULL
	        ; p_cur = p_cur->p_next
	) {
	    countRecords++;
	}
	dbg("total records : %d",countRecords);	


	resp.record_num = countRecords;

	if ( resp.record_num > 0 ) {
//		int i = 0;

		resp.record = g_new0( struct waiting_info, resp.record_num );

		for (countValidRecords = 0, p_cur = sp_response->p_intermediates
            		; p_cur != NULL
            		; p_cur = p_cur->p_next)
		{
			err = at_tok_start(&(p_cur->line));
			if (err < 0){
				dbg("start line error. skip this line");				
				goto error;		
			}
			
			err = at_tok_nextint(&(p_cur->line), &status);// status
			if (err < 0) {
				dbg("status error. skip this line");				
				goto error;		
			}			
	
			if(status == 1){
				resp.record[countValidRecords].status = SS_STATUS_ACTIVATE;
			}
			else	{
				resp.record[countValidRecords].status = SS_STATUS_DEACTIVATE;
			}

			err = at_tok_nextint(&(p_cur->line), &classx); //class
			if (err < 0) {
				dbg("class error. skip this line");				
				goto error;		
			}	

			switch(classx){
				case 1:
					resp.record[countValidRecords].class = SS_CLASS_VOICE;
				break;
				case 2:
					resp.record[countValidRecords].class = SS_CLASS_ALL_DATA_TELE;
				break;		
				case 4:
					resp.record[countValidRecords].class = SS_CLASS_FAX;
				break;					
				case 7:
					resp.record[countValidRecords].class = SS_CLASS_ALL_TELE;
				break;
				case 8:
					resp.record[countValidRecords].class = SS_CLASS_SMS;
				break;					
				case 16:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_SYNC;
				break;					
				case 32:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_ASYNC;
				break;	
				default:
					dbg("unspoorted class : [%d]\n", classx );	
					goto error;
				break;
			}

			countValidRecords++;
			continue;
error:
			dbg("invalid field found. coutinue");
			continue;
		}

		dbg("valid count :%d",countValidRecords);
		resp.record_num = countValidRecords;
		resp.err = TCORE_RETURN_SUCCESS;
	}
	else
	{
		dbg("no active status - return to user")
		resp.err = TCORE_RETURN_FAILURE;
	}
	dbg("on_response_ss_waiting_get - rsp.err : %d, ur : %x", resp.err, ur);

	ReleaseResponse();

	if ( ur )
		tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_waiting), &resp);
	else 
		dbg("[ error ] ur is 0");

	g_free( user_data );
	
}

static void on_confirmation_ss_ussd( TcorePending *p, int data_len, const void *data, void *user_data )
{
	struct ss_confirm_info *info = 0;

	struct tresp_ss_ussd resp;
	CoreObject*		o = 0;
	UserRequest*	ur = 0;

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);


	printResponse();	
	
	info = (struct ss_confirm_info*)user_data;
	
	if(sp_response->success > 0){
		resp.err = TCORE_RETURN_SUCCESS;
	}	
	else{
		resp.err = TCORE_RETURN_FAILURE;
	}

	dbg("on_confirmation_ss_ussd - rsp.err : %d, ur : %x", resp.err, ur);


	if ( resp.err ) {

		UssdSession *ussd_s = 0;
		enum tcore_ss_ussd_type type = 0;

		ussd_s = tcore_ss_ussd_get_session( o );

		if ( ussd_s )
			type = tcore_ss_ussd_get_session_type( ussd_s );
		else
			dbg("[ error ] ussd_s : (0)");

		resp.type = (enum telephony_ss_ussd_type)type;

		if ( type == TCORE_SS_USSD_TYPE_USER_INITIATED ) {
			UserRequest *ur2 = 0;

			tcore_ss_ussd_get_session_data( ussd_s, (void**)&ur2 );
			if ( ur2 )
				tcore_user_request_free( ur2 );

			tcore_ss_ussd_destroy_session( ussd_s );
		}

		if ( ur )
			tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_ussd), &resp);
		else
			dbg("[ error ] ur : (0)");

		ReleaseResponse();
	}
}


static struct tcore_ss_operations ss_ops = {
	.barring_activate		= s_ss_barring_activate,
	.barring_deactivate		= s_ss_barring_deactivate,
	.barring_change_password= s_ss_barring_change_password,
	.barring_get_status		= s_ss_barring_get_status,
	.forwarding_activate	= s_ss_forwarding_activate,
	.forwarding_deactivate	= s_ss_forwarding_deactivate,
	.forwarding_register	= s_ss_forwarding_register,
	.forwarding_deregister	= s_ss_forwarding_deregister,
	.forwarding_get_status	= s_ss_forwarding_get_status,
	.waiting_activate		= s_ss_waiting_activate,
	.waiting_deactivate		= s_ss_waiting_deactivate,
	.waiting_get_status		= s_ss_waiting_get_status,
	.cli_activate			= s_ss_cli_activate,
	.cli_deactivate			= s_ss_cli_deactivate,
	.cli_get_status			= s_ss_cli_get_status,
	.send_ussd				= s_ss_send_ussd,
	.set_aoc				= s_ss_set_aoc,
	.get_aoc				= s_ss_get_aoc,
};


static TReturn _ss_barring_set( CoreObject *o, UserRequest *ur, enum telephony_ss_opcode op )
{
	struct treq_ss_barring *barring = 0;
	TcorePlugin *p = 0;
	struct ss_confirm_info *user_data = 0;
	gboolean ret = FALSE;
	char passwd[MAX_SS_BARRING_PASSWORD_LEN+1];

	struct ATReqMetaInfo metainfo;
	int info_len =0;
	char* cmd_str = NULL;
	int opco;
	int classx;
	char* facility = NULL;
	

	barring = (struct treq_ss_barring*)tcore_user_request_ref_data( ur, 0 );
	p		= tcore_object_ref_plugin( o );

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);


	switch(op){
		case TIZEN_SS_OPCO_ACTIVATE:
			opco = 1;
		break;
		case TIZEN_SS_OPCO_DEACTIVATE:
			opco = 0;
		break;
		default:
			dbg("unsupported opco : %d", op);
		return TCORE_RETURN_FAILURE;
	}


	switch(barring->mode){
		case SS_BARR_MODE_BAOC:
			facility = "AO";
		break;
		case SS_BARR_MODE_BOIC:
			facility = "OI";
		break;
		case SS_BARR_MODE_BOIC_NOT_HC:
			facility = "OX";
		break;
		case SS_BARR_MODE_BAIC:
			facility = "AI";
		break;
		case SS_BARR_MODE_BIC_ROAM:
			facility = "IR";
		break;
		case SS_BARR_MODE_AB:
			facility = "AB";
		break;
		case SS_BARR_MODE_AOB:
			facility = "AG";
		break;
		case SS_BARR_MODE_AIB:
			facility = "AC";
		break;
		case SS_BARR_MODE_BIC_NOT_SIM:
			facility = "NS";
		break;
		default:
			dbg("unspported mode %d", barring->mode);
		return TCORE_RETURN_FAILURE;
	}

	switch(barring->class)
	{
		case SS_CLASS_ALL_TELE:
			classx =7;
		break;
		case SS_CLASS_VOICE:
			classx =1;
		break;
		case SS_CLASS_ALL_DATA_TELE:
			classx =2;
		break;
		case SS_CLASS_FAX:
			classx =4;
		break;
		case SS_CLASS_SMS:
			classx = 8;
		break;
		case SS_CLASS_ALL_CS_SYNC:
			classx = 16;
		break;
	
		default:
			classx =7;
			dbg("unsupported class %d. set to default : 7", barring->class);
		break;
	}

	// null-ended pwd handling added - unexpected  0x11 value observed in req string
	memcpy(passwd, barring->password, MAX_SS_BARRING_PASSWORD_LEN);
	passwd[MAX_SS_BARRING_PASSWORD_LEN]='\0';


 	cmd_str = g_strdup_printf("AT+CLCK=\"%s\",%d,\"%s\",%d%s", facility, opco, passwd, classx,"\r");
	dbg("request command : %s", cmd_str);
	


	user_data = g_new0( struct ss_confirm_info, 1 );

	if ( op == TIZEN_SS_OPCO_ACTIVATE) {
		user_data->resp = TRESP_SS_BARRING_ACTIVATE;

	} else if ( op == TIZEN_SS_OPCO_DEACTIVATE) {
		user_data->resp = TRESP_SS_BARRING_DEACTIVATE;

	} else {
		dbg("[ error ] wrong ss opco ( 0x%x )", op );
		return TCORE_RETURN_FAILURE;
	}

	user_data->flavor_type = (int)(barring->mode);
	user_data->class = barring->class;

	ret = _ss_request_message( o, ur, cmd_str, strlen(cmd_str), on_response_ss_barring_set, user_data );

	g_free(cmd_str);

	if ( !ret )
		return TCORE_RETURN_FAILURE;

	return TCORE_RETURN_SUCCESS;
}

static TReturn _ss_barring_get( CoreObject *o, 
								UserRequest *ur, 
								enum telephony_ss_class class, 
								enum telephony_ss_barring_mode mode, 
								enum tcore_response_command resp )
{
	TcorePlugin *p = 0;
	struct ss_confirm_info *user_data = 0;
	gboolean ret = FALSE;

	struct ATReqMetaInfo metainfo;
	int info_len =0;
	char* cmd_str = NULL;
	int opco, classx;
	char* facility = NULL;
	
	p	= tcore_object_ref_plugin( o );

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = MULTILINE;
	memcpy(metainfo.responsePrefix,"+CLCK:",strlen("+CLCK:"));
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	//query status - opco is fixed to 2 
	opco = 2;

	//barring mode
	switch(mode){
		case SS_BARR_MODE_BAOC:
			facility = "AO";
		break;
		case SS_BARR_MODE_BOIC:
			facility = "OI";
		break;
		case SS_BARR_MODE_BOIC_NOT_HC:
			facility = "OX";
		break;
		case SS_BARR_MODE_BAIC:
			facility = "AI";
		break;
		case SS_BARR_MODE_BIC_ROAM:
			facility = "IR";
		break;
		case SS_BARR_MODE_AB:
			facility = "AB";
		break;
		case SS_BARR_MODE_AOB:
			facility = "AG";
		break;
		case SS_BARR_MODE_AIB:
			facility = "AC";
		break;
		case SS_BARR_MODE_BIC_NOT_SIM:
			facility = "NS";
		break;
		default:
			dbg("unspported mode %d", mode);
		return TCORE_RETURN_FAILURE;
	}

	switch(class)
	{
		case SS_CLASS_ALL_TELE:
			classx =7;
		break;
		case SS_CLASS_VOICE:
			classx =1;
		break;
		case SS_CLASS_ALL_DATA_TELE:
			classx =2;
		break;
		case SS_CLASS_FAX:
			classx =4;
		break;
		case SS_CLASS_SMS:
			classx = 8;
		break;
		case SS_CLASS_ALL_CS_SYNC:
			classx = 16;
		break;
	
		default:
			classx =7;
			dbg("unsupported class %d. set to default : 7", class);
		break;
	}


	if(classx ==7)
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\",%d%s", facility, opco,"\r");
	else
		cmd_str = g_strdup_printf("AT+CLCK=\"%s\",%d,,%d%s", facility, opco,classx,"\r");

	dbg("request command : %s", cmd_str);

	user_data = g_new0( struct ss_confirm_info, 1 );
	user_data->resp = resp;

	user_data->flavor_type = (int)(mode);
	user_data->class = class;

	ret = _ss_request_message( o, ur, cmd_str, strlen(cmd_str), on_response_ss_barring_get, user_data );

	g_free(cmd_str);

	if ( !ret )
		return TCORE_RETURN_FAILURE;

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_barring_activate( CoreObject *o, UserRequest *ur )
{
	return _ss_barring_set( o, ur, TIZEN_SS_OPCO_ACTIVATE );
}

static TReturn s_ss_barring_deactivate( CoreObject *o, UserRequest *ur )
{
	return _ss_barring_set( o, ur, TIZEN_SS_OPCO_DEACTIVATE );
}

static TReturn s_ss_barring_change_password( CoreObject *o, UserRequest *ur )
{
	TcorePlugin *p = 0;
	struct treq_ss_barring_change_password *barring = 0;

	struct ss_confirm_info *user_data = 0;

	gboolean ret = FALSE;

//	struct ATReqMetaInfo metainfo;
//	int info_len =0;
	char* cmd_str = NULL;

	p		= tcore_object_ref_plugin( o );
	barring = (struct treq_ss_barring_change_password*)tcore_user_request_ref_data( ur, 0 );


	cmd_str = g_strdup_printf("AT+CPWD=\"%s\",\"%s\",\"%s\"%s", "AB", barring->password_old, barring->password_new,"\r");
	dbg("request command : %s", cmd_str);


	user_data = g_new0( struct ss_confirm_info, 1 );
	user_data->resp = TRESP_SS_BARRING_CHANGE_PASSWORD;

	ret = _ss_request_message( o, ur, cmd_str, strlen(cmd_str), on_response_ss_barring_change_pwd, user_data );

	g_free(cmd_str);
	if ( !ret )
		return TCORE_RETURN_FAILURE;

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_barring_get_status( CoreObject *o, UserRequest *ur )
{
	struct treq_ss_barring *barring = 0;
	barring = (struct treq_ss_barring*)tcore_user_request_ref_data( ur, 0 );

	return _ss_barring_get( o, ur, barring->class, barring->mode, TRESP_SS_BARRING_GET_STATUS );
}

static TReturn _ss_forwarding_set( CoreObject *o, UserRequest *ur, enum telephony_ss_opcode op )
{
	TcorePlugin *p = 0;
	struct treq_ss_forwarding *forwarding = 0;

	struct ss_confirm_info *user_data = 0;

	gboolean ret = FALSE;
	int len = 0;

	struct ATReqMetaInfo metainfo;
	int info_len =0;
	char* cmd_str = NULL;
	char* tmp_str = NULL;
	int reason=0,mode=0,num_type=0, classx=0,time=0;
	gboolean valid_num = FALSE;

	dbg("_ss_forwarding_set with opco %d ", op);


	forwarding = (struct treq_ss_forwarding*) tcore_user_request_ref_data( ur, 0 );
	p		= tcore_object_ref_plugin( o );

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	switch(forwarding->mode)
	{
		case SS_CF_MODE_CFU:
			reason =0;
			break;
		case SS_CF_MODE_CFB:
			reason =1;
			break;
		case SS_CF_MODE_CFNRy:
			reason =2;
			break;
		case SS_CF_MODE_CFNRc:
			reason =3;
			break;
		case SS_CF_MODE_CF_ALL:
			reason = 4;
		break;
		case SS_CF_MODE_CFC:
			reason = 5;
		break;		
		
		default:
			dbg("unsupported reason : %d");
			break;
	}
	
	switch(op){
		case TIZEN_SS_OPCO_DEACTIVATE:
			mode = 0;
		break;
		case TIZEN_SS_OPCO_ACTIVATE:
			mode = 1;
		break;
		case TIZEN_SS_OPCO_REG:
			mode = 3;
		break;
		case TIZEN_SS_OPCO_DEREG:
			mode = 4;
		break;

		default:
			dbg("unsupported opco : %d", op);
			return TCORE_RETURN_FAILURE;
	}


// class
	switch(forwarding->class)
	{
		case SS_CLASS_ALL_TELE:
			classx =7;
		break;
		case SS_CLASS_VOICE:
			classx =1;
		break;
		case SS_CLASS_ALL_DATA_TELE:
			classx =2;
		break;
		case SS_CLASS_FAX:
			classx =4;
		break;
		case SS_CLASS_SMS:
			classx = 8;
		break;
		case SS_CLASS_ALL_CS_SYNC:
			classx = 16;
		break;
	
		default:
			classx =7;
			dbg("unsupported class %d. set to default : 7", forwarding->class);
		break;
	}

//number	
	len = strlen(forwarding->number);
	if ( len > 0 ){
		valid_num = TRUE;
		if ( forwarding->number[0] == '+' )
			num_type = ((TIZEN_NUM_TYPE_INTERNATIONAL << 4)|TIZEN_NUM_PLAN_ISDN);
		else
			num_type = 0;
	}
	user_data = g_new0( struct ss_confirm_info, 1 );

	switch ( op ) {
		case TIZEN_SS_OPCO_REG:
			user_data->resp = TRESP_SS_FORWARDING_REGISTER;
			break;
		case TIZEN_SS_OPCO_DEREG:
			user_data->resp = TRESP_SS_FORWARDING_DEREGISTER;
			break;
		case TIZEN_SS_OPCO_ACTIVATE:
			user_data->resp = TRESP_SS_FORWARDING_ACTIVATE;
			break;
		case TIZEN_SS_OPCO_DEACTIVATE:
			user_data->resp = TRESP_SS_FORWARDING_DEACTIVATE;
			break;
		default:
			dbg("[ error ] unknown op ( 0x%x )", op );
			break;
	}

	if(op == TIZEN_SS_OPCO_REG)
		tmp_str = g_strdup_printf("AT+CCFC=%d,%d,\"%s\",%d,%d", reason, mode, forwarding->number, num_type, classx);
	else// other opcode does not need num field
		tmp_str = g_strdup_printf("AT+CCFC=%d,%d,,,%d", reason, mode, classx);

	
	if(forwarding->mode == SS_CF_MODE_CFNRy){
		//add time info to 'no reply' case
		time = (int)(forwarding->time);
		cmd_str = g_strdup_printf("%s,,,%d%s", tmp_str,time,"\r");	
	}
	else	{
		cmd_str = g_strdup_printf("%s%s", tmp_str,"\r");	
	}

	dbg("request command : %s", cmd_str);
	


	user_data->flavor_type = forwarding->mode;
	user_data->class = forwarding->class;

	ret = _ss_request_message( o, ur, cmd_str, strlen(cmd_str), on_response_ss_forwarding_set, user_data );
	g_free(tmp_str);
	g_free(cmd_str);

	if ( !ret )
		return TCORE_RETURN_FAILURE;

	return TCORE_RETURN_SUCCESS;
}

static TReturn _ss_forwarding_get(	CoreObject *o, 
									UserRequest *ur, 
									enum telephony_ss_class class, 
									enum telephony_ss_forwarding_mode type, 
									enum tcore_response_command resp )
{
	TcorePlugin *p = 0;
	struct ss_confirm_info *user_data = 0;

	gboolean ret = FALSE;
//	int len = 0;

	struct ATReqMetaInfo metainfo;
	int info_len=0, reason=0, mode=0, classx =0;
	char* cmd_str = NULL;

	p	= tcore_object_ref_plugin( o );

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = MULTILINE;
	memcpy(metainfo.responsePrefix,"+CCFC:",strlen("+CCFC:"));
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	switch(type)
	{
		case SS_CF_MODE_CFU:
			reason =0;
		break;
		case SS_CF_MODE_CFB:
			reason =1;
		break;
		case SS_CF_MODE_CFNRy:
			reason =2;
		break;
		case SS_CF_MODE_CFNRc:
			reason =3;
		break;
		case SS_CF_MODE_CF_ALL:
			reason = 4;
		break;
		case SS_CF_MODE_CFC:
			reason = 5;
		break;		
		
		default:
			dbg("unsupported reason : %d");
		break;
	}

	switch(class)
	{
		case SS_CLASS_ALL_TELE:
			classx =7;
		break;
		case SS_CLASS_VOICE:
			classx =1;
		break;
		case SS_CLASS_ALL_DATA_TELE:
			classx =2;
		break;
		case SS_CLASS_FAX:
			classx =4;
		break;
		case SS_CLASS_SMS:
			classx = 8;
		break;
		case SS_CLASS_ALL_CS_SYNC:
			classx = 16;
		break;
		default:
			classx =7;
			dbg("unsupported class %d. set to default : 7", class);
		break;
	}	

	//query status - mode set to 2
	mode =2;

	user_data = g_new0( struct ss_confirm_info, 1 );
	user_data->resp = resp;

	user_data->class = class;
	user_data->flavor_type = type;

	if(classx ==7)
		cmd_str = g_strdup_printf("AT+CCFC=%d,%d%s", reason, mode,"\r");
	else
		cmd_str = g_strdup_printf("AT+CCFC=%d,%d,,,%d%s", reason, mode,classx,"\r");

	dbg("request command : %s", cmd_str);
	ret = _ss_request_message( o, ur, cmd_str, strlen(cmd_str), on_response_ss_forwarding_get, user_data );
	g_free(cmd_str);

	if ( !ret )
		return TCORE_RETURN_FAILURE;

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_forwarding_activate( CoreObject *o, UserRequest *ur )
{
	return _ss_forwarding_set( o, ur, TIZEN_SS_OPCO_ACTIVATE );
}

static TReturn s_ss_forwarding_deactivate( CoreObject *o, UserRequest *ur )
{
	return _ss_forwarding_set( o, ur, TIZEN_SS_OPCO_DEACTIVATE );
}

static TReturn s_ss_forwarding_register( CoreObject *o, UserRequest *ur )
{
	return _ss_forwarding_set( o, ur, TIZEN_SS_OPCO_REG );
}

static TReturn s_ss_forwarding_deregister( CoreObject *o, UserRequest *ur )
{
	return _ss_forwarding_set( o, ur, TIZEN_SS_OPCO_DEREG );
}

static TReturn s_ss_forwarding_get_status( CoreObject *o, UserRequest *ur )
{
	struct treq_ss_forwarding *forwarding = 0;
	forwarding = (struct treq_ss_forwarding*)tcore_user_request_ref_data( ur, 0 );

	return _ss_forwarding_get( o, ur, forwarding->class, forwarding->mode, TRESP_SS_FORWARDING_GET_STATUS );
}

static TReturn _ss_waiting_set( CoreObject *o, UserRequest *ur, enum telephony_ss_opcode opco )
{
	TcorePlugin *p = 0;
	struct treq_ss_waiting *waiting = 0;

	struct ss_confirm_info *user_data = 0;

	gboolean ret = FALSE;
	int mode=0, classx=0;
	char* cmd_str;
	struct ATReqMetaInfo metainfo;
	
//set metainfo
	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';

	tcore_user_request_set_metainfo(ur, sizeof(struct ATReqMetaInfo), &metainfo);
	
	p	= tcore_object_ref_plugin( o );

	waiting = (struct treq_ss_waiting*) tcore_user_request_ref_data( ur, 0 );

	user_data = g_new0( struct ss_confirm_info, 1 );

	if ( opco == TIZEN_SS_OPCO_ACTIVATE ){
		user_data->resp = TRESP_SS_WAITING_ACTIVATE;
		mode = 1;//enable
	}	
	else if ( opco == TIZEN_SS_OPCO_DEACTIVATE ){
		user_data->resp = TRESP_SS_WAITING_DEACTIVATE;
		mode =0; //diable
	}
	else
		dbg("[ error ] unknown ss mode (0x%x)", opco);

switch(waiting->class)
	{
		case SS_CLASS_ALL_TELE:
			classx =7;
		break;
		case SS_CLASS_VOICE:
			classx =1;
		break;
		case SS_CLASS_ALL_DATA_TELE:
			classx =2;
		break;
		case SS_CLASS_FAX:
			classx =4;
		break;
		case SS_CLASS_SMS:
			classx = 8;
		break;
	
		default:
			classx =7;
			dbg("unsupported class %d. set to default : 7", waiting->class);
		break;
	}	
	

	user_data->class = waiting->class;
	user_data->flavor_type = (int)opco;

	cmd_str = g_strdup_printf("AT+CCWA=1,%d,%d%s", mode, classx,"\r"); //always enable +CCWA: unsolicited cmd
	dbg("request command : %s",cmd_str);

	ret = _ss_request_message( o, ur, cmd_str, strlen(cmd_str), on_response_ss_waiting_set, user_data );

	g_free(cmd_str);
	if ( !ret )
		return TCORE_RETURN_FAILURE;

	return TCORE_RETURN_SUCCESS;
}

static TReturn _ss_waiting_get( CoreObject *o, 
								UserRequest *ur, 
								enum telephony_ss_class class, 
								enum tcore_response_command resp )
{
	TcorePlugin *p = 0;

	struct ss_confirm_info *user_data = 0;

	gboolean ret = FALSE;
	int classx, info_len=0;//mode,
	char* cmd_str;
	struct ATReqMetaInfo metainfo;

//set metainfo
	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = MULTILINE;
	memcpy(metainfo.responsePrefix,"+CCWA:",strlen("+CCWA:"));
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, sizeof(struct ATReqMetaInfo), &metainfo);
	
	p	= tcore_object_ref_plugin( o );

	switch(class)
	{
		case SS_CLASS_ALL_TELE:
			classx =7;
		break;
		case SS_CLASS_VOICE:
			classx =1;
		break;
		case SS_CLASS_ALL_DATA_TELE:
			classx =2;
		break;
		case SS_CLASS_FAX:
			classx =4;
		break;
		case SS_CLASS_SMS:
			classx = 8;
		break;

		default:
			classx =7;
			dbg("unsupported class %d. set to default : 7", class);
		break;
	}	

	dbg("allocating user data");
	user_data = g_new0( struct ss_confirm_info, 1 );
	user_data->resp = resp;
	user_data->class = class;

	cmd_str = g_strdup_printf("AT+CCWA=1,2,%d%s", classx,"\r"); //always enable +CCWA: unsolicited cmd , mode is fixed to 2(query status)
	dbg("request cmd : %s", cmd_str);

	ret = _ss_request_message( o, ur, cmd_str, strlen(cmd_str), on_response_ss_waiting_get, user_data );

	g_free(cmd_str);

	if ( !ret )
		return TCORE_RETURN_FAILURE;

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_waiting_activate( CoreObject *o, UserRequest *ur )
{
	return _ss_waiting_set( o, ur, TIZEN_SS_OPCO_ACTIVATE );
}

static TReturn s_ss_waiting_deactivate( CoreObject *o, UserRequest *ur )
{
	return _ss_waiting_set( o, ur, TIZEN_SS_OPCO_DEACTIVATE );
}

static TReturn s_ss_waiting_get_status( CoreObject *o, UserRequest *ur )
{
	struct treq_ss_waiting *waiting = 0;
	waiting = (struct treq_ss_waiting*)tcore_user_request_ref_data( ur, 0 );

	return _ss_waiting_get( o, ur, waiting->class, TRESP_SS_WAITING_GET_STATUS );
}

static TReturn s_ss_cli_activate( CoreObject *o, UserRequest *ur )
{
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_cli_deactivate( CoreObject *o, UserRequest *ur )
{
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_cli_get_status( CoreObject *o, UserRequest *ur )
{
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_send_ussd( CoreObject *o, UserRequest *ur )
{
	TcorePlugin *p = 0;
	UssdSession *ussd_s = 0;

	struct treq_ss_ussd *ussd = 0;
	struct ss_confirm_info *user_data = 0;
		
	gboolean ret = FALSE;
	char* cmd_str;
	struct ATReqMetaInfo metainfo;
	
//set metainfo
	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	tcore_user_request_set_metainfo(ur, sizeof(struct ATReqMetaInfo), &metainfo);
	
	p = tcore_object_ref_plugin(o);
	ussd = (struct treq_ss_ussd*)tcore_user_request_ref_data( ur, 0 );

	cmd_str = g_strdup_printf("AT+CUSD=1,\"%s\",%d%s", ussd->str, 0x0f,"\r"); //always enable +CUSD: unsolicited cmd. set to dcs to 0x0f. only supports HEX type
	dbg("request command : %s",cmd_str);


	user_data = g_new0( struct ss_confirm_info, 1 );
	user_data->resp = TRESP_SS_SEND_USSD;

	ussd_s = tcore_ss_ussd_get_session( o );
	if ( !ussd_s ) {
		tcore_ss_ussd_create_session( o, (enum tcore_ss_ussd_type)ussd->type, (void*)tcore_user_request_dup(ur), 0 );
	} else {

		if ( ussd->type == SS_USSD_TYPE_USER_INITIATED ) {
			dbg("[ error ] ussd session is already exist");

			g_free( user_data );
			return TCORE_RETURN_FAILURE;
		}

		tcore_ss_ussd_set_session_type( ussd_s, (enum tcore_ss_ussd_type)ussd->type);
	}

	ret = _ss_request_message( o, ur, cmd_str, strlen(cmd_str), on_confirmation_ss_ussd, user_data );

	if ( !ret )
		return TCORE_RETURN_FAILURE;


	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_set_aoc( CoreObject *o, UserRequest *ur )
{
	dbg("[ error ] unsupported function");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_get_aoc( CoreObject *o, UserRequest *ur )
{
	dbg("[ error ] unsupported function");
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_call_control_operations call_ops = {
	.answer_hold_and_accept = s_ss_manage_call_2_send,
	.answer_replace			= s_ss_manage_call_1_send,
	.answer_reject			= s_ss_manage_call_0_send,
	.end_specific			= s_ss_manage_call_1x_send,
	.end_all_active			= s_ss_manage_call_1_send,
	.end_all_held			= s_ss_manage_call_0_send,
	.active					= s_ss_manage_call_2_send,
	.hold					= s_ss_manage_call_2_send,
	.swap					= s_ss_manage_call_2_send,
	.join					= s_ss_manage_call_3_send,
	.split					= s_ss_manage_call_2x_send,
	.transfer				= s_ss_manage_call_4_send,
	.deflect				= s_ss_manage_call_4dn_send,
};

static TReturn s_ss_manage_call_0_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup_printf("%s%s", "AT+CHLD=0", "\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_manage_call_1_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup_printf("%s%s", "AT+CHLD=1", "\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_manage_call_1x_send( CoreObject* o, UserRequest* ur, const int id, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup_printf("%s%d%s", "AT+CHLD=1", id,"\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_manage_call_2_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup_printf("%s%s", "AT+CHLD=2", "\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_manage_call_2x_send( CoreObject* o, UserRequest* ur, const int id, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup_printf("%s%d%s", "AT+CHLD=2", id,"\r");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_manage_call_3_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data )
{
//	gboolean ret = FALSE;
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;	

	GSList *l = 0;
	CallObject *co = 0;
	int id = 0;

	l = tcore_call_object_find_by_status( o, CALL_STATUS_ACTIVE );
	if ( !l || !l->data ) {
		dbg("[ error ] there is no call status [ call_active ]");
		return TCORE_RETURN_FAILURE;
	}

	co = l->data;
	id = tcore_call_object_get_id( co );
	dbg("active call id : [ %d ]");

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup_printf("%s%s", "AT+CHLD=3","\r");

	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_manage_call_4_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);


	cmd_str = g_strdup_printf("%s%s", "AT+CHLD=4", "\r");
 
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_manage_call_4dn_send( CoreObject* o, UserRequest* ur, const char* number, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);


	cmd_str = g_strdup_printf("%s%s%s", "AT+CHLD=4", number,"\r");
 
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

#if 0
static TReturn s_ss_manage_call_5_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);


 	cmd_str = g_strdup_printf("%s%s", "AT+CHLD=5", "\r");

	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_ss_manage_call_6_send( CoreObject* o, UserRequest* ur, ConfirmCallback cb, void* user_data )
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);


 	cmd_str= g_strdup_printf("%s%s", "AT+CHLD=6", "\r");

	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d",cmd_str, "N/A", strlen(cmd_str));

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	g_free(cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, (TcorePendingResponseCallback)cb, user_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	tcore_pending_set_send_callback(pending, on_confirmation_call_control_ss_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}
#endif


gboolean s_ss_init( TcorePlugin *p )
{
	CoreObject *so = 0, *co = 0;
	struct property_call_info *data = 0;

	dbg("s_ss_init()");

	so = tcore_ss_new( p, "ss", &ss_ops );
	if (!so) {
		dbg("[ error ] ss_new()");
		return FALSE;
	}

	co = tcore_plugin_ref_core_object(p, "call");
	if (!co) {
		dbg("[ error ] plugin_ref_core_object");
		return FALSE;
	}

	tcore_call_control_set_operations( co, &call_ops );

	tcore_object_add_callback( so, EVENT_SS_INFO, on_notification_ss_info, 0 );
	tcore_object_add_callback( so, EVENT_SS_USSD, on_notification_ss_ussd, 0 );

	data = calloc( sizeof(struct property_call_info *), 1);
	tcore_plugin_link_property(p, "SS", data);

	return TRUE;
}

void s_ss_exit( TcorePlugin *p )
{
	CoreObject *o;
//	TcoreHal *h;
	struct property_network_info *data;

	o = tcore_plugin_ref_core_object(p, "ss");

	data = tcore_plugin_ref_property(p, "SS");
	if (data)
		free(data);

	tcore_ss_free(o);
}
