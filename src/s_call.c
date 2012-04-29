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
#include <server.h>
#include <co_call.h>
#include <user_request.h>

#include "s_common.h"
#include "s_call.h"

#include "atchannel.h"
#include "at_tok.h"


extern struct ATResponse *sp_response;
extern char *s_responsePrefix;
extern enum ATCommandType s_type;

struct call_confirm_info_t {
	CallObject *co;
	enum tcore_response_command resp;
};

struct CLCC_call_t {
	struct CLCC_call_info_t {
		int				id;
		enum tcore_call_direction 	direction;
		enum tcore_call_status		status;
		enum tcore_call_type 		type;
		int	mpty;
		int	num_len;
		int	num_type;
	} info;
	char number[90];
};


static gboolean	_call_request_message( CoreObject *o, UserRequest* ur, char* cmd_string, 
												unsigned int cmd_length, void* on_resp, void* user_data);

static void		_call_status_idle( TcorePlugin *p, CallObject *co );
static void		_call_status_active( TcorePlugin *p, CallObject *co );
static void		_call_status_dialing( TcorePlugin *p, CallObject *co );
static void		_call_status_alert( TcorePlugin *p, CallObject *co );
static void		_call_status_incoming( TcorePlugin *p, CallObject *co );
static void		_call_status_waiting( TcorePlugin *p, CallObject *co );

static void		_call_branch_by_status( TcorePlugin *p, CallObject *co, unsigned int status );
static enum tcore_call_type _call_type( int type );
static enum tcore_call_status _call_status(unsigned int status);
static gboolean _call_is_in_mpty(int mpty);

static TReturn	_call_list_get( CoreObject *o, CallObject *co );

static void		on_confirmation_call_message_send( TcorePending *p, gboolean result, void *user_data ); // from Kernel
static void		on_confirmation_call_request( TcorePending *p, int data_len, const void *data, void *user_data ); // from Modem
static void		on_confirmation_call_hold( TcorePending *p, int data_len, const void *data, void *user_data );
static void		on_confirmation_call_swap( TcorePending *p, int data_len, const void *data, void *user_data );
static void		on_confirmation_call_split( TcorePending *p, int data_len, const void *data, void *user_data );
static void		on_confirmation_call_hold_and_accept( TcorePending *p, int data_len, const void *data, void *user_data );
static void		on_confirmation_call_endall( TcorePending *p, int data_len, const void *data, void *user_data ); // from Modem


static void		on_response_call_list_get(TcorePending *p, int data_len, const void *data, void *user_data);
static void		on_notification_call_waiting( CoreObject *o, const void *data, void *user_data );
static void		on_notification_call_incoming( CoreObject *o, const void *data, void *user_data );
static void		on_notification_call_status( CoreObject *o, const void *data, void *user_data);


static int _callFromCLCCLine(char *line, struct CLCC_call_t *p_call);


static enum tcore_call_cli_mode _get_clir_status( char *num )
{
	enum tcore_call_cli_mode clir = CALL_CLI_MODE_DEFAULT;

	if( !strncmp( num, "*31#", 4 ) )
		return TCORE_CALL_CLI_MODE_RESTRICT;

	if( !strncmp( num, "#31#", 4 ) )
		return TCORE_CALL_CLI_MODE_PRESENT;

	return clir;
}


static enum tcore_call_status _call_status(unsigned int status)
{
	switch(status)
	{
		case 0:
			return TCORE_CALL_STATUS_ACTIVE;
	case 1:
			return TCORE_CALL_STATUS_HELD;
	case 2:
			return TCORE_CALL_STATUS_DIALING;
		case 3:
			return TCORE_CALL_STATUS_ALERT;
		case 4:
			return TCORE_CALL_STATUS_INCOMING;
		case 5:
			return TCORE_CALL_STATUS_WAITING;
		case 6:
			return TCORE_CALL_STATUS_DIALING; //connecting not exist. set to dialing 
	case 7: 
			return TCORE_CALL_STATUS_IDLE;

		default:
			return TCORE_CALL_STATUS_IDLE;
		break;
	}

	return TCORE_CALL_STATUS_IDLE;
}

static gboolean _call_is_in_mpty(int mpty)
{
	switch(mpty){
		case 0:
			return FALSE;
		break;

		case 1:
			return TRUE;

		default:
		break;
	}
	return FALSE;
}

static enum tcore_call_type _call_type(int type )
{
	switch (type) {
	case 0:
		return TCORE_CALL_TYPE_VOICE;
	case 1:
		return TCORE_CALL_TYPE_VIDEO;
	default:
		break;
	}

	return TCORE_CALL_TYPE_VOICE;
}

static gboolean _call_request_message(	CoreObject *o,
										UserRequest *ur,
										char *cmd_string,
										unsigned int cmd_len,
										void* on_resp,
										void* user_data)
{
	TcorePending *pending = NULL;
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;

	unsigned int info_len = 0;
	info_len = sizeof(struct ATReqMetaInfo);

	dbg("_call_request_message - cmd : %s, cmdlen :%d (including '\r')",cmd_string, cmd_len);
	

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, cmd_len, cmd_string);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	if ( on_resp )
		tcore_pending_set_response_callback(pending, on_resp, user_data);

	tcore_pending_set_send_callback(pending, on_confirmation_call_message_send, NULL);

	if ( !ur ) {
		dbg("[ check ] ur is NULL, is this internal request??");
	} else {
		tcore_pending_link_user_request(pending, ur);
	}

	p = tcore_object_ref_plugin(o);
	h = tcore_plugin_ref_hal(p);

	tcore_hal_send_request(h, pending);

	return TRUE;
}

static void _call_status_idle( TcorePlugin *p, CallObject *co ) 
{
	struct tnoti_call_status_idle data;

	dbg("call id [%d], call status [%d]", tcore_call_object_get_id(co), tcore_call_object_get_status(co));

	if ( tcore_call_object_get_status( co ) != TCORE_CALL_STATUS_IDLE ) {

		CoreObject *o = 0;
		//int id = 0;

		o = tcore_plugin_ref_core_object(p, "call");

		data.type = tcore_call_object_get_type( co );
		dbg("data.type : [%d]", data.type );

		data.id = tcore_call_object_get_id( co );
		dbg("data.id : [%d]", data.id );

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_IDLE );

		tcore_server_send_notification(	tcore_plugin_ref_server(p), 
									o,
									TNOTI_CALL_STATUS_IDLE,
									sizeof(struct tnoti_call_status_idle),
									(void*)&data	);

		tcore_call_object_free( o, co );
	} else {

		dbg("[ error ] call object was not free");
	}
}

static void _call_status_dialing( TcorePlugin *p, CallObject *co )
{
	CoreObject* o = 0;

	struct tnoti_call_status_dialing data;

	o = tcore_plugin_ref_core_object( p, "call");

	if ( tcore_call_object_get_status( co ) != TCORE_CALL_STATUS_DIALING ) {

		data.type = tcore_call_object_get_type( co );
		dbg("data.type : [%d]", data.type );

		data.id = tcore_call_object_get_id( co );
		dbg("data.id : [%d]", data.id );

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_DIALING );

		tcore_server_send_notification(	tcore_plugin_ref_server(p), 
									tcore_plugin_ref_core_object(p, "call"),
									TNOTI_CALL_STATUS_DIALING,
									sizeof(struct tnoti_call_status_dialing),
									(void*)&data );

	}

#if 0
	_call_list_get( o, co );
#endif
}

static void _call_status_alert( TcorePlugin *p, CallObject *co )
{
	CoreObject* o = 0;
	struct tnoti_call_status_alert data;

	o = tcore_plugin_ref_core_object( p, "call");

	if ( tcore_call_object_get_status( co ) != TCORE_CALL_STATUS_ALERT ) {

		data.type = tcore_call_object_get_type( co );
		dbg("data.type : [%d]", data.type );

		data.id = tcore_call_object_get_id( co );
		dbg("data.id : [%d]", data.id );

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_ALERT );

		tcore_server_send_notification(	tcore_plugin_ref_server(p), 
									tcore_plugin_ref_core_object(p, "call"),
									TNOTI_CALL_STATUS_ALERT,
									sizeof(struct tnoti_call_status_alert),
									(void*)&data );

	}

#if 0
	_call_list_get( o, co );
#endif
}

static void _call_status_active( TcorePlugin *p, CallObject *co )
{
	struct tnoti_call_status_active data;

	if ( tcore_call_object_get_status( co ) != TCORE_CALL_STATUS_ACTIVE ) {

		data.type = tcore_call_object_get_type( co );
		dbg("data.type : [%d]", data.type );

		data.id = tcore_call_object_get_id( co );
		dbg("data.id : [%d]", data.id );

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_ACTIVE );

		tcore_server_send_notification(	tcore_plugin_ref_server(p), 
									tcore_plugin_ref_core_object(p, "call"),
									TNOTI_CALL_STATUS_ACTIVE,
									sizeof(struct tnoti_call_status_active),
									(void*)&data );

	}
}

static void _call_status_held( TcorePlugin *p, CallObject *co )
{
	struct tnoti_call_status_held data;

	if ( tcore_call_object_get_status( co ) != TCORE_CALL_STATUS_HELD ) {

		data.type = tcore_call_object_get_type( co );
		dbg("data.type : [%d]", data.type );

		data.id = tcore_call_object_get_id( co );
		dbg("data.id : [%d]", data.id );

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_HELD );

		tcore_server_send_notification(	tcore_plugin_ref_server(p), 
									tcore_plugin_ref_core_object(p, "call"),
									TNOTI_CALL_STATUS_HELD,
									sizeof(struct tnoti_call_status_held),
									(void*)&data );

	}
}

static void _call_status_incoming( TcorePlugin *p, CallObject *co )
{
	struct tnoti_call_status_incoming data;
	CoreObject* o = 0;
	o = tcore_plugin_ref_core_object( p, "call");

	if ( tcore_call_object_get_status( co ) != TCORE_CALL_STATUS_INCOMING ) {

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_INCOMING );

		data.type = tcore_call_object_get_type( co );
		dbg("data.type : [%d]", data.type );

		data.id = tcore_call_object_get_id( co );
		dbg("data.id : [%d]", data.id );

		data.cli.mode = tcore_call_object_get_cli_mode( co );
		dbg("data.cli.mode : [%d]", data.cli.mode );

		tcore_call_object_get_number( co, data.cli.number );
		dbg("data.cli.number : [%s]", data.cli.number );

		data.cna.mode = tcore_call_object_get_cna_mode( co );
		dbg("data.cna.mode : [%d]", data.cna.mode );

		tcore_call_object_get_name( co, data.cna.name );
		dbg("data.cna.name : [%s]", data.cna.name );

		data.forward = FALSE; // this is tmp code
		data.active_line = tcore_call_object_get_active_line( co );
		dbg("data.active_line : [%d]", data.active_line );

		tcore_server_send_notification(	tcore_plugin_ref_server(p), 
				tcore_plugin_ref_core_object(p, "call"),
				TNOTI_CALL_STATUS_INCOMING,
				sizeof(struct tnoti_call_status_incoming),
				(void*)&data	);
	}

#if 0
	_call_list_get( o, co );
#endif

}

static void _call_status_waiting( TcorePlugin *p, CallObject *co )
{
	_call_status_incoming( p, co );
}

static void _call_branch_by_status( TcorePlugin *p, CallObject *co, unsigned int status )
{
	switch ( status ) {
	case TCORE_CALL_STATUS_IDLE:
		_call_status_idle( p, co );
		break;

	case TCORE_CALL_STATUS_ACTIVE:
		_call_status_active( p, co );
		break;

	case TCORE_CALL_STATUS_HELD:
		_call_status_held( p, co );
		break;

	case TCORE_CALL_STATUS_DIALING:
		_call_status_dialing( p, co );
		break;

	case TCORE_CALL_STATUS_ALERT:
		_call_status_alert( p, co );
		break;

	case TCORE_CALL_STATUS_INCOMING:
		_call_status_incoming( p, co );
		break;

	case TCORE_CALL_STATUS_WAITING:
		_call_status_waiting( p, co );
		break;
	}
}


static TReturn _call_list_get( CoreObject *o, CallObject *co )
{
	gboolean ret = FALSE;
	UserRequest* 	ur = NULL;

	char*	cmd_str = NULL;		
	struct ATReqMetaInfo metainfo;
	int info_len =0;	

	if ( !o )
		return TCORE_RETURN_FAILURE;

	ur = tcore_user_request_new(NULL, NULL);

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));

	metainfo.type = MULTILINE;
	memcpy(metainfo.responsePrefix,"+CLCC:",strlen("+CLCC:"));
	info_len = sizeof(struct ATReqMetaInfo);
	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	cmd_str = g_strdup("AT+CLCC\r");

	ret = _call_request_message ( o, ur, cmd_str, strlen(cmd_str), on_response_call_list_get, NULL); 
	
	if ( !ret )
		return TCORE_RETURN_FAILURE;

	return TCORE_RETURN_SUCCESS;
}




// CONFIRMATION

static void on_confirmation_call_message_send( TcorePending *p, gboolean result, void *user_data )
{
	UserRequest* ur = NULL;
	struct ATReqMetaInfo* metainfo = NULL;
	unsigned int info_len =0;
	dbg("on_confirmation_call_message_send - msg out from queue. alloc ATRsp buffer & write rspPrefix if needed\n");

	ReleaseResponse(); //release leftover
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

static void _confirmation_call( CoreObject *o, UserRequest *ur, TReturn err, struct call_confirm_info_t *ci )
{
	struct tresp_call_general resp;

	if ( !ci->co )
		dbg("call object is NULL, is it general requst??");

	resp.type =  (enum telephony_call_type )tcore_call_object_get_type( ci->co );
	resp.id	 =  tcore_call_object_get_id( ci->co );
	resp.err = err;

	if (ur) {
		tcore_user_request_send_response(ur, ci->resp, sizeof(struct tresp_call_general), &resp);

	} else {
		dbg("[ error ] ur is NULL");
		return ;
	}

	dbg("resp.err : [ 0x%x ]", resp.err);

#if 0
		_call_list_get( o, ci->co );
#endif

}


static void on_confirmation_call_request( TcorePending *p, int data_len, const void *data, void *user_data )
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;
	TReturn err = TCORE_RETURN_SUCCESS;

	struct call_confirm_info_t* ci = 0;

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);


	ci  = (struct call_confirm_info_t *)user_data;
	if ( !ci ) {
		dbg("[ error ] user_data is NULL");
		return ;
	}

	if(sp_response->success >0)
		err = TCORE_RETURN_SUCCESS;		
	else
		err = TCORE_RETURN_FAILURE;

	ReleaseResponse();

	_confirmation_call( o, ur, err, ci );

	g_free( ci );
}

static void on_confirmation_call_split( TcorePending *p, int data_len, const void *data, void *user_data )
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;

	struct tresp_call_general resp;
	struct call_confirm_info_t *ci = 0;

	dbg("ok, function entrance");
	printResponse();

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	ci  = (struct call_confirm_info_t *)user_data;
	if ( !ci ) {
		dbg("[ error ] user_data is NULL");
		goto out;
	}

	resp.type =  (enum telephony_call_type )tcore_call_object_get_type( ci->co );
	resp.id	  =  tcore_call_object_get_id( ci->co );
	if(sp_response->success >0){
		resp.err = FALSE;
	}else{
		resp.err = TRUE;
	}

	ReleaseResponse();

	if ( ur ) {
		tcore_user_request_send_response(ur, ci->resp, sizeof(struct tresp_call_general), &resp);

	} else {
		dbg("[ error ] ur is NULL");
		goto out;
	}

	if ( !resp.err ) {

		GSList *active = 0;
		CallObject *co = 0;

		active = tcore_call_object_find_by_status( o, TCORE_CALL_STATUS_ACTIVE );
		if ( !active ) {
			dbg("[ error ] can't find active call");
			goto out;
		}

		co = (CallObject*)active->data;
		if ( !co ) {
			dbg("[ error ] can't get active call object");
			goto out;
		}

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_HELD );
		tcore_call_object_set_status( ci->co, TCORE_CALL_STATUS_ACTIVE );
	}

out:
	g_free( ci );

}


static void on_confirmation_call_hold( TcorePending *p, int data_len, const void *data, void *user_data )
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;

	struct tresp_call_general resp;
	struct call_confirm_info_t *ci = 0;

	dbg("ok, function entrance");
	printResponse();

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	ci  = (struct call_confirm_info_t *)user_data;
	if ( !ci ) {
		dbg("[ error ] user_data is NULL");
		goto out;
	}

	resp.type =  (enum telephony_call_type )tcore_call_object_get_type( ci->co );
	resp.id	  =  tcore_call_object_get_id( ci->co );
	
	if(sp_response->success >0){
		resp.err = FALSE;
	}else{
		resp.err = TRUE;
	}

	ReleaseResponse();

	
	if ( ur ) {
		tcore_user_request_send_response(ur, ci->resp, sizeof(struct tresp_call_general), &resp);

	} else {
		dbg("[ error ] ur is NULL");
		goto out;
	}

	if ( !resp.err ) {

		GSList *active = 0;
		CallObject *co = 0;

		active = tcore_call_object_find_by_status( o, TCORE_CALL_STATUS_ACTIVE );
		if ( !active ) {
			dbg("[ error ] can't find active call");
			goto out;
		}

		co = (CallObject*)active->data;
		if ( !co ) {
			dbg("[ error ] can't get active call object");
			goto out;
		}

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_HELD );
	}

out:
	g_free( ci );

}

static void on_confirmation_call_swap( TcorePending *p, int data_len, const void *data, void *user_data )
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;

	struct tresp_call_general resp;
	struct call_confirm_info_t *ci = 0;

	dbg("ok, function entrance");
	printResponse();

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	ci  = (struct call_confirm_info_t *)user_data;
	if ( !ci ) {
		dbg("[ error ] user_data is NULL");
		goto out;
	}


	resp.type =  (enum telephony_call_type )tcore_call_object_get_type( ci->co );
	resp.id	  =  tcore_call_object_get_id( ci->co );
	if(sp_response->success >0){
		resp.err = FALSE;
	}else{
		resp.err = TRUE;
	}

	ReleaseResponse();

	if ( ur ) {
		tcore_user_request_send_response(ur, ci->resp, sizeof(struct tresp_call_general), &resp);

	} else {
		dbg("[ error ] ur is NULL");
		goto out;
	}

	if ( !resp.err ) {

		GSList *active = 0, *held = 0;
		CallObject *co = 0;

		held = tcore_call_object_find_by_status( o, TCORE_CALL_STATUS_HELD );
		if ( !held ) {
			dbg("[ error ] can't find held call");
			goto out;
		}

		active = tcore_call_object_find_by_status( o, TCORE_CALL_STATUS_ACTIVE );
		if ( !active ) {
			dbg("[ error ] can't find active call");
			goto out;
		}

		co = (CallObject*)held->data;
		if ( !co ) {
			dbg("[ error ] can't get held call object");
			goto out;
		}

		resp.id	 =  tcore_call_object_get_id( co );
		tcore_call_object_set_status( co, TCORE_CALL_STATUS_ACTIVE );

		tcore_user_request_send_response(ur, TRESP_CALL_ACTIVE, sizeof(struct tresp_call_general), &resp);

		co = (CallObject*)active->data;
		if ( !co ) {
			dbg("[ error ] can't get active call object");
			goto out;
		}

		resp.id	 =  tcore_call_object_get_id( co );
		tcore_call_object_set_status( co, TCORE_CALL_STATUS_HELD );

		tcore_user_request_send_response(ur, TRESP_CALL_HOLD, sizeof(struct tresp_call_general), &resp);
	}

out:
	g_free( ci );
}

static void on_confirmation_call_hold_and_accept( TcorePending *p, int data_len, const void *data, void *user_data )
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;

	struct tresp_call_general resp;
	struct call_confirm_info_t *ci = 0;

	dbg("ok, function entrance");
	printResponse();

	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	ci  = (struct call_confirm_info_t *)user_data;
	if ( !ci ) {
		dbg("[ error ] user_data is NULL");
		goto out;
	}


	resp.type =  (enum telephony_call_type )tcore_call_object_get_type( ci->co );
	resp.id	  =  tcore_call_object_get_id( ci->co );
	
	if(sp_response->success >0){
		resp.err = FALSE;
	}else{
		resp.err = TRUE;
	}

	ReleaseResponse();
	
	if ( ur ) {
		tcore_user_request_send_response(ur, ci->resp, sizeof(struct tresp_call_general), &resp);

	} else {
		dbg("[ error ] ur is NULL");
		goto out;
	}

	if ( !resp.err ) {

		GSList *l = 0;
		CallObject *co = 0;

		l = tcore_call_object_find_by_status( o, TCORE_CALL_STATUS_ACTIVE );
		if ( !l ) {
			dbg("[ error ] can't find active call");
			goto out;
		}

		co = (CallObject*)l->data;
		if ( !co ) {
			dbg("[ error ] can't get active call object");
			goto out;
		}

		tcore_call_object_set_status( co, TCORE_CALL_STATUS_HELD );
	}

out:
	g_free( ci );
}

// RESPONSE 
static void on_confirmation_call_endall( TcorePending *p, int data_len, const void *data, void *user_data )
{
	CoreObject*		o = 0;
	UserRequest*	ur = 0;
	//TReturn err = TCORE_RETURN_SUCCESS;
	struct call_confirm_info_t* ci = 0;
	
	dbg("on_confirmation_call_endall - 1st result. wait for final result");


	o  = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

//skip response handling - actual result will be handled in on_confirmation_call_request
	ReleaseResponse();

	ci  = (struct call_confirm_info_t *)user_data;
	if ( !ci ) {
		dbg("[ error ] user_data is NULL");
		return ;
	}
}

// RESPONSE 

static void on_response_call_list_get(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcorePlugin* plugin = 0;
	CoreObject*	o = 0;
	CallObject*	co = 0;
    	struct ATLine *p_cur;

	char* cmd= 0;
	struct CLCC_call_t*		call_list = 0;

	int i = 0, countCalls =0, countValidCalls =0, err =0;
	

	plugin	= tcore_pending_ref_plugin( p );
	o		= tcore_pending_ref_core_object( p );

	cmd		= (char*)data;


	if(sp_response->success > 0)
	{

	    /* count the calls */
	    for (countCalls = 0, p_cur = sp_response->p_intermediates
	            ; p_cur != NULL
	            ; p_cur = p_cur->p_next
	    ) {
	        countCalls++;
	    }
	   dbg("total calls : %d",countCalls);

	   if(countCalls ==0)
	   	return;

		call_list	= g_new0( struct CLCC_call_t, countCalls);
		

		for (countValidCalls = 0, p_cur = sp_response->p_intermediates
            		; p_cur != NULL
            		; p_cur = p_cur->p_next) 
        	{

			err = _callFromCLCCLine( p_cur->line, call_list + countValidCalls );

		        if (err != 0) {
		            continue;
		        }

			co = tcore_call_object_find_by_id( o, call_list[i].info.id );
			if ( !co ) {
				co = tcore_call_object_new( o, call_list[i].info.id );
				if ( !co ) {
					dbg("error : tcore_call_object_new [ id : %d ]", call_list[i].info.id);
					continue ;
				}
			}

			tcore_call_object_set_type( co, _call_type( call_list[i].info.type ) );
			tcore_call_object_set_direction( co, call_list[i].info.direction );
			tcore_call_object_set_multiparty_state( co, _call_is_in_mpty(call_list[i].info.mpty) );
			tcore_call_object_set_cli_info( co, CALL_CLI_MODE_DEFAULT, call_list[i].number );

			_call_branch_by_status( plugin, co, call_list[i].info.status );

		}
	}

	ReleaseResponse();
}

static int _callFromCLCCLine(char *line, struct CLCC_call_t*p_call)
{
        //+CLCC: 1,0,2,0,0,\"+18005551212\",145
        //     index,isMT,state,mode,isMpty(,number,TOA)?

    int err;
    int state;
    int mode;
    int isMT;
    char* num;

    err = at_tok_start(&line);
    if (err < 0) goto error;

//id
    err = at_tok_nextint(&line, &(p_call->info.id));
    if (err < 0) goto error;
    dbg("id : [%d]\n", p_call->info.id );
//MO/MTcall
    err = at_tok_nextint(&line, &isMT);
    if (err < 0) goto error;

   if(isMT ==0)
   	p_call->info.direction = TCORE_CALL_DIRECTION_OUTGOING;
   else
   	p_call->info.direction = TCORE_CALL_DIRECTION_INCOMING;
   	
	dbg("direction : [ %d ]\n", p_call->info.direction);

//state
    err = at_tok_nextint(&line, &state);
    if (err < 0) goto error;

    switch(state){
	case 0: //active
		p_call->info.status = TCORE_CALL_STATUS_ACTIVE;
	break;
	case 1:
		p_call->info.status = TCORE_CALL_STATUS_HELD;
	break;
	case 2:
		p_call->info.status = TCORE_CALL_STATUS_DIALING;
	break;
	case 3:
		p_call->info.status = TCORE_CALL_STATUS_ALERT;
	break;
	case 4:
		p_call->info.status = TCORE_CALL_STATUS_INCOMING;
	break;
	case 5:
		p_call->info.status = TCORE_CALL_STATUS_WAITING;
	break;
    }
	dbg("status	: [%d]\n", p_call->info.status );
	
//mode		
    err = at_tok_nextint(&line, &mode);
    if (err < 0) goto error;
	
   switch(mode)
  {
	case 0:
		p_call->info.type	= TCORE_CALL_TYPE_VOICE;
	break;

	case 1:
		p_call->info.type	= TCORE_CALL_TYPE_VIDEO;
	break;

	default:	// only Voice/VT call is supported in CS. treat other unknown calls as error
		dbg("invalid type : [%d]\n", mode );
		goto error;
	break;
   }
	dbg("type : [%d]\n", p_call->info.type );

   
    err = at_tok_nextint(&line, &(p_call->info.mpty));
    if (err < 0) goto error;
	dbg("mpty	: [%d]\n", p_call->info.mpty );	

    if (at_tok_hasmore(&line)) {
        err = at_tok_nextstr(&line, &num);

        /* tolerate null here */
        if (err < 0) return 0;

	memcpy(p_call->number, num, strlen(num));
	dbg("number	: [ %s ]\n", p_call->number );

	p_call->info.num_len = strlen(num);	
	dbg("num_len : [0x%x]\n", p_call->info.num_len );

        err = at_tok_nextint(&line, &(p_call->info.num_type));
        if (err < 0) goto error;
	dbg("num_type : [0x%x]\n", p_call->info.num_type );
	
    }

    return 0;

error:
    err("invalid CLCC line\n");
    return -1;
}

// NOTIFICATION

static void on_notification_call_waiting( CoreObject *o, const void *data, void *user_data )
{
	TcorePlugin* plugin = NULL;
	char* cmd = NULL, *num = NULL;
	CallObject *co, *dupco = 0;
	int id, status, err, type, mpty,direction; 
	GSList* pList = NULL;
#define LINE_DEFAULT 0

	dbg("call waiting noti : %s", cmd);	
	plugin = tcore_object_ref_plugin(o);

	cmd = (char*)data;

	at_tok_start(&cmd);

	err = at_tok_nextint(&cmd,&id);
	err = at_tok_nextint(&cmd,&direction);
	err = at_tok_nextint(&cmd,&status);
	err = at_tok_nextint(&cmd,&type);
	err = at_tok_nextint(&cmd,&mpty);

	if(at_tok_hasmore(&cmd)){
		err = at_tok_nextstr(&cmd,&num);
		dbg("id: %d, direction : %d, status : %d, type :%d, mpty : %d, num : %s", id,direction,status, type, mpty, num);
	}
	else	{
		dbg("id: %d, direction : %d, status : %d, type :%d, mpty : %d, num : NULL", id,direction,status, type, mpty);	
	}
// check call with incoming status already exist
	pList = tcore_call_object_find_by_status(o, TCORE_CALL_STATUS_WAITING);
	if(pList != NULL){
		dbg("waiting call already exist. skip");
		return;
	}

	pList = tcore_call_object_find_by_status(o, TCORE_CALL_STATUS_INCOMING);
	if(pList != NULL){
		dbg("incoming call already exist. skip");
		return;
	}

	dupco = tcore_call_object_find_by_id(o, id);
	if(dupco!= NULL){
		dbg("co with same id already exist. skip");
		return;
	}

// make new co, add to list
	co = tcore_call_object_new( o, id);
			if ( !co ) {
				dbg("[ error ] co is NULL");
				return ;
			}

	tcore_call_object_set_type(co, _call_type(type));
	tcore_call_object_set_multiparty_state(co,_call_is_in_mpty(mpty));
	tcore_call_object_set_direction(co, TCORE_CALL_DIRECTION_INCOMING);
	tcore_call_object_set_cli_info(co, TCORE_CALL_CLI_MODE_DEFAULT,  num);
	tcore_call_object_set_active_line(co, LINE_DEFAULT);

	_call_list_get( o, co );
}

static void on_notification_call_incoming( CoreObject *o, const void *data, void *user_data )
{
	TcorePlugin* plugin = NULL;
	char* cmd = NULL, *num = NULL;
	CallObject *co, *dupco = 0;
	int id, status, err, type, mpty,direction; 
	GSList* pList = NULL;
#define LINE_DEFAULT 0

	dbg("call incoming noti : %s", cmd);	
	plugin = tcore_object_ref_plugin(o);

	cmd = (char*)data;

	at_tok_start(&cmd);

	err = at_tok_nextint(&cmd,&id);
	err = at_tok_nextint(&cmd,&direction);
	err = at_tok_nextint(&cmd,&status);
	err = at_tok_nextint(&cmd,&type);
	err = at_tok_nextint(&cmd,&mpty);

	if(at_tok_hasmore(&cmd))	{
		err = at_tok_nextstr(&cmd,&num);
		dbg("id: %d, direction : %d, status : %d, type :%d, mpty : %d, num : %s", id,direction,status, type, mpty, num);
	}
	else	{
		dbg("id: %d, direction : %d, status : %d, type :%d, mpty : %d, num : NULL", id,direction,status, type, mpty);	
	}
// check call with incoming status already exist
	pList = tcore_call_object_find_by_status(o, TCORE_CALL_STATUS_INCOMING);
	if(pList != NULL){
		dbg("incoming call already exist. skip");
		return;
	}

	dupco = tcore_call_object_find_by_id(o, id);
	if(dupco!= NULL){
		dbg("co with same id already exist. skip");
		return;
	}

// make new co, add to list
	co = tcore_call_object_new( o, id);
			if ( !co ) {
				dbg("[ error ] co is NULL");
				return ;
			}

	tcore_call_object_set_type(co, _call_type(type));
	tcore_call_object_set_multiparty_state(co,_call_is_in_mpty(mpty));
	tcore_call_object_set_direction(co, TCORE_CALL_DIRECTION_INCOMING);
	tcore_call_object_set_cli_info(co, TCORE_CALL_CLI_MODE_DEFAULT,  num);
	tcore_call_object_set_active_line(co, LINE_DEFAULT);

	_call_list_get( o, co );

}

static void on_notification_call_status( CoreObject *o, const void *data, void *user_data)
{
	char* cmd = NULL, *num = NULL;
	TcorePlugin*	p  = 0;
	CallObject*			co = 0;
	int id, status, type, mpty,direction;
	int err;

	enum tcore_call_status co_status;

			p	= tcore_object_ref_plugin( o );
	cmd = (char*)data;

	at_tok_start(&cmd);

	err = at_tok_nextint(&cmd,&id);
	err = at_tok_nextint(&cmd,&direction);
	err = at_tok_nextint(&cmd,&status);
	err = at_tok_nextint(&cmd,&type);
	err = at_tok_nextint(&cmd,&mpty);

	if(at_tok_hasmore(&cmd))	{
		err = at_tok_nextstr(&cmd,&num);
		dbg("id: %d, direction : %d, status : %d, type :%d, mpty : %d, num : %s", id,direction,status, type, mpty, num);
	}
	else	{
		dbg("id: %d, direction : %d, status : %d, type :%d, mpty : %d, num : NULL", id,direction,status, type, mpty);	
	}

	co_status = _call_status(status);

	switch (co_status) {
		case CALL_STATUS_ACTIVE:{

		dbg("call(%d) status : [ ACTIVE ]", id);
		co	= tcore_call_object_find_by_id(o,id);
		if ( !co ) {
			dbg("co is NULL");
			return ;
		}
		_call_status_active( p, co );

		} break;
		case CALL_STATUS_HELD:
		break;
		case CALL_STATUS_DIALING:
		{
		dbg("call(%d) status : [ dialing ]", id);
		co	= tcore_call_object_find_by_id(o,id);		
		if ( !co ) {
			co = tcore_call_object_new( o, id );
			if ( !co ) {
				dbg("error : tcore_call_object_new [ id : %d ]", id);
				return ;
			}
		}

		tcore_call_object_set_type( co, _call_type(type) );
		tcore_call_object_set_direction( co, TCORE_CALL_DIRECTION_OUTGOING );

		_call_status_dialing( p, co );
		}
		break;
		case CALL_STATUS_ALERT:
		{

		dbg("call(%d) status : [ alert ]", id);
		co	= tcore_call_object_find_by_id(o, id);	
		if ( !co ) {
			dbg("co is NULL");
			return ;
		}

		_call_list_get( o, co );

		} break;
		case CALL_STATUS_INCOMING:
		case CALL_STATUS_WAITING:
		break;
		case CALL_STATUS_IDLE: {

				dbg("call(%d) status : [ release ]", id);

				co	= tcore_call_object_find_by_id( o, id );
				if ( !co )
					dbg("co is NULL");

				p	= tcore_object_ref_plugin( o );
				if ( !p )
					dbg("plugin is NULL");

				_call_status_idle( p, co );

			} break;

		default:
			break;
		}
}

static TReturn s_call_outgoing( CoreObject *o, UserRequest *ur )
{
	TcorePlugin*			p = NULL;
	CallObject*					co = 0;
	struct treq_call_dial*		data = 0;
	char*						raw_str= NULL;
	char*						cmd_str = NULL;
    const char *cclir;
	struct call_confirm_info_t* ci = 0;
	struct ATReqMetaInfo metainfo;
	int info_len =0;
	enum tcore_call_cli_mode clir = CALL_CLI_MODE_DEFAULT;

	gboolean					ret = FALSE;

	data	= (struct treq_call_dial*)tcore_user_request_ref_data( ur, 0 );
	p		= tcore_object_ref_plugin( o );
 
	ci = g_new0( struct call_confirm_info_t, 1 );
	ci->co = NULL;
	ci->resp = TRESP_CALL_DIAL;

	clir = _get_clir_status( data->number );

//Compose ATCmd string 
	switch (clir) 
	{
		case TCORE_CALL_CLI_MODE_PRESENT: 
			cclir = "I";
		break;  /*invocation*/
		case TCORE_CALL_CLI_MODE_RESTRICT: 
			cclir = "i"; 
		break;  /*suppression*/
		case TCORE_CALL_CLI_MODE_DEFAULT:
		default:
			cclir = "";
		break;   /*subscription default*/
	}

	raw_str = g_strdup_printf("ATD%s%s;", data->number, cclir);
	cmd_str = g_strdup_printf("%s%s",raw_str,"\r");

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));

//set metainfo
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	ret = _call_request_message ( o, ur, cmd_str, strlen(cmd_str), on_confirmation_call_request, ci); 

	free(raw_str);
	free(cmd_str);	
	
	if ( !ret ) {
		tcore_call_object_free( o, co );
		return TCORE_RETURN_FAILURE;
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_answer( CoreObject *o, UserRequest *ur )
{
	CallObject*					co = 0;
	struct treq_call_answer*	data = 0;
//	unsigned int				ipc_size = 0;
	gboolean					ret = FALSE;
	char*						cmd_str = NULL;
	struct ATReqMetaInfo metainfo ;
	unsigned int info_len =0;
	
	struct call_confirm_info_t* ci = 0;


	data = (struct treq_call_answer*)tcore_user_request_ref_data( ur, 0 );

	co = tcore_call_object_find_by_id( o, data->id );

	ci = g_new0( struct call_confirm_info_t, 1 );
	ci->co = co;
	ci->resp = TRESP_CALL_ANSWER;


	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));

//set metainfo
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] = '\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	if ( data->type == CALL_ANSWER_TYPE_ACCEPT ) {

		cmd_str = g_strdup_printf("%s%s","ATA","\r");
		ret = _call_request_message ( o, ur, (void*)cmd_str, strlen(cmd_str), on_confirmation_call_request, ci); 
		free(cmd_str);
		if ( !ret )
			return TCORE_RETURN_FAILURE;

	} else {

		switch ( data->type ) {
			case CALL_ANSWER_TYPE_REJECT: {
				dbg("call answer reject");
				tcore_call_control_answer_reject( o, ur, on_confirmation_call_request, ci );
			} break;

			case CALL_ANSWER_TYPE_REPLACE: {
				dbg("call answer replace");
				tcore_call_control_answer_replace( o, ur, on_confirmation_call_request, ci );
			} break;

			case CALL_ANSWER_TYPE_HOLD_ACCEPT: {
				dbg("call answer hold and accept");
				tcore_call_control_answer_hold_and_accept( o, ur, on_confirmation_call_hold_and_accept, ci );
			} break;

			default :
				dbg("[ error ] wrong answer type [ %d ]", data->type);
				return TCORE_RETURN_FAILURE;
		}
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_release( CoreObject *o, UserRequest *ur )
{
	CallObject*					co = 0;

	struct treq_call_end*		data = 0;
	struct call_confirm_info_t* ci = 0;
	gboolean					ret = FALSE;
	UserRequest* ur_dup = 0;

	char*					chld0_cmd = NULL;
	char*					chld1_cmd = NULL;
	struct ATReqMetaInfo metainfo1 ;
	struct ATReqMetaInfo  metainfo2 ;
	unsigned int info_len1, info_len2 =0;

	data = (struct treq_call_end*)tcore_user_request_ref_data( ur, 0 );

	co = tcore_call_object_find_by_id( o, data->id );

	ci = g_new0( struct call_confirm_info_t, 1 );
	ci->co = co;

	if ( data->type == CALL_END_TYPE_ALL ) {

		ci->resp = TRESP_CALL_END_ALL;

		//releaseAll do not exist on legacy request. send CHLD=0, CHLD=1 in sequence	
		chld0_cmd = g_strdup("AT+CHLD=0\r");
		chld1_cmd = g_strdup("AT+CHLD=1\r");

	memset(&metainfo1, 0, sizeof(struct ATReqMetaInfo));
	memset(&metainfo2, 0, sizeof(struct ATReqMetaInfo));


//set metainfo
		metainfo1.type = NO_RESULT;
		metainfo1.responsePrefix[0] = '\0';
		info_len1 = sizeof(struct ATReqMetaInfo);

//set metainfo
		metainfo2.type = NO_RESULT;
		metainfo2.responsePrefix[0] = '\0';
		info_len2 = sizeof(struct ATReqMetaInfo);

		ur_dup = tcore_user_request_new(NULL, NULL);

		tcore_user_request_set_metainfo(ur_dup, info_len1, &metainfo1);
		tcore_user_request_set_metainfo(ur, info_len2, &metainfo2);

		ret = _call_request_message(o, ur_dup, chld0_cmd, strlen(chld0_cmd), on_confirmation_call_endall, NULL);
		free(chld0_cmd);
		if ( !ret )
			return TCORE_RETURN_FAILURE;
		
		ret = _call_request_message(o, ur, chld1_cmd, strlen(chld1_cmd), on_confirmation_call_request, ci);
		free(chld1_cmd);
		if ( !ret )
			return TCORE_RETURN_FAILURE;		

	} else {

		switch ( data->type ) {
			case CALL_END_TYPE_DEFAULT: {
				int id = 0;
				id = tcore_call_object_get_id( co );

				ci->resp = TRESP_CALL_END;

				dbg("call end call id [%d]", id);
				tcore_call_control_end_specific( o, ur, id, on_confirmation_call_request, ci );
			} break;

			case CALL_END_TYPE_ACTIVE_ALL: {

				ci->resp = TRESP_CALL_END_ALL_ACTIVE;

				dbg("call end all active");
				tcore_call_control_end_all_active( o, ur, on_confirmation_call_request, ci );
			} break;

			case TCORE_CALL_END_ALL_HELD: {

				ci->resp = TRESP_CALL_END_ALL_HELD;

				dbg("call end all held");
				tcore_call_control_end_all_held( o, ur, on_confirmation_call_request, ci );
			} break;

			default :
				dbg("[ error ] wrong end type [ %d ]", data->type);
				return TCORE_RETURN_FAILURE;
		}

	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_hold( CoreObject *o, UserRequest *ur )
{
	struct call_confirm_info_t* ci = 0;
	unsigned int *id = 0;
	id = (unsigned int*)tcore_user_request_ref_data( ur, 0 );

	ci = g_new0( struct call_confirm_info_t, 1 );

	dbg("call id : [ %d ]", *id);

	ci->co = tcore_call_object_find_by_id( o, *id );
	ci->resp = TRESP_CALL_HOLD;

	tcore_call_control_hold( o, ur, on_confirmation_call_hold, ci );

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_active( CoreObject *o, UserRequest *ur )
{
	struct call_confirm_info_t* ci = 0;
	unsigned int *id = 0;
	id = (unsigned int*)tcore_user_request_ref_data( ur, 0 );

	ci = g_new0( struct call_confirm_info_t, 1 );

	dbg("call id : [ %d ]", *id);

	ci->co = tcore_call_object_find_by_id( o, *id );
	ci->resp = TRESP_CALL_ACTIVE;

	tcore_call_control_active( o, ur, on_confirmation_call_request, ci );

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_swap( CoreObject *o, UserRequest *ur )
{
	struct call_confirm_info_t* ci = 0;
	unsigned int *id = 0;
	id = (unsigned int*)tcore_user_request_ref_data( ur, 0 );

	ci = g_new0( struct call_confirm_info_t, 1 );

	dbg("call id : [ %d ]", *id);

	ci->co = tcore_call_object_find_by_id( o, *id );
	ci->resp = TRESP_CALL_SWAP;

	tcore_call_control_swap( o, ur, on_confirmation_call_swap, ci );

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_join( CoreObject *o, UserRequest *ur )
{
	struct call_confirm_info_t* ci = 0;
	unsigned int *id = 0;
	id = (unsigned int*)tcore_user_request_ref_data( ur, 0 );

	ci = g_new0( struct call_confirm_info_t, 1 );

	dbg("call id : [ %d ]", *id);

	ci->co = tcore_call_object_find_by_id( o, *id );
	ci->resp = TRESP_CALL_JOIN;

	tcore_call_control_join( o, ur, on_confirmation_call_request, ci );

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_split( CoreObject *o, UserRequest *ur )
{
	struct call_confirm_info_t* ci = 0;
	unsigned int *id = 0;

	ci = g_new0( struct call_confirm_info_t, 1 );

	id = (unsigned int *)tcore_user_request_ref_data( ur, 0 );
	ci->co = tcore_call_object_find_by_id ( o, *id );
	ci->resp = TRESP_CALL_SPLIT;

	tcore_call_control_split( o, ur, *id, on_confirmation_call_split, ci );

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_deflect( CoreObject *o, UserRequest *ur )
{
	struct call_confirm_info_t* ci = 0;
	char *number = 0;

	ci = g_new0( struct call_confirm_info_t, 1 );
	number = (char*)tcore_user_request_ref_data( ur, 0 );

	ci->co = tcore_call_object_find_by_number( o, number );
	ci->resp = TRESP_CALL_DEFLECT;

	tcore_call_control_deflect( o, ur, number, on_confirmation_call_request, ci );

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_transfer( CoreObject *o, UserRequest *ur )
{
	struct call_confirm_info_t* ci = 0;
	unsigned int *id = 0;
	id = (unsigned int*)tcore_user_request_ref_data( ur, 0 );

	ci = g_new0( struct call_confirm_info_t, 1 );

	dbg("call id : [ %d ]", *id);

	ci->co = tcore_call_object_find_by_id( o, *id );
	ci->resp = TRESP_CALL_TRANSFER;

	tcore_call_control_transfer( o, ur, on_confirmation_call_request, ci );

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_send_dtmf( CoreObject *o, UserRequest *ur )
{
	struct call_confirm_info_t* ci = 0;
	ci = g_new0( struct call_confirm_info_t, 1 );

	ci->co = 0;
	ci->resp = TRESP_CALL_SEND_DTMF;

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_set_sound_path( CoreObject *o, UserRequest *ur )
{

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_set_sound_volume_level( CoreObject *o, UserRequest *ur )
{

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_get_sound_volume_level( CoreObject *o, UserRequest *ur )
{

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_mute( CoreObject *o, UserRequest *ur )
{

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_unmute( CoreObject *o, UserRequest *ur )
{

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_get_mute_status( CoreObject *o, UserRequest *ur )
{

	return TCORE_RETURN_SUCCESS;
}


static struct tcore_call_operations call_ops = {
	.dial					= s_call_outgoing,
	.answer					= s_call_answer,
	.end					= s_call_release,
	.hold					= s_call_hold,
	.active					= s_call_active,
	.swap					= s_call_swap,
	.join					= s_call_join,
	.split					= s_call_split,
	.deflect				= s_call_deflect,
	.transfer				= s_call_transfer,
	.send_dtmf				= s_call_send_dtmf,
	.set_sound_path			= s_call_set_sound_path,
	.set_sound_volume_level = s_call_set_sound_volume_level,
	.get_sound_volume_level = s_call_get_sound_volume_level,
	.mute					= s_call_mute,
	.unmute					= s_call_unmute,
	.get_mute_status		= s_call_get_mute_status,
};


static void s_call_info_mo_waiting( CoreObject *o )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mo_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_WAITING,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mo_forwarded( CoreObject *o )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mo_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_FORWARDED,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mo_barred_incoming( CoreObject *o )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mo_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_BARRED_INCOMING,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mo_barred_outgoing( CoreObject *o )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mo_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_BARRED_OUTGOING,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mo_deflected( CoreObject *o )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mo_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_DEFLECTED,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mo_clir_suppression_reject( CoreObject *o )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mo_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_CLIR_SUPPRESSION_REJECT,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mo_cfu( CoreObject *o )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mo_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_FORWARD_UNCONDITIONAL,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mo_cfc( CoreObject *o )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mo_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_FORWARD_CONDITIONAL,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mt_cli( CoreObject *o, enum tcore_call_cli_mode mode, char* number )
{
	CallObject *co = 0;

	co = tcore_call_object_current_on_mt_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	tcore_call_object_set_cli_info( co, mode, number );
}

static void s_call_info_mt_cna( CoreObject *o, enum tcore_call_cna_mode mode, char* name, int dcs )
{
	CallObject *co = 0;

	co = tcore_call_object_current_on_mt_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}
	tcore_call_object_set_cna_info( co, mode, name, dcs );
}

static void s_call_info_mt_forwarded_call( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mt_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_FORWARDED_CALL,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mt_deflected_call( CoreObject *o, char* number ) 
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mt_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_DEFLECTED_CALL,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_mt_transfered( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_current_on_mt_processing( o );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_TRANSFERED_CALL,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_held( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_find_by_number( o, number );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_HELD,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_active( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_find_by_number( o, number );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_ACTIVE,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_joined( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_find_by_number( o, number );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_JOINED,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_released_on_hold( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_find_by_number( o, number );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_RELEASED_ON_HOLD,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_transfer_alert( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_find_by_number( o, number );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_TRANSFER_ALERT,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_transfered( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_find_by_number( o, number );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_TRANSFERED,
								sizeof(unsigned int),
								(void*)&id	);
}

static void s_call_info_cf_check_message( CoreObject *o, char* number )
{
	CallObject *co = 0;
	int id = 0;

	TcorePlugin *p = 0;
	p = tcore_object_ref_plugin(o);

	co = tcore_call_object_find_by_number( o, number );
	if ( !co ) {
		dbg("[ error ] can't find call object!");
		return ;
	}

	id = tcore_call_object_get_id( co );

	tcore_server_send_notification(	tcore_plugin_ref_server(p), 
								tcore_plugin_ref_core_object(p, "call"),
								TNOTI_CALL_INFO_CF_CHECK_MESSAGE,
								sizeof(unsigned int),
								(void*)&id	);
}


static struct tcore_call_information_operations call_information_ops = {
	.mo_call_col				= 0, 
	.mo_call_waiting			= s_call_info_mo_waiting,
	.mo_call_cug				= 0,
	.mo_call_forwarded			= s_call_info_mo_forwarded,
	.mo_call_barred_incoming	= s_call_info_mo_barred_incoming,
	.mo_call_barred_outgoing	= s_call_info_mo_barred_outgoing,
	.mo_call_deflected			= s_call_info_mo_deflected,
	.mo_call_clir_suppression_reject = s_call_info_mo_clir_suppression_reject,
	.mo_call_cfu				= s_call_info_mo_cfu,
	.mo_call_cfc				= s_call_info_mo_cfc,
	.mt_call_cli				= s_call_info_mt_cli,
	.mt_call_cna				= s_call_info_mt_cna,
	.mt_call_forwarded_call		= s_call_info_mt_forwarded_call,
	.mt_call_cug_call			= 0,
	.mt_call_deflected_call		= s_call_info_mt_deflected_call,
	.mt_call_transfered			= s_call_info_mt_transfered,
	.call_held					= s_call_info_held,
	.call_active				= s_call_info_active,
	.call_joined				= s_call_info_joined,
	.call_released_on_hold		= s_call_info_released_on_hold,
	.call_transfer_alert		= s_call_info_transfer_alert,
	.call_transfered			= s_call_info_transfered,
	.call_cf_check_message		= s_call_info_cf_check_message,
};

gboolean s_call_init( TcorePlugin *p )
{
	CoreObject *o = NULL;
//	TcoreHal *h = NULL;
	struct property_call_info *data = NULL;

	o = tcore_call_new( p, "call", &call_ops );
	if (!o)
		return FALSE;

	tcore_call_information_set_operations( o, &call_information_ops );

	tcore_object_add_callback( o, EVENT_CALL_STATUS, on_notification_call_status, NULL );
	tcore_object_add_callback( o, EVENT_CALL_INCOMING, on_notification_call_incoming, NULL );
	tcore_object_add_callback( o, EVENT_CALL_WAITING, on_notification_call_waiting, NULL );

	data = calloc( sizeof(struct property_call_info *), 1);
	tcore_plugin_link_property(p, "CALL", data);

	return TRUE;
}

void s_call_exit( TcorePlugin *p )
{
	CoreObject *o;
//	TcoreHal *h;
	struct property_network_info *data;

	o = tcore_plugin_ref_core_object(p, "call");

	data = tcore_plugin_ref_property(p, "CALL");
	if (data)
		free(data);

	tcore_call_free(o);
}
