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
#include <co_sms.h>
#include <co_sim.h>
#include <user_request.h>
#include <storage.h>
#include <server.h>

#include "s_common.h"
#include "s_sms.h"

#include "atchannel.h"
#include "at_tok.h"

#define MAX_GSM_SMS_TPDU_SIZE               244
#define MAX_GSM_SMS_PARAM_RECORD_SIZE       156 /* Maximum number of bytes SMSP Record size (Y + 28), y : 0 ~ 128 */
#define SWAPBYTES16(x) \
{ \
    unsigned short int data = *(unsigned short int*)&(x); \
    data = ((data & 0xff00) >> 8) |    \
           ((data & 0x00ff) << 8);     \
    *(unsigned short int*)&(x) = data ;      \
}

extern struct ATResponse *sp_response;
extern char *s_responsePrefix;
extern enum ATCommandType s_type;

static TReturn Send_SmsSubmitTpdu(CoreObject *o, UserRequest *ur);

/************************************************************/
/*********************  Utility for SMS  *************************/
/************************************************************/
static void util_sms_get_length_of_sca(int* nScLength) {
	if (*nScLength % 2) {
		*nScLength = (*nScLength / 2) + 1;
	} else {
		*nScLength = *nScLength / 2;
	}

	return;
}

static int util_sms_decode_smsParameters(unsigned char *incoming, unsigned int length, struct telephony_sms_Params *params)
{
	int alpha_id_len = 0;
	int i = 0;
	int nOffset = 0;

	dbg(" RecordLen = %d", length);

	if(incoming == NULL || params == NULL)
		return FALSE;

	alpha_id_len = length -SMS_SMSP_PARAMS_MAX_LEN;

	if ( alpha_id_len > 0 )
	{
		if(alpha_id_len > SMS_SMSP_ALPHA_ID_LEN_MAX)
		{
			alpha_id_len = SMS_SMSP_ALPHA_ID_LEN_MAX;
		}

		for( i=0 ; i < alpha_id_len ; i++)
		{
			if( 0xff == incoming[i])
			{
				dbg(" found");
				break;
			}
		}

		memcpy(params->szAlphaId, incoming, i);

		params->alphaIdLen = i;

		dbg(" Alpha id length = %d", i);

	}
	else
	{
		params->alphaIdLen = 0;
		dbg(" Alpha id length is zero");
	}

	// start parse from here.
	params->paramIndicator = incoming[alpha_id_len];

	dbg(" Param Indicator = %02x", params->paramIndicator);

	// DestAddr
	if( (params->paramIndicator & SMSPValidDestAddr) == 0)
	{
		nOffset = nDestAddrOffset;

		if( 0x00 == incoming[alpha_id_len + nOffset] || 0xff == incoming[alpha_id_len + nOffset])
		{
			params->tpDestAddr.dialNumLen = 0;

			dbg("DestAddr Length is 0");
		}
		else
		{
			if ( 0 < (int)incoming[alpha_id_len + nOffset] )
			{
				params->tpDestAddr.dialNumLen = (int)(incoming[alpha_id_len + nOffset] - 1 );

			        if(params->tpDestAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
				        params->tpDestAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;
			}
			else
			{
				params->tpDestAddr.dialNumLen = 0;
			}

			params->tpDestAddr.numPlanId= incoming[alpha_id_len + (++nOffset)] & 0x0f ;
			params->tpDestAddr.typeOfNum= (incoming[alpha_id_len + nOffset] & 0x70 )>>4 ;

			memcpy( params->tpDestAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)], (params->tpDestAddr.dialNumLen)) ;

			dbg("Dest TON is %d",params->tpDestAddr.typeOfNum);
			dbg("Dest NPI is %d",params->tpDestAddr.numPlanId);
			dbg("Dest Length = %d",params->tpDestAddr.dialNumLen);
			dbg("Dest Addr = %s",params->tpDestAddr.diallingNum);

		}
	}

	// SvcAddr
	if( (params->paramIndicator & SMSPValidSvcAddr) == 0)
	{
		nOffset = nSCAAddrOffset;

		if( 0x00 == (int)incoming[alpha_id_len + nOffset] || 0xff == (int)incoming[alpha_id_len + nOffset] )
		{
			params->tpSvcCntrAddr.dialNumLen = 0;

			dbg(" SCAddr Length is 0");
		}
		else
		{
			if ( 0 < (int)incoming[alpha_id_len + nOffset]  )
			{
				params->tpSvcCntrAddr.dialNumLen = (int)(incoming[alpha_id_len + nOffset] - 1);

			        if(params->tpSvcCntrAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
				        params->tpSvcCntrAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;

				params->tpSvcCntrAddr.numPlanId= incoming[alpha_id_len + (++nOffset)] & 0x0f ;
				params->tpSvcCntrAddr.typeOfNum= (incoming[alpha_id_len + nOffset] & 0x70) >>4 ;

				memcpy( params->tpSvcCntrAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)], (params->tpSvcCntrAddr.dialNumLen));

				dbg("SCAddr Length = %d ",params->tpSvcCntrAddr.dialNumLen);
				dbg("SCAddr TON is %d",params->tpSvcCntrAddr.typeOfNum);
				dbg("SCAddr NPI is %d",params->tpSvcCntrAddr.numPlanId);

				for( i = 0 ; i < (int)params->tpSvcCntrAddr.dialNumLen ; i ++)
					dbg("SCAddr = %d [%02x]",i,params->tpSvcCntrAddr.diallingNum[i]);
			}
			else
			{
				params->tpSvcCntrAddr.dialNumLen = 0;
			}
		}
	}
	else if ( (0x00 < (int)incoming[alpha_id_len +nSCAAddrOffset] && (int)incoming[alpha_id_len +nSCAAddrOffset] <= 12 )
			|| 0xff != (int)incoming[alpha_id_len +nSCAAddrOffset])
	{
		nOffset = nSCAAddrOffset;

		if( 0x00 == (int)incoming[alpha_id_len + nOffset] || 0xff == (int)incoming[alpha_id_len + nOffset] )
		{
			params->tpSvcCntrAddr.dialNumLen = 0;
			dbg("SCAddr Length is 0");
		}
		else
		{

			if ( 0 < (int)incoming[alpha_id_len + nOffset]  )
			{
				params->tpSvcCntrAddr.dialNumLen = (int)(incoming[alpha_id_len + nOffset] - 1);

				params->tpSvcCntrAddr.dialNumLen = incoming[alpha_id_len + nOffset] -1;

			        if(params->tpSvcCntrAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
				        params->tpSvcCntrAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;

				params->tpSvcCntrAddr.numPlanId= incoming[alpha_id_len + (++nOffset)] & 0x0f ;
				params->tpSvcCntrAddr.typeOfNum= (incoming[alpha_id_len + nOffset] & 0x70) >>4 ;

				memcpy( params->tpSvcCntrAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)],
						(params->tpSvcCntrAddr.dialNumLen)) ;

				dbg("SCAddr Length = %d ",params->tpSvcCntrAddr.dialNumLen);
				dbg("SCAddr TON is %d",params->tpSvcCntrAddr.typeOfNum);
				dbg("SCAddr NPI is %d",params->tpSvcCntrAddr.numPlanId);

				for( i = 0 ; i < (int)params->tpSvcCntrAddr.dialNumLen ; i ++)
					dbg("SCAddr = %d [%02x]",i,params->tpSvcCntrAddr.diallingNum[i]);
			}
			else
			{
				params->tpSvcCntrAddr.dialNumLen = 0;
			}
		}

	}

	if( (params->paramIndicator & SMSPValidPID) == 0 &&	(alpha_id_len + nPIDOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
	{
		params->tpProtocolId = incoming[alpha_id_len + nPIDOffset];
	}
	if( (params->paramIndicator & SMSPValidDCS) == 0 && (alpha_id_len + nDCSOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
	{
		params->tpDataCodingScheme = incoming[alpha_id_len + nDCSOffset];
	}
	if( (params->paramIndicator & SMSPValidVP) == 0 && (alpha_id_len + nVPOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
	{
		params->tpValidityPeriod = incoming[alpha_id_len + nVPOffset];
	}

	dbg(" Alpha Id(Len) = %d",(int)params->alphaIdLen);

	for (i=0; i< (int)params->alphaIdLen ; i++)
	{
		dbg(" Alpha Id = [%d] [%c]",i,params->szAlphaId[i]);
	}
	dbg(" PID = %d",params->tpProtocolId);
	dbg(" DCS = %d",params->tpDataCodingScheme);
	dbg(" VP = %d",params->tpValidityPeriod);

	return TRUE;
}

static int util_sms_ipcError2SmsError(int err)
{
	int returnStatus=0;

	switch(err)
	{
		case 300: //ME Failure;
			returnStatus = SMS_PHONE_FAILURE;
			break;
		case 302: //Operation not allowed;
		case 303: //Operation not supported;
			returnStatus = SMS_OPERATION_NOT_SUPPORTED;
			break;
		case 304: //Invalid PDU mode parameter;
		case 305: //Invalid text mode parameter;
			returnStatus = SMS_INVALID_PARAMETER_FORMAT;
			break;
		case 320: //memory failure;
		case 321: //invalid memory index;
		case 322: //memory full;
			returnStatus = SMS_MEMORY_FAILURE;
			break;
		case 330: //SCA unknown;
		case 500: //Unknown error;
		default:
			returnStatus = SMS_UNKNOWN;
			break;
	}

	return returnStatus;
}

/************************************************************/
/************************  Events Cb  *************************/
/************************************************************/

static gboolean on_event_sms_incom_msg(CoreObject *o, const void *event_info, void *user_data)
{
	struct smsDeliveryPDU *smsPdu = (struct smsDeliveryPDU *)event_info;
	int *property;
	struct tnoti_sms_umts_msg gsmMsgInfo;

	int ScLength = 0, i = 0;
	unsigned char LastSemiOctect;

	memset(&gsmMsgInfo, 0, sizeof(struct tnoti_sms_umts_msg));
	// +CMT: <length><CR><LF><pdu>
	ScLength = smsPdu->pdu[0];

	dbg(" ScLength is %d",ScLength);

	LastSemiOctect = smsPdu->pdu[ScLength + 1] & 0xf0;
	if( LastSemiOctect == 0xf0 )
	{
		smsPdu->pdu[0] = (ScLength-1)*2 - 1;
	}
	else
	{
		smsPdu->pdu[0] = (ScLength-1)*2;
	}

	gsmMsgInfo.msgInfo.msgLength = smsPdu->len - ScLength;
	dbg(" MSG LENGTH [%d]", gsmMsgInfo.msgInfo.msgLength);

	if ( (gsmMsgInfo.msgInfo.msgLength >0) && (0xff >= gsmMsgInfo.msgInfo.msgLength))
	{
		property = tcore_plugin_ref_property(tcore_object_ref_plugin(o), "SMSPRECORDLEN");
		if(!property) {
			dbg("property is NULL");
			return TRUE;
		}

		memcpy(gsmMsgInfo.msgInfo.sca, &smsPdu->pdu[0], (ScLength+1));

		for(i=0;i<(ScLength+1);i++)
		{
			dbg("SCA is [%02x] ",gsmMsgInfo.msgInfo.sca[i]);
		}

		if(gsmMsgInfo.msgInfo.msgLength > SMS_SMDATA_SIZE_MAX)
		{
			gsmMsgInfo.msgInfo.msgLength = SMS_SMDATA_SIZE_MAX;
		}

		memcpy(gsmMsgInfo.msgInfo.tpduData, &smsPdu->pdu[ScLength +1], gsmMsgInfo.msgInfo.msgLength);

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_INCOM_MSG, sizeof(struct tnoti_sms_umts_msg), &gsmMsgInfo);

	}
	else
	{
		dbg("Invalid Message Length");
	}

	return TRUE;
}

static gboolean on_event_sms_device_ready(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_sms_ready_status readyStatusInfo = {0,};
	int rtn = -1;

	dbg(" Func Entrance");
	readyStatusInfo.status = TRUE;
	tcore_sms_set_ready_status(o, readyStatusInfo.status);

	dbg("SMS Ready status = [%s]", readyStatusInfo.status ? "TRUE" : "FALSE");

	rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_DEVICE_READY, sizeof(struct tnoti_sms_ready_status), &readyStatusInfo);

	dbg(" Return value [%d]",rtn);

	return TRUE;
}

/*************************************************************/
/***********************  Responses Cb  ************************/
/************************************************************/
static void on_confirmation_sms_message_send( TcorePending *p, gboolean result, void *user_data )
{
	UserRequest* ur = NULL;
	struct ATReqMetaInfo* metainfo = NULL;
	unsigned int info_len =0;
	dbg("on_confirmation_call_message_send - msg out from queue. alloc ATRsp buffer & write rspPrefix if needed\n");

	ReleaseResponse(); //release leftover

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

static void on_response_send_umts_msg(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_send_umts_msg respSendMsg;

	int error;
	char *line = NULL;
	int ret;

	memset(&respSendMsg, 0, sizeof(struct tresp_sms_send_umts_msg));
	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	printResponse();

	if(sp_response->success == TRUE)
	{
		ReleaseResponse();
		ur = tcore_user_request_ref(ur);
		ret = (int) Send_SmsSubmitTpdu(tcore_pending_ref_core_object(p), ur);

		if(ret != (int)TCORE_RETURN_SUCCESS)
		{
			respSendMsg.result = SMS_INVALID_PARAMETER;
			tcore_user_request_send_response(ur, TRESP_SMS_SEND_UMTS_MSG, sizeof(struct tresp_sms_send_umts_msg), &respSendMsg);
		}
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

		respSendMsg.result = util_sms_ipcError2SmsError(error);

		tcore_user_request_send_response(ur, TRESP_SMS_SEND_UMTS_MSG, sizeof(struct tresp_sms_send_umts_msg), &respSendMsg);
	}

	return;
}

static void on_response_send_smsSubmitTpdu(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	struct tresp_sms_send_umts_msg respUmtsInfo;

	char *line = NULL;
	char *ackpdu = NULL;
	int ret;
	int mr;
	int error;
	char *hexData;

	printResponse();

	if(sp_response->success > 0)
	{
		line = sp_response->p_intermediates->line;

		memset(&respUmtsInfo, 0 , sizeof(struct tresp_sms_send_umts_msg));
		// +CMGS: <mr>[, <ackpdu>]
		// SMS_SMDATA_SIZE_MAX + 1
		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line, &mr);
		if (ret < 0)
			return;

		ret = at_tok_nextstr(&line, &hexData);
		if (ret < 0)
		{
			dbg(" ackpdu is NULL ");
			ackpdu = NULL;
		} else {
			ackpdu = util_hexStringToBytes(hexData);
			util_hex_dump("    ", strlen(hexData)/2, ackpdu);
		}

		dbg(" Func Entrance ");

		ur = tcore_pending_ref_user_request(p);
		if(ur)
		{
			respUmtsInfo.result = SMS_SENDSMS_SUCCESS;

			tcore_user_request_send_response(ur, TRESP_SMS_SEND_UMTS_MSG, sizeof(struct tresp_sms_send_umts_msg), &respUmtsInfo);

		} else
			dbg("no user_request");
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


		//5. release sp_response & s_responsePrefix - before sending user callback, because user callback can request additional request
		// and if queue is empty, that req can be directly sent to mdm - can cause sp_response, s_responsePrefix dangling
		ReleaseResponse();

		ur = tcore_pending_ref_user_request(p);
		if (ur) {
			struct tresp_sms_send_umts_msg respSendMsg;

			memset(&respSendMsg, 0, sizeof(struct tresp_sms_send_umts_msg));
			respSendMsg.result = SMS_INVALID_MANDATORY_INFO;

			respSendMsg.result = util_sms_ipcError2SmsError(error);

			tcore_user_request_send_response(ur, TRESP_SMS_SEND_UMTS_MSG, sizeof(struct tresp_sms_send_umts_msg), &respSendMsg);
		}
		else {
			dbg("no user_request");
		}
	}
}

static void on_response_get_storedMsgCnt(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_storedMsgCnt respStoredMsgCnt;

	int error;
	char *line = NULL;
	int ret;
	int usedCount = 0;
	int totalCount = 0;

	memset(&respStoredMsgCnt, 0, sizeof(struct tresp_sms_get_storedMsgCnt));
	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	printResponse();

	if(sp_response->success > 0)
	{
		//failure case - consider this later
		line = sp_response->p_intermediates->line;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&usedCount);
		if (ret < 0)
			AT_TOK_ERROR(line);
		ret = at_tok_nextint(&line,&totalCount);
		if (ret < 0)
			AT_TOK_ERROR(line);

		respStoredMsgCnt.storedMsgCnt.totalCount = totalCount;
		respStoredMsgCnt.storedMsgCnt.usedCount = usedCount;

		dbg(" totalCount:%d, usedCount:%d",respStoredMsgCnt.storedMsgCnt.totalCount , respStoredMsgCnt.storedMsgCnt.usedCount );

		respStoredMsgCnt.result = SMS_SUCCESS;
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

		respStoredMsgCnt.result = util_sms_ipcError2SmsError(error);
	}

	ReleaseResponse();


	tcore_user_request_send_response(ur, TRESP_SMS_GET_STORED_MSG_COUNT, sizeof(struct tresp_sms_get_storedMsgCnt), &respStoredMsgCnt);

	return;

}

static void on_response_get_sca(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_sca respGetSca;

	char* line=NULL;
	int ret = 0;
	char *scaStr = NULL;
	int scaType = 0;
	int error;

	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	printResponse();

	// +CSCA: <sca number>,<sca type>
	if(sp_response->success > 0)
	{
		respGetSca.result = SMS_SUCCESS;

		line = sp_response->p_intermediates->line;
		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextstr(&line, &scaStr);
		if (ret < 0)
			AT_TOK_ERROR(line);
		memcpy(respGetSca.scaAddress.diallingNum, scaStr, strlen(scaStr));


		line = sp_response->p_intermediates->line;
		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextstr(&line,&scaStr);
		if(scaStr!=NULL)
			ret = at_tok_nextint(&line,&scaType);

		respGetSca.scaAddress.dialNumLen = strlen(scaStr);
		if(scaType == 145)
			respGetSca.scaAddress.typeOfNum = SIM_TON_INTERNATIONAL;
		else		respGetSca.scaAddress.typeOfNum = SIM_TON_NATIONAL;
		respGetSca.scaAddress.numPlanId = 0;

		memcpy(respGetSca.scaAddress.diallingNum, scaStr, strlen(scaStr));

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

		respGetSca.result = util_sms_ipcError2SmsError(error);

	}

	ReleaseResponse();

	tcore_user_request_send_response(ur, TRESP_SMS_GET_SCA, sizeof(struct tresp_sms_get_sca), &respGetSca);

	return;
}

static void on_response_set_sca(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_set_sca respSetSca;
	int ret;
	int error;
	char *line = NULL;

	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	printResponse();

	if(sp_response->success > 0)
	{
		respSetSca.result = SMS_SUCCESS;
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

		respSetSca.result = util_sms_ipcError2SmsError(error);
	}

	ReleaseResponse();

	tcore_user_request_send_response(ur, TRESP_SMS_SET_SCA, sizeof(struct tresp_sms_get_sca), &respSetSca);

	return;
}

static void on_response_set_delivery_report(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_set_delivery_report respSetDeliveryReport = {0,};

	int error;
	char *line = NULL;
	int ret;

	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	printResponse();

	if(sp_response->success > 0)
	{
		respSetDeliveryReport.result = SMS_SUCCESS;
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

		respSetDeliveryReport.result = util_sms_ipcError2SmsError(error);
	}

	ReleaseResponse();


	tcore_user_request_send_response(ur, TRESP_SMS_SET_DELIVERY_REPORT, sizeof(struct tresp_sms_set_delivery_report), &respSetDeliveryReport);

	return;
}

static void on_response_get_sms_params(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_params respGetSmsParams;
	int *property = NULL;

	char *line = NULL;
	int error;
	int ret = 0;
	int sw1 = 0;
	int sw2 = 0;
	char *recordData;

	memset(&respGetSmsParams, 0, sizeof(struct tresp_sms_get_params));
	printResponse();


	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

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

		if(sw1 != 144 || sw2 != 0)
			respGetSmsParams.result = SMS_UNKNOWN;
		else
		{
			char *hexData;

			ret = at_tok_nextstr(&line,&hexData);
			if (ret < 0)
				AT_TOK_ERROR(line);

			recordData = util_hexStringToBytes(hexData);
			util_hex_dump("    ", strlen(hexData)/2, recordData);

			// respGetSmsParams.paramsInfo.recordIndex = 0;
			respGetSmsParams.paramsInfo.recordLen = strlen(hexData)/2;

			property = tcore_plugin_ref_property(tcore_object_ref_plugin(tcore_pending_ref_core_object(p)), "SMSPRECORDLEN");

			if(!property) {
				dbg("property is NULL");
				free(recordData);
				return;
			}

			util_sms_decode_smsParameters((unsigned char *)recordData, strlen(hexData) / 2, &respGetSmsParams.paramsInfo);
			*property = respGetSmsParams.paramsInfo.recordLen;

			respGetSmsParams.result = SMS_SUCCESS;

			free(recordData);
		}
	}
	else
	{
		respGetSmsParams.result = SMS_UNKNOWN;
		//failure case - consider this later
		line = sp_response->finalResponse;

		ret = at_tok_start(&line);
		if (ret < 0)
			AT_TOK_ERROR(line);

		ret = at_tok_nextint(&line,&error);
		if (ret < 0)
			AT_TOK_ERROR(line);

		respGetSmsParams.result = util_sms_ipcError2SmsError(error);
	}

	ReleaseResponse();

	tcore_user_request_send_response(ur, TRESP_SMS_GET_PARAMS, sizeof(struct tresp_sms_get_params), &respGetSmsParams);

	return;
}

static void on_response_get_paramcnt(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_paramcnt respGetParamCnt = {0,};
	CoreObject *co_sim = NULL;
	char *line = NULL;
	int ret = 0;
	int sw1 = 0;
	int sw2 = 0;

	ur = tcore_pending_ref_user_request(p);

	if(sp_response->success == TRUE)
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

			co_sim = tcore_plugin_ref_core_object(tcore_pending_ref_plugin(p), CORE_OBJECT_TYPE_SIM);
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
								file_type = 0x01;	//SIM_FTYPE_TRANSPARENT
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
								file_type = 0x02;	// SIM_FTYPE_LINEAR_FIXED
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
								file_type = 0x04;	//SIM_FTYPE_CYCLIC
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
			}
			else if (tcore_sim_get_type(co_sim) == SIM_TYPE_GSM)
			{
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
									(file_type_tag == 0x00) ? 0x01 : 0x02; // SIM_FTYPE_TRANSPARENT:SIM_FTYPE_LINEAR_FIXED;
						} else {
							/* increment to next byte */
							ptr_data++;
							/*	For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
							/* the INCREASE command is allowed on the selected cyclic file. */
							file_type = 0x04;	// SIM_FTYPE_CYCLIC;
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

			dbg("EF[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]", file_id, file_size, file_type, num_of_records, record_len);

			respGetParamCnt.recordCount = num_of_records;
			respGetParamCnt.result = SMS_SUCCESS;

			free(recordData);
		}
		else
		{
			/*2. SIM access fail case*/
			dbg("SIM access fail");
			respGetParamCnt.result = SMS_UNKNOWN;
		}
	}
	else
	{
		dbg("response error!!!");
		respGetParamCnt.result = SMS_UNKNOWN;
	}

	ReleaseResponse();

	tcore_user_request_send_response(ur, TRESP_SMS_GET_PARAMCNT, sizeof(struct tresp_sms_get_paramcnt), &respGetParamCnt);

	return;

}

/********************************************************/
/***********************  Requests ************************/
/********************************************************/
static TReturn send_umts_msg(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_send_umts_msg *sendUmtsMsg = NULL;
	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	dbg("new pending(IPC_SMS_SEND_MSG)");

	sendUmtsMsg = tcore_user_request_ref_data(ur, NULL);

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	if (!sendUmtsMsg || !h)
		return TCORE_RETURN_ENOSYS;

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	// AT+CMMS=<mode>
	cmd_str = g_strdup_printf("AT+CMMS=%d%s", sendUmtsMsg->more, "\r");
	dbg("[tcore_SMS] *************************MsgLen[%d]", sendUmtsMsg->msgDataPackage.msgLength);

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_send_umts_msg, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	free(cmd_str);

	return tcore_hal_send_request(h, pending);
}

static TReturn Send_SmsSubmitTpdu(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_send_umts_msg *sendUmtsMsg = NULL;
	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;
	char tpdu[MAX_GSM_SMS_TPDU_SIZE];
	int ScLength = 0;
	char *hexString = NULL;
	int tpduDataLen = 0;
	int i = 0;

	TReturn api_err = TCORE_RETURN_SUCCESS;

	dbg("new pending(IPC_SMS_SEND_MSG)");

	sendUmtsMsg = tcore_user_request_ref_data(ur, NULL);

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	if (!sendUmtsMsg || !h)
		return TCORE_RETURN_ENOSYS;

	/* Populate data */
	dbg("[tcore_SMS] MoreToSend[0x%x](1:Persist, 2:NotPersist) MsgLen[%d]",sendUmtsMsg->more, sendUmtsMsg->msgDataPackage.msgLength);
	for(i=0; i<sendUmtsMsg->msgDataPackage.msgLength; i++)
		dbg("[%02x]", sendUmtsMsg->msgDataPackage.tpduData[i]);

	if ((sendUmtsMsg->msgDataPackage.msgLength > 0) && (MAX_GSM_SMS_TPDU_SIZE > sendUmtsMsg->msgDataPackage.msgLength))
	{
		if (sendUmtsMsg->msgDataPackage.msgLength < SMS_SMDATA_SIZE_MAX)
		{
			memset(tpdu, 0, sizeof(MAX_GSM_SMS_TPDU_SIZE));

			memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
			metainfo.type = SINGLELINE;
			memcpy(metainfo.responsePrefix,"+CMGS:",strlen("+CMGS:"));
			info_len = sizeof(struct ATReqMetaInfo);

			tcore_user_request_set_metainfo(ur, info_len, &metainfo);

			ScLength = sendUmtsMsg->msgDataPackage.sca[0];
			if(sendUmtsMsg->msgDataPackage.sca[0] == 0)
			{
				memcpy(&tpdu[0], sendUmtsMsg->msgDataPackage.sca, ScLength+2);
			}
			else
			{
				dbg("SC length in ipc tx is %d - before", ScLength);

				util_sms_get_length_of_sca(&ScLength);

				dbg(" SC length in ipc tx is %d - after", ScLength);

				tpdu[0] = ScLength +1 ;
				//1Copy SCA to the ipc stream first
				memcpy(&(tpdu[1]), &( sendUmtsMsg->msgDataPackage.sca[1]), (ScLength + 1));
			}

			if ((ScLength <= SMS_SMSP_ADDRESS_LEN) && (sendUmtsMsg->msgDataPackage.msgLength < SMS_SMDATA_SIZE_MAX))
			{
				//1Copy rest of the SMS-SUBMIT TPDU
				memcpy(&(tpdu[ScLength + 2]), sendUmtsMsg->msgDataPackage.tpduData, sendUmtsMsg->msgDataPackage.msgLength);
			} else
			{
				dbg("SCA len is %d", ScLength);
				api_err = TCORE_RETURN_SMS_INVALID_DATA_LEN;
				return api_err;
			}

			tpduDataLen = sendUmtsMsg->msgDataPackage.msgLength + (ScLength + 2);
			hexString = calloc(tpduDataLen*2, 1);;

			for( i=0; i<tpduDataLen*2; i+=2)
			{
				char value = 0;

				value = (tpdu[i/2] & 0xf0 ) >> 4;
				if(value < 0xA)
					hexString[i] = ((tpdu[i/2] & 0xf0 ) >> 4) + '0';
				else hexString[i] = ((tpdu[i/2] & 0xf0 ) >> 4) + 'A' -10;

				value = tpdu[i/2] & 0x0f;
				if(value < 0xA)
					hexString[i+1] = (tpdu[i/2] & 0x0f ) + '0';
				else hexString[i+1] = (tpdu[i/2] & 0x0f ) + 'A' -10;

			}

			// AT+CMGS=<length><CR>pdu_is_given<ctrl-z/ESC>
			cmd_str = g_strdup_printf("AT+CMGS=%d%s%s%x%s", sendUmtsMsg->msgDataPackage.msgLength, "\r", hexString, 0x1A,"\r");
			dbg("cmd_str is %s", cmd_str);

			pending = tcore_pending_new(o, ID_RESERVED_AT);
			tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
			tcore_pending_set_timeout(pending, 0);
			tcore_pending_set_response_callback(pending, on_response_send_smsSubmitTpdu, NULL);
			tcore_pending_link_user_request(pending, ur);

			tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

			api_err = tcore_hal_send_request(h, pending);

			free(cmd_str);
			free(hexString);
		}
		else
		{
			dbg("[tcore_SMS] TPDU size[%d] is over !!!, max is [%d]", sendUmtsMsg->msgDataPackage.msgLength, SMS_SMDATA_SIZE_MAX);
			api_err = TCORE_RETURN_SMS_INVALID_DATA_LEN;
			return api_err;
		}
	}
	else
	{
		dbg("[tcore_SMS] Invalid Data Length");
		api_err = TCORE_RETURN_SMS_INVALID_DATA_LEN;
	}

	return api_err;

}

static TReturn send_cdma_msg(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;}

static TReturn read_msg(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn save_msg(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn delete_msg(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn get_storedMsgCnt(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_get_msg_count *getStoredMsgCnt = NULL;

	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	dbg("new pending(IPC_SMS_GET_STORED_MSG_COUNT)");

	getStoredMsgCnt = tcore_user_request_ref_data(ur, NULL);

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	if (!h)
	{
		dbg("[ERR]  tcore_object_get_hal() pointer is NULL");
		return TCORE_RETURN_ENOSYS;
	}

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = SINGLELINE;
	memcpy(metainfo.responsePrefix,"+CPMS:",strlen("+CPMS:"));
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	// AT+CPMS=<mem1>[,<mem2>[,<mem3>]]
	// Possible response(s) : +CPMS: <used1>,<total1>,<used2>,<total2>,<used3>,<total3>
	cmd_str = g_strdup_printf("AT+CPMS=\"SM\"%s", "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_get_storedMsgCnt, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	free(cmd_str);

	return tcore_hal_send_request(h, pending);

}

static TReturn get_sca(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_get_sca *getSca = NULL;
	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	dbg("new pending(IPC_SMS_GET_SCA)");

	getSca = tcore_user_request_ref_data(ur, NULL);

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	if (!getSca || !h)
		return TCORE_RETURN_ENOSYS;

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = SINGLELINE;
	memcpy(metainfo.responsePrefix,"+CSCA:",strlen("+CSCA:"));
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	// AT +CSCA?
	// Possible response(s) : +CSCA: <sca number>,<sca type>
	cmd_str = g_strdup_printf("AT +CSCA?%s", "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_get_sca, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	free(cmd_str);

	return tcore_hal_send_request(h, pending);

}

static TReturn set_sca(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_set_sca *setSca;
	int scaType = 0;
	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	dbg("new pending(IPC_SMS_SET_SCA)");

	setSca = tcore_user_request_ref_data(ur, NULL);

	if(setSca->index != 0){
		dbg("Index except 0 is supported");
		return TCORE_RETURN_EINVAL;	// TCORE_API_NOT_SUPPORTED;
	}

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	if (!setSca || !h)
		return TCORE_RETURN_ENOSYS;

	if(setSca->scaInfo.typeOfNum == SIM_TON_INTERNATIONAL)
			scaType = 145;
	else		scaType = 129;

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	// AT +CSCA=<sca number>[,<sca type>]
	// 129:Unknown numbering plan, national/international number unknown, 145:international number
	cmd_str = g_strdup_printf("AT+CSCA=\"%s\", %d%s", setSca->scaInfo.diallingNum, scaType, "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_set_sca, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	free(cmd_str);

	return tcore_hal_send_request(h, pending);

}

static TReturn get_cb_config(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn set_cb_config(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn set_mem_status(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn get_pref_brearer(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn set_pref_brearer(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn set_delivery_report(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_set_delivery_report *deliveryReport = NULL;
	char *cmd_str;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	dbg("new pending(IPC_SMS_SVC_CENTER_ADDR)");

	deliveryReport = tcore_user_request_ref_data(ur, NULL);

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	if (!deliveryReport || !h)
		return TCORE_RETURN_ENOSYS;

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = NO_RESULT;
	metainfo.responsePrefix[0] ='\0';
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	// AT+CNMA
	if(deliveryReport->rspType == SMS_SENDSMS_SUCCESS)
		cmd_str = g_strdup_printf("AT+CNMA=0%s", "\r");
	else
		cmd_str = g_strdup_printf("AT+CNMA=2,3%s%x%s", "/n", 0x00ff00, "");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_set_delivery_report, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	free(cmd_str);

	return tcore_hal_send_request(h, pending);

}

static TReturn set_msg_status(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn get_sms_params(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_get_params *getSmsParams = NULL;

	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	dbg("new pending(IPC_SMS_GET_CBS_CFG)");

	getSmsParams = tcore_user_request_ref_data(ur, NULL);

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	if (!getSmsParams || !h)
	{
		dbg("[ERR]  pointer is NULL, getSmsParams=0x%x, h=0x%x", getSmsParams, h);
		return TCORE_RETURN_ENOSYS;
	}

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = SINGLELINE;
	memcpy(metainfo.responsePrefix,"+CRSM:",strlen("+CRSM:"));
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	// AT+CRSM=<command>,<fildid>,<p1>,<p2+C29,<p3>
	cmd_str = g_strdup_printf("AT+CRSM=%d, %d, %d, 4, 40%s", 178, 0x6F42, getSmsParams->index + 1, "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_get_sms_params, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	free(cmd_str);

	return tcore_hal_send_request(h, pending);

}

static TReturn set_sms_params(CoreObject *o, UserRequest *ur)
{
	dbg("[tcore_SMS] Not supported");
	return TCORE_RETURN_ENOSYS;
}

static TReturn get_paramcnt(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_get_paramcnt *getParamCnt = NULL;

	char *cmd_str = NULL;
	struct ATReqMetaInfo metainfo;
	int info_len =0;

	getParamCnt = tcore_user_request_ref_data(ur, NULL);

	p = tcore_object_ref_plugin(o);
	h = tcore_object_get_hal(o);

	if (!h) // request data is NULL, so do not NULL check for getParamCnt
	{
		dbg("[ERR]  pointer is NULL, getParamCnt=0x%x, h=0x%x", getParamCnt, h);
		return TCORE_RETURN_ENOSYS;
	}

	memset(&metainfo, 0, sizeof(struct ATReqMetaInfo));
	metainfo.type = SINGLELINE;
	memcpy(metainfo.responsePrefix,"+CRSM:",strlen("+CRSM:"));
	info_len = sizeof(struct ATReqMetaInfo);

	tcore_user_request_set_metainfo(ur, info_len, &metainfo);

	// AT+CRSM=<command>,<fildid>,<p1>,<p2+C29,<p3>, EFsmsp: 0x6F42
	cmd_str = g_strdup_printf("AT+CRSM=192, %d%s", 0x6F42, "\r");

	pending = tcore_pending_new(o, ID_RESERVED_AT);
	tcore_pending_set_request_data(pending, strlen(cmd_str), cmd_str);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_get_paramcnt, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	free(cmd_str);

	return tcore_hal_send_request(h, pending);
}

static struct tcore_sms_operations sms_ops =
{
	.send_umts_msg = send_umts_msg,
	.read_msg = read_msg,
	.save_msg = save_msg,
	.delete_msg = delete_msg,
	.get_stored_msg_cnt = get_storedMsgCnt,
	.get_sca = get_sca,
	.set_sca = set_sca,
	.get_cb_config = get_cb_config,
	.set_cb_config = set_cb_config,
	.set_mem_status = set_mem_status,
	.get_pref_brearer = get_pref_brearer,
	.set_pref_brearer = set_pref_brearer,
	.set_delivery_report = set_delivery_report,
	.set_msg_status = set_msg_status,
	.get_sms_params = get_sms_params,
	.set_sms_params = set_sms_params,
	.get_paramcnt = get_paramcnt,
	.send_cdma_msg = send_cdma_msg,
};

gboolean s_sms_init(TcorePlugin *cp, CoreObject *co)
{
	int *smsp_record_len;
	GQueue *work_queue;

	dbg("Entry");

	/* Override SMS Operations */
	tcore_sms_override_ops(co, &sms_ops);

	work_queue = g_queue_new();
	tcore_object_link_user_data(co, work_queue);

	tcore_object_override_callback(co, EVENT_SMS_INCOM_MSG, on_event_sms_incom_msg, NULL);
	tcore_object_override_callback(co, EVENT_SMS_DEVICE_READY, on_event_sms_device_ready, NULL);

	/* Storing SMSP record length */
	smsp_record_len = g_new0(int, 1);
	tcore_plugin_link_property(cp, "SMSPRECORDLEN", smsp_record_len);

	dbg("Exit");

	return TRUE;
}

void s_sms_exit(TcorePlugin *cp, CoreObject *co)
{
	GQueue *work_queue;
	int *smsp_record_len;

	smsp_record_len = tcore_plugin_ref_property(cp, "SMSPRECORDLEN");
	g_free(smsp_record_len);

	work_queue = tcore_object_ref_user_data(co);
	if (work_queue)
		g_queue_free(work_queue);

	dbg("Exit");
}

