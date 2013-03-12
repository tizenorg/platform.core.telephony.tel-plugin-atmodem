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
#include <ctype.h>
#include <string.h>
#include <glib.h>

#include <tcore.h>
#include <plugin.h>
#include <hal.h>
#include <server.h>
#include <queue.h>

#include "s_common.h"
#include "s_sim.h"
#include "s_ps.h"
#include "s_call.h"
#include "s_ss.h"
#include "s_sms.h"
#include "s_network.h"
#include "s_modem.h"
#include "atchannel.h"
#include "at_tok.h"

static char s_ATBuffer[MAX_AT_RESPONSE+1];
static char *s_ATBufferCur = s_ATBuffer;

struct sms_pdu_control
{
	 gboolean sms_pdu_mode;

	 int sms_pdu_len;
	 int cum_pdu_len;
	 char* line1 ;
	 char* ppdu ;
	 char* ppdu_marker;
};

static struct sms_pdu_control spc;

static int s_readCount = 0;

enum ATCommandType s_type;
char *s_responsePrefix= NULL;
struct ATResponse *sp_response= NULL;


static const char * s_smsUnsoliciteds[] = {
    "+CMT:"
};

static int isSMSUnsolicited(const char *line)
{
    unsigned int i;

    for (i = 0 ; i < NUM_ELEMS(s_smsUnsoliciteds) ; i++) {
        if (strStartsWith(line, s_smsUnsoliciteds[i])) {
            return 1;
        }
    }

    return 0;
}

static void startSMSBuffering(char* line)
{
	char* temp_line = NULL;
	int sms_pdu_len;

	spc.line1 = strdup(line);

	temp_line = line;

	at_tok_start(&temp_line);
	at_tok_nextint(&temp_line, &sms_pdu_len);

	dbg("total pdu length : %d", sms_pdu_len);
	spc.sms_pdu_len = sms_pdu_len;

	//allocate pdu buffer
	spc.ppdu = malloc(sizeof(char) *sms_pdu_len);
	spc.sms_pdu_mode = TRUE;
	spc.cum_pdu_len = 0;
}

static void stopSMSBuffering()
{
	if(spc.line1 != NULL)
		free(spc.line1);
	spc.line1 = NULL;

	spc.sms_pdu_len = 0;
	spc.cum_pdu_len =0;

	spc.sms_pdu_mode = FALSE;

	if(spc.ppdu !=NULL)
		free(spc.ppdu);
	spc.ppdu = NULL;

	spc.ppdu_marker = NULL;

	dbg("sms pdu data buffering ended!");
}

static void handleFinalResponse(TcoreHal* hal, const char *line)
{
	dbg("Final response arrived. call response callback");

	// 1. add final rsp string into sp_response
	sp_response->finalResponse = strdup(line);

	// 1.1 reverse intermediates
	reverseIntermediates(sp_response);

	// 2. pop head pending from queue -> call callback hung pending(on_response) ->
	//	release sp_response/s_responsePrefix -> release userRequest/pending -> send next pending from queue
	//	warning) length have no meaning. data always pointer sp_response
	tcore_hal_dispatch_response_data(hal, ID_RESERVED_AT, strlen(line), sp_response);
}

static void onUnsolicited (const char *s, TcorePlugin* plugin, char* sms_pdu, int pdu_len)
{
	char *line = NULL, *p= NULL;
	char *cmd = NULL;
	struct smsDeliveryPDU smsPdu;

	int id;
	int status, direction;

#define STATUS_INCOMING 4
#define STATUS_WAITING 5


	if(strStartsWith(s,"+CMT:")){
		//SMS incoming
		cmd = EVENT_SMS_INCOM_MSG;

		smsPdu.cmdLine = strdup(s);
		smsPdu.pdu = malloc(pdu_len);
		memcpy(smsPdu.pdu, sms_pdu, pdu_len);
		smsPdu.len = pdu_len;

		tcore_plugin_core_object_event_emit(plugin, cmd, &smsPdu);
		free(smsPdu.cmdLine);
		free(smsPdu.pdu);

		return;
	}
	/* Ignore unsolicited responses until we're initialized.
	* This is OK because the RIL library will poll for initial state
	*/
	else if (strStartsWith(s,"%SCFUN:")){
        /* SS specific -- modem power status notification */
		cmd = EVENT_MODEM_PHONE_STATE;
	}
	else if(strStartsWith(s,"%SCSIM:")){
		cmd = EVENT_SIM_PIN_STATUS;
	}
	else if(strStartsWith(s,"%SCLCC:")){
		line = strdup(s);
		p = line;

		at_tok_start(&p);
		at_tok_nextint(&p, &id);
		at_tok_nextint(&p, &direction);
		at_tok_nextint(&p, &status);

		switch(status){
			case STATUS_INCOMING:
				cmd = EVENT_CALL_INCOMING;
			break;
			case STATUS_WAITING:
				cmd = EVENT_CALL_WAITING;
			break;
			default:
				cmd = EVENT_CALL_STATUS;
			break;
		}

		free(line);

		dbg("%SCLCC cmd : %d",cmd);
	}
	else if (strStartsWith(s,"+CRING:")
		|| strStartsWith(s,"RING")){
		dbg("incoming call notification - wait for SCLCC with status 4");
		return;
	}
	else if (strStartsWith(s,"CONNECT")){
		dbg("call connect notification - wait for SCLCC with status 0");
		return;
	}
	else if (strStartsWith(s,"NO CARRIER")){
		dbg("call release notification - wait for SCLCC with status 7");
		return ;
	}
	else if(strStartsWith(s,"+CCWA:")){
		dbg("call waiting notification - wait for SCLCC with status 5");
		return;
	}
	else if (strStartsWith(s,"+CREG:")
		|| strStartsWith(s,"+CGREG:")){
		cmd = EVENT_NETWORK_REGISTRATION;
	}
	else if (strStartsWith(s,"+CMGS:"))	{
		cmd = EVENT_SMS_SEND_ACK;
	}
	else if (strStartsWith(s,"%SCDEV:"))	{
		cmd = EVENT_SMS_DEVICE_READY;
	}
	else if(strStartsWith(s,"+CIEV:")){
		cmd = EVENT_NETWORK_ICON_INFO;
	}
	else if (strStartsWith(s,"+CSSU:")){
		cmd = EVENT_SS_INFO;
	}
	else if (strStartsWith(s,"+CUSD:")){
		cmd = EVENT_SS_USSD;
	}

	/* Send Event */
	if(cmd)
	{
		line = strdup(s);
		tcore_plugin_core_object_event_emit(plugin, cmd, line);
		free(line);
	}

}

static void processLine(TcoreHal *hal, char *line, TcorePlugin* p)
{
	TcoreQueue* pPendingQueue = NULL;
	TcorePending* pPending =NULL;
	gboolean result_status = FALSE;
	pPendingQueue =(TcoreQueue*)tcore_hal_ref_queue(hal);
	pPending = (TcorePending*)tcore_queue_ref_head(pPendingQueue); //topmost request

	dbg("processLine -------start");

	if(TCORE_RETURN_SUCCESS == tcore_pending_get_send_status(pPending, &result_status)
		&& (result_status == FALSE))//request not sent but data comes - Unsolicited msg!
	{
		/* no command pending */
		dbg("no command pending. call onUnsolicited()");
		onUnsolicited(line, p, NULL, 0);
	} else if (isFinalResponseSuccess(line)) {
		dbg("final response -success. call handleFinalResponse()");
		sp_response->success = 1;
		handleFinalResponse(hal, line);
	} else if (isFinalResponseError(line)) {
		dbg("final response -ERROR. call handleFinalResponse()");
		sp_response->success = 0;
		handleFinalResponse(hal, line);
	} else switch (s_type) {
		case NO_RESULT:
		{
			dbg("[NO_RESULT]:call onUnsolicited()");
			onUnsolicited(line, p, NULL, 0);
		}
		break;
		case NUMERIC:
		{
			if (sp_response->p_intermediates == NULL
				&& isdigit(line[0])
			) {
				dbg("[NUMERIC]:line[0] is digit. call addIntermediate()");
				addIntermediate(line);
			} else {
				/* either we already have an intermediate response or
				the line doesn't begin with a digit */
				dbg("[NUMERIC]:either we already have an intermediate response or the line doesn't begin with a digit. call onUnsolicited()");
				onUnsolicited(line,p,NULL, 0);
			}
		}
		break;
		case SINGLELINE:
		{
			if (sp_response->p_intermediates == NULL
				&& strStartsWith (line, s_responsePrefix)
			) {
				dbg("[SINGLELINE]:line starts with s_responsePrefix. call addIntermediate()");
				addIntermediate(line);
			} else {
				/* we already have an intermediate response */
				dbg("[SINGLELINE]:we already have an intermediate response. call onUnsolicited()");
				onUnsolicited(line,p, NULL, 0);
			}
		}
		break;
		case MULTILINE:
		if (strStartsWith (line, s_responsePrefix)) {
			dbg("[MULTILINE]:line starts with s_responsePrefix. call addIntermediate()");
			addIntermediate(line);
		} else {
			dbg("[MULTILINE]:line don't starts with s_responsePrefix. call onUnsolicited()");
			onUnsolicited(line,p, NULL, 0);
		}
		break;

		default: /* this should never be reached */
			err("Unsupported AT command type %d\n", s_type);
			onUnsolicited(line,p, NULL, 0);
		break;
	}
}

static gboolean readline(TcoreHal *hal, unsigned int data_len, const void *data, TcorePlugin* p)
{
	char *ret;
	char *p_read = NULL;
	char *p_eol = NULL;
	char *p_marker = NULL;
	int len, leftover_len;

	char* act_data;
	int act_len;

	act_data = (char*)data;
	act_len = data_len;

	dbg("recv string = %s, length : %d", (char*)act_data, act_len);
	/* this is a little odd. I use *s_ATBufferCur == 0 to
	* mean "buffer consumed completely". If it points to a character, than
	* the buffer continues until a \0
	*/

	/*check sms pdu cumulating process - data hijacking*/
	if(spc.sms_pdu_mode == TRUE)
	{ //continue sms pdu buffering
		dbg("resume pdu buffering. pdu size : %d, gathered size : %d",spc.sms_pdu_len,spc.cum_pdu_len);
		len = spc.sms_pdu_len - spc.cum_pdu_len; //length needed

		if(act_len > len){
			dbg("whole pdu received - data surplus");
			memcpy(spc.ppdu_marker, act_data,len);//data fully copied
			spc.cum_pdu_len = spc.cum_pdu_len + len;

			//change data & datalen
			act_data = act_data + len;
			act_len = act_len - len;
			dbg("recv string changed to = %s, length changed to : %d", (char*)act_data, act_len);

			onUnsolicited(spc.line1, p, spc.ppdu, spc.sms_pdu_len);
			stopSMSBuffering();
			dbg("incoming sms handled. back to normal mode & continue");
		}
		else if(act_len == len){
			dbg("exactly whole pdu received");

			memcpy(spc.ppdu_marker, act_data,len);//data fully copied
			spc.cum_pdu_len = spc.cum_pdu_len + len;

			onUnsolicited(spc.line1, p, spc.ppdu, spc.sms_pdu_len);
			stopSMSBuffering();
			dbg("all incoming data consumed. return");
			return TRUE;
		}
		else	{
			dbg("data received but not sufficient");
			memcpy(spc.ppdu_marker, act_data,act_len);
			spc.ppdu_marker = spc.ppdu_marker +act_len;
			spc.cum_pdu_len = spc.cum_pdu_len + act_len;
			dbg("data buffered. wait for more data");
			return TRUE;
		}
	}


	if (*s_ATBufferCur == '\0')
	{
		/* empty buffer */
		s_ATBufferCur = s_ATBuffer;
		*s_ATBufferCur = '\0';
		p_read = s_ATBuffer;
	}
	else
	{
		/* *s_ATBufferCur != '\0' */
		/* there's data in the buffer from the last read */

		// skip over leading newlines
		while (*s_ATBufferCur == '\r' || *s_ATBufferCur == '\n')
			s_ATBufferCur++;

		p_eol = findNextEOL(s_ATBufferCur);

		if (p_eol == NULL)
		{
			/* a partial line. move it up and prepare to read more */
			unsigned int  len;
			len = strlen(s_ATBufferCur);

			memmove(s_ATBuffer, s_ATBufferCur, len + 1);
			p_read = s_ATBuffer + len;
			s_ATBufferCur = s_ATBuffer;
		}
		/* Otherwise, (p_eol !- NULL) there is a complete line  */
		else
		{
			err("this should not be happening - complete data pending??");
		}

	}

	if (0 > MAX_AT_RESPONSE - ((p_read - s_ATBuffer)+(int)act_len))
	{
		dbg("ERROR: Input line exceeded buffer\n");
		/* ditch buffer and start over again */
		s_ATBufferCur = s_ATBuffer;
		*s_ATBufferCur = '\0';
		p_read = s_ATBuffer;
	}

	//copy data into buffer
	memcpy(p_read, act_data, act_len);

	if (act_len <= 0)
	{
		/* read error encountered or EOF reached */
		if(act_len == 0) {
			err("atchannel: EOF reached");
		}
		else {
			err("invalid data coming");
		}
		return FALSE;
	}
	else
	{
		s_readCount += act_len;
		p_read[act_len] = '\0';

		p_marker = p_read + act_len; //pin the last position of data copy
	}


	do
	{
		// skip over leading newlines
		while (*s_ATBufferCur == '\r' || *s_ATBufferCur == '\n')
			s_ATBufferCur++;

		p_eol = findNextEOL(s_ATBufferCur);

		if(p_eol !=NULL) /*end of line found!*/
		{
			/* a full line in the buffer. Place a \0 over the \r and return */
			ret = s_ATBufferCur;
			*p_eol = '\0';
			s_ATBufferCur = p_eol + 1; /* this will always be <= p_read,    */
			/* and there will be a \0 at *p_read */

			dbg("complete line found. process it/n");
			dbg("rsp line : %s/n",ret);
			if(1 == isSMSUnsolicited(ret))
			{
				dbg("start of incoming sms found!!! - next data is PDU");
				startSMSBuffering(ret);
				s_ATBufferCur++; //move starting point by 1 - it goes to the very starting point of PDU
				leftover_len = p_marker - s_ATBufferCur;

				dbg("count leftover : %d", leftover_len);
				if(leftover_len <0){
					dbg("pointer address error -serious!");
					return FALSE;
				}
				else if(leftover_len ==0){
					dbg("no pdu received - wait for incoming data");
					spc.cum_pdu_len =0;
					spc.ppdu_marker = spc.ppdu;
				}
				else if(leftover_len >= spc.sms_pdu_len){
					dbg("whole  pdu already received!");
					memcpy(spc.ppdu, s_ATBufferCur, spc.sms_pdu_len);
					spc.cum_pdu_len = spc.sms_pdu_len;
					onUnsolicited(spc.line1, p, spc.ppdu, spc.sms_pdu_len);
					s_ATBufferCur = s_ATBufferCur+spc.sms_pdu_len;
					dbg("move buffercur to point the very end of pdu!");
					stopSMSBuffering();
				}
				else	{
					dbg("staring part of pdu received!");
					memcpy(spc.ppdu, s_ATBufferCur,leftover_len);
					spc.ppdu_marker = spc.ppdu + leftover_len;
					spc.cum_pdu_len = leftover_len;
					s_ATBufferCur = s_ATBufferCur + leftover_len;
				}

			}
			else
			{
			processLine(hal, ret,p);
			}
		}
		else
		{
			dbg("complete responses all handled/n");
		}
	}while(p_eol != NULL);

	dbg("all the pending rsp's handled. wait for next incoming data/n");
	return TRUE;
}

static enum tcore_hook_return on_hal_send(TcoreHal *hal, unsigned int data_len, void *data, void *user_data)
{
	hook_hex_dump(TX, data_len, data);
	return TCORE_HOOK_RETURN_CONTINUE;
}

static void on_hal_recv(TcoreHal *hal, unsigned int data_len, const void *data, void *user_data)
{
	gboolean ret = FALSE;
	TcorePlugin *plugin = user_data;

	ret = readline(hal,data_len, data,plugin);
}

static gboolean on_load()
{
	dbg("i'm load!");

	return TRUE;
}

static gboolean on_init(TcorePlugin *p)
{
	TcoreHal *h;

	if (!p)
		return FALSE;

	dbg("i'm init!");

	h = tcore_server_find_hal(tcore_plugin_ref_server(p), "vmodem");
	if (!h)  {
		return FALSE;
	}

	tcore_hal_add_send_hook(h, on_hal_send, p);
	tcore_hal_add_recv_callback(h, on_hal_recv, p);

	s_modem_init(p, h);
	s_network_init(p, h);
	s_sim_init(p, h);
//	s_sap_init(p);
	s_ps_init(p, h);
	s_call_init(p, h);
	s_ss_init(p, h);
	s_sms_init(p, h);
//	s_phonebook_init(p);
#ifndef TEST_AT_SOCKET
	tcore_hal_set_power(h, TRUE);
#endif
//send "CPAS" command to invoke POWER UP NOTI
	s_modem_send_poweron(p);

	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	struct global_data *gd;

	if (!p)
		return;

	dbg("i'm unload");

	gd = tcore_plugin_ref_user_data(p);
	if (gd) {
		free(gd);
	}
}

struct tcore_plugin_define_desc plugin_define_desc =
{
	.name = "ATMODEM",
	.priority = TCORE_PLUGIN_PRIORITY_MID,
	.version = 1,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
