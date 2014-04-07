#ifndef __ATCHANNEL_H__
#define __ATCHANNEL_H__

/* //device/system/reference-ril/atchannel.c
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/
//code from atchannel.c - android
#include "type/common.h"

#define AT_ERROR_GENERIC -1
#define AT_ERROR_COMMAND_PENDING -2
#define AT_ERROR_CHANNEL_CLOSED -3
#define AT_ERROR_TIMEOUT -4
#define AT_ERROR_INVALID_THREAD -5 /* AT commands may not be issued from
                                       reader thread (or unsolicited response
                                       callback */
#define AT_ERROR_INVALID_RESPONSE -6 /* eg an at_send_command_singleline that
                                        did not get back an intermediate
                                        response */

#define MAX_AT_RESPONSE (8 * 1024)
#define MAX_AT_RESP_PREFIX 10

#define NUM_ELEMS(x) (sizeof(x)/sizeof(x[0]))

#define ID_RESERVED_AT 0x0229


enum ATCommandType{
    NO_RESULT,   /* no intermediate response expected */
    NUMERIC,     /* a single intermediate response starting with a 0-9 */
    SINGLELINE,  /* a single intermediate response starting with a prefix */
    MULTILINE    /* multiple line intermediate response
                    starting with a prefix */
};

enum ATCMEError{
	AT_ERROR_MOBILE_FAILRURE					=0,
	AT_ERROR_NOT_CONNECTED_TO_PHONE		=1,
	AT_ERROR_LINK_RESERVED					=2,
	AT_ERROR_OPER_NOT_ALLOWED				=3,
	AT_ERROR_OPER_NOT_SUPPORTED			=4,
	AT_ERROR_PH_SIM_PIN_REQUIRED			=5,
	AT_ERROR_PH_FSIM_PIN_REQUIRED			=6,
	AT_ERROR_PH_FSIM_PUK_REQUIRED			=7,

	AT_ERROR_SIM_NOT_INSERTED				=10,
	AT_ERROR_SIM_PIN_REQUIRED				=11,
	AT_ERROR_SIM_PUK_REQUIRED				=12,
	AT_ERROR_SIM_FAILURE						=13,
	AT_ERROR_SIM_BUSY							=14,
	AT_ERROR_SIM_WRONG						=15,
	AT_ERROR_INCORRECT_PWD					=16,
	AT_ERROR_SIM_PIN2_REQUIRED				=17,
	AT_ERROR_SIM_PUK2_REQUIRED				=18,

	AT_ERROR_MEMORY_FULL						=20,
	AT_ERROR_INVALID_INDEX					=21,
	AT_ERROR_NOT_FOUND						=22,
	AT_ERROR_MEMORY_FAILURE					=23,
	AT_ERROR_TEXT_TOO_LONG					=24,
	AT_ERROR_INVALID_CHAR_IN_STR			=25,
	AT_ERROR_DIAL_TOO_LONG					=26,
	AT_ERROR_INVALID_CHAR_IN_DIAL			=27,

	AT_ERROR_NO_NETWORK_SVC					=30,
	AT_ERROR_NETWORK_TIMEOUT				=31,
	AT_ERROR_EMERGENCY_CALL_ONLY			=32,

	AT_ERROR_NET_PERSONAL_PIN_REQ			=40,
	AT_ERROR_NET_PERSONAL_PUN_REQ			=41,
	AT_ERROR_NET_SUB_PERSONAL_PIN_REQ		=42,
	AT_ERROR_NET_SUB_PERSONAL_PUK_REQ		=43,
	AT_ERROR_PROVIDER_PERSONAL_PIN_REQ		=44,
	AT_ERROR_PROVIDER_PERSONAL_PUK_REQ		=45,
	AT_ERROR_CORP_PERSONAL_PIN_REQ			=46,
	AT_ERROR_CORP_PERSONAL_PUK_REQ			=47,
	AT_ERROR_HIDDEN_KEY_REQUIRED			=48,
	AT_ERROR_EAP_METHOD_NOT_SUPPORTED		=49,
	AT_ERROR_INCORRECT_PARAM				=50,

	AT_ERROR_UNKNOWN							=100
};



/** a singly-lined list of intermediate responses */
struct ATLine  {
    struct ATLine *p_next;
    char *line;
} ;

/** Free this with at_response_free() */
struct ATResponse{
    int success;              /* true if final response indicates
                                    success (eg "OK") */
    char *finalResponse;      /* eg OK, ERROR */
    struct ATLine  *p_intermediates; /* any intermediate responses */
} ;

struct ATReqMetaInfo{
	enum ATCommandType type;
	char responsePrefix[MAX_AT_RESP_PREFIX];
};

struct smsDeliveryPDU{
char* cmdLine;
char* pdu;
int	len;
};

//utility API for at command response parsing
/**
 * Returns a pointer to the end of the next line
 * special-cases the "> " SMS prompt
 *
 * returns NULL if there is no complete line
 */
char * findNextEOL(char *cur);
struct ATResponse * at_response_new();
void at_response_free(struct ATResponse *p_response);
int strStartsWith(const char *line, const char *prefix);
        /* SMS prompt character...not \r terminated */
int isFinalResponseError(const char *line);
int isFinalResponseSuccess(const char *line);

int isFinalResponse(const char *line);
void addIntermediate(const char *line);
void ReleaseResponse(void);
void reverseIntermediates(struct ATResponse *p_response);
void printResponse(void);
TReturn convertCMEError(enum ATCMEError error);

#include <log.h> /* err */
#include <stdio.h> /* __file__, __line__ */

#define AT_TOK_ERROR(token) AT_TOK_ERROR_INTERNEL(token, __FILE__, __LINE__)
#define AT_TOK_ERROR_INTERNEL(token, file, line) \
{\
	ReleaseResponse();\
	err("AT_TOK_ERROR %s:%d %s",file,line,token?token:"");\
	return;\
}\

#define AT_NOTI_TOK_ERROR(token) AT_NOTI_TOK_ERROR_INTERNEL(token, __FILE__, __LINE__)
#define AT_NOTI_TOK_ERROR_INTERNEL(token, file, line) \
{\
	err("AT_NOTI_TOK_ERROR_INTERNEL %s:%d %s",file,line,token?token:"");\
	return TRUE;\
}\

#endif /* __ATCHANNEL_H__ */
/*EOF*/

