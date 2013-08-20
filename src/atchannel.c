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

#include "atchannel.h"
#include "at_tok.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

extern enum ATCommandType s_type;
extern char *s_responsePrefix;
extern struct ATResponse *sp_response;

/**
 * returns 1 if line is a final response indicating success
 * See 27.007 annex B
 */
static const char * s_finalResponsesSuccess[] = {
    "OK",
};
/**
 * returns 1 if line is a final response indicating error
 * See 27.007 annex B
 */
static const char * s_finalResponsesError[] = {
    "ERROR",
    "+CMS ERROR:",
    "+CME ERROR:",
    "NO ANSWER",
    "NO DIALTONE",
};


struct ATResponse * at_response_new()
{
     return (struct ATResponse *) calloc(1, sizeof(struct ATResponse));
}

void at_response_free(struct ATResponse *p_response)
{
    struct ATLine *p_line;

    if (p_response == NULL) return;

    p_line = p_response->p_intermediates;

    while (p_line != NULL) {
        struct ATLine *p_toFree;

        p_toFree = p_line;
        p_line = p_line->p_next;

        free(p_toFree->line);
        free(p_toFree);
    }

    free (p_response->finalResponse);
    free (p_response);
}

char * findNextEOL(char *cur)
{
    if (cur[0] == '>' && cur[1] == ' ' && cur[2] == '\0') {
        /* SMS prompt character...not \r terminated */
        return cur+2;
    }

    // Find next newline
    while (*cur != '\0' && *cur != '\r' && *cur != '\n') cur++;

    return *cur == '\0' ? NULL : cur;
}

/** returns 1 if line starts with prefix, 0 if it does not */
int strStartsWith(const char *line, const char *prefix)
{
    for ( ; *line != '\0' && *prefix != '\0' ; line++, prefix++) {
        if (*line != *prefix) {
            return 0;
        }
    }

    return *prefix == '\0';
}

int isFinalResponseError(const char *line)
{
    unsigned int i;

    for (i = 0 ; i < NUM_ELEMS(s_finalResponsesError) ; i++) {
        if (strStartsWith(line, s_finalResponsesError[i])) {
            return 1;
        }
    }

    return 0;
}

int isFinalResponseSuccess(const char *line)
{
     unsigned int i;

    for (i = 0 ; i < NUM_ELEMS(s_finalResponsesSuccess) ; i++) {
        if (strStartsWith(line, s_finalResponsesSuccess[i])) {
            return 1;
        }
    }

    return 0;
}

/**
 * returns 1 if line is a final response, either  error or success
 * See 27.007 annex B
 */
int isFinalResponse(const char *line)
{
    return isFinalResponseSuccess(line) || isFinalResponseError(line);
}

/** add an intermediate response to sp_response*/
void addIntermediate(const char *line)
{
    struct ATLine *p_new;

    printf("addIntermediate line arrived : %s", line);

    p_new = (struct ATLine*) malloc(sizeof(struct ATLine));

    p_new->line = strdup(line);

    /* note: this adds to the head of the list, so the list
       will be in reverse order of lines received. the order is flipped
       again before passing on to the command issuer */
    p_new->p_next = sp_response->p_intermediates;
    sp_response->p_intermediates = p_new;
}


//** release sp_response & s_responsePrefix
void ReleaseResponse(void)
{
	if(sp_response!=NULL)
	{
		at_response_free(sp_response);
		sp_response = NULL;
	}

	if(s_responsePrefix!= NULL)
	{
		free(s_responsePrefix);
		s_responsePrefix = NULL;
	}

	s_type = NO_RESULT;
}

void reverseIntermediates(struct ATResponse *p_response)
{
    struct ATLine *pcur,*pnext;

    pcur = p_response->p_intermediates;
    p_response->p_intermediates = NULL;

    while (pcur != NULL) {
        pnext = pcur->p_next;
        pcur->p_next = p_response->p_intermediates;
        p_response->p_intermediates = pcur;
        pcur = pnext;
    }
}

void printResponse(void)
{
   	struct ATLine *pcur= NULL;
   	struct ATLine *pnext= NULL;
	int count =0;

	printf("sp_response.success : %d\n", sp_response->success);

	if(sp_response->finalResponse ==NULL)
	{
		printf("sp_response.finalResponse : NULL\n");
	}
	else
	{
		printf("sp_response.finalResponse : %s\n",sp_response->finalResponse);
	}


	pcur = sp_response->p_intermediates;
	
	if(pcur ==NULL)
	{
		printf("sp_response.p_intermediates : NULL\n");
	}

	while(pcur != NULL)
	{
		printf("sp_response.p_intermediates[%d] : %s\n",count,pcur->line);
		pnext = pcur->p_next;	
		pcur = pnext;
		count++;
	}
}

TReturn convertCMEError(enum ATCMEError error)
{
	printf("CMEerror : %d", error);

	//mapping will be done later
	return TCORE_RETURN_3GPP_ERROR;

}
