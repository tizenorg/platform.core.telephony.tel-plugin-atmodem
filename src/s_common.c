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
#include <string.h>
#include <stdlib.h>

#include <glib.h>


#include "s_common.h"

#include <plugin.h>


void util_hex_dump(char *pad, int size, const void *data)
{
	char buf[255] = {0, };
	char hex[4] = {0, };
	int i;
	unsigned char *p;

	if (size <= 0) {
		msg("%sno data", pad);
		return;
	}

	p = (unsigned char *)data;

	snprintf(buf, 255, "%s%04X: ", pad, 0);
	for (i = 0; i<size; i++) {
		snprintf(hex, 4, "%02X ", p[i]);
		strcat(buf, hex);

		if ((i + 1) % 8 == 0) {
			if ((i + 1) % 16 == 0) {
				msg("%s", buf);
				memset(buf, 0, 255);
				snprintf(buf, 255, "%s%04X: ", pad, i + 1);
			}
			else {
				strcat(buf, "  ");
			}
		}
	}

	msg("%s", buf);
}

void hook_hex_dump(enum direction_e d, int size, const void *data)
{
	msg("=== TX data DUMP =====");
	util_hex_dump("          ", size, data);
	msg("=== TX data DUMP =====");

}

unsigned int util_assign_message_sequence_id(TcorePlugin *p)
{
	struct global_data *gd;

	if (!p) {
		dbg("plugin is NULL");
		return -1;
	}

	gd = tcore_plugin_ref_user_data(p);
	if (!gd) {
		dbg("global data is NULL");
		return -1;
	}

	if (gd->msg_auto_id_current == 0) {
		gd->msg_auto_id_current = gd->msg_auto_id_start;
		dbg("pending_auto_id_current is 0, reset to start");
	}
	else if (gd->msg_auto_id_current >= gd->msg_auto_id_end) {
		gd->msg_auto_id_current = gd->msg_auto_id_start;
		dbg("pending_auto_id_current is over, reset to start");
	}
	else {
		gd->msg_auto_id_current++;
	}

	dbg("message_sequence_id = %d", gd->msg_auto_id_current);

	return gd->msg_auto_id_current;
}

gboolean util_add_waiting_job(GQueue *queue, unsigned int id, UserRequest *ur)
{
	struct work_queue_data *wqd;

	if (!queue)
		return FALSE;

	wqd = calloc(sizeof(struct work_queue_data), 1);
	if (!wqd)
		return FALSE;

	wqd->id = id;
	wqd->ur = tcore_user_request_ref(ur);
	g_queue_push_tail(queue, wqd);

	dbg("id = %d, ur = 0x%x", wqd->id, wqd->ur);
	return TRUE;
}

UserRequest *util_pop_waiting_job(GQueue *queue, unsigned int id)
{
	int i = 0;
	UserRequest *ur;
	struct work_queue_data *wqd;

	if (!queue)
		return NULL;


	dbg("before waiting job count: %d", g_queue_get_length(queue));

	do {
		wqd = g_queue_peek_nth(queue, i);
		if (!wqd)
			return NULL;

		if (wqd->id == id) {
			wqd = g_queue_pop_nth(queue, i);
			break;
		}

		i++;
	} while (wqd != NULL);

	dbg("after  waiting job count: %d", g_queue_get_length(queue));

	if (!wqd)
		return NULL;

	ur = wqd->ur;
	free(wqd);

	return ur;
}

unsigned char util_hexCharToInt(char c)
{
    if (c >= '0' && c <= '9')
        return (c - '0');
    else if (c >= 'A' && c <= 'F')
        return (c - 'A' + 10);
    else if (c >= 'a' && c <= 'f')
        return (c - 'a' + 10);
    else
    {
        dbg("invalid charater!!");
        return -1;
    }
}

char * util_hexStringToBytes(char * s)
{
    char * ret;
    int     i;
    int         sz;

    if(s == NULL)
        return NULL;

        sz = strlen(s);

    ret = malloc(sz /2);

    dbg("Convert String to Binary!!");

    for(i = 0; i < sz; i += 2)
    {
        ret[i/2] = (char)((util_hexCharToInt(s[i]) << 4) | util_hexCharToInt(s[i + 1]));
        dbg("[%02x]", ret[i/2]);
    }

    return ret;
}

