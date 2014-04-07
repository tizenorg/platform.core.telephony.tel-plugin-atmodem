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
#include <string.h>
#include <stdlib.h>

#include <glib.h>

#include <log.h>
#include <tcore.h>

#include "atmodem_common.h"

void on_send_atmodem_request(TcorePending *p,
	TelReturn send_status, void *user_data)
{
	dbg("Send - [%s]",
		(send_status == TEL_RETURN_SUCCESS ? "OK" : "NOK"));
}

AtmodemRespCbData *atmodem_create_resp_cb_data(TcoreObjectResponseCallback cb,
	void *cb_data, void *data, guint data_len)
{
	AtmodemRespCbData *resp_cb_data;

	resp_cb_data = tcore_malloc0(sizeof(AtmodemRespCbData) + data_len);
	resp_cb_data->cb = cb;
	resp_cb_data->cb_data = cb_data;
	if ((data != NULL) && (data_len > 0))
		memcpy(resp_cb_data->data, data, data_len);

	return resp_cb_data;
}

void atmodem_destroy_resp_cb_data(AtmodemRespCbData *resp_cb_data)
{
	if (resp_cb_data)
		tcore_free(resp_cb_data);
}
