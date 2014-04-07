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

#ifndef __ATMODEM_COMMON_H__
#define __ATMODEM_COMMON_H__

#define ATMODEM_SWAP_BYTES_16(x) \
{ \
	unsigned short int data = *(unsigned short int *)&(x);	\
	data = ((data & 0xff00) >> 8) |	  \
		   ((data & 0x00ff) << 8);	  \
	*(unsigned short int *)&(x) = data;	 \
}

typedef struct {
	TcoreObjectResponseCallback cb;
	void *cb_data;
	char data[]; /* Additional data */
} AtmodemRespCbData;

#define ATMODEM_GET_DATA_FROM_RESP_CB_DATA(ptr) (gpointer)ptr->data
#define ATMODEM_CHECK_REQUEST_RET(ret, resp_cb_data, request) \
do {\
	if (ret != TEL_RETURN_SUCCESS) { \
		err("Failed to process request - [%s]", request); \
		atmodem_destroy_resp_cb_data(resp_cb_data); \
	} \
} while(0)

AtmodemRespCbData *atmodem_create_resp_cb_data(TcoreObjectResponseCallback cb,
	void *cb_data, void *data, guint data_len);
void atmodem_destroy_resp_cb_data(AtmodemRespCbData *resp_cb_data);

void on_send_atmodem_request(TcorePending *p,
	TelReturn send_status, void *user_data);

#endif	/* __ATMODEM_COMMON_H__ */
