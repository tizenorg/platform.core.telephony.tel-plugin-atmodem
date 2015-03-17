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

#include <glib.h>

#include <tcore.h>
#include <plugin.h>
#include <hal.h>
#include <server.h>

#include "s_common.h"
#include "s_sim.h"
#include "s_ps.h"
#include "s_call.h"
#include "s_ss.h"
#include "s_sms.h"
#include "s_network.h"
#include "s_modem.h"

static void on_hal_recv(TcoreHal *hal,
	unsigned int data_len, const void *data, void *user_data)
{
	hook_hex_dump(RX, data_len, data);
}

static enum tcore_hook_return on_hal_send(TcoreHal *hal,
	unsigned int data_len, void *data, void *user_data)
{
	hook_hex_dump(TX, data_len, data);
	return TCORE_HOOK_RETURN_CONTINUE;
}

static gboolean on_load()
{
	dbg("LOAD!!!");

	return TRUE;
}

static gboolean on_init(TcorePlugin *p)
{
	TcoreHal *h;

	dbg("INIT!!!");

	if (!p) {
		err("Plug-in is NULL");
		return FALSE;
	}

	h = tcore_server_find_hal(tcore_plugin_ref_server(p), "vmodem");
	if (!h)  {
		err("HAL is NULL");
		return FALSE;
	}

	tcore_hal_add_send_hook(h, on_hal_send, p);
	tcore_hal_add_recv_callback(h, on_hal_recv, p);

	/* Initialize Modules */
	s_modem_init(p, h);
	s_network_init(p, h);
	s_sim_init(p, h);
	s_ps_init(p, h);
	s_call_init(p, h);
	s_ss_init(p, h);
	s_sms_init(p, h);
#ifndef TEST_AT_SOCKET
	tcore_hal_set_power(h, TRUE);
#endif

	/* Send "CPAS" command to invoke POWER UP NOTI */
	s_modem_send_poweron(p);

	dbg("Init - Successful");

	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	TcoreHal *h;

	dbg("UNLOAD!!!");

	if (!p) {
		err("Plug-in is NULL");
		return;
	}

	h = tcore_server_find_hal(tcore_plugin_ref_server(p), "vmodem");
	if (h)  {
		tcore_hal_remove_send_hook(h, on_hal_send);
		tcore_hal_remove_recv_callback(h, on_hal_recv);
	}

	/* De-initialize Modules */
	s_modem_exit(p);
	s_network_exit(p);
	s_sim_exit(p);
	s_ps_exit(p);
	s_call_exit(p);
	s_ss_exit(p);
	s_sms_exit(p);
}

/* ATMODEM plug-in descriptor */
struct tcore_plugin_define_desc plugin_define_desc = {
	.name = "ATMODEM",
	.priority = TCORE_PLUGIN_PRIORITY_MID,
	.version = 1,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
