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
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <glib.h>

#include <tcore.h>
#include <plugin.h>
#include <hal.h>
#include <server.h>
#include <queue.h>
#include <core_object.h>
#include <at.h>

#include "atmodem_common.h"
#include "atmodem_sim.h"
#include "atmodem_ps.h"
#include "atmodem_call.h"
#include "atmodem_ss.h"
#include "atmodem_sms.h"
#include "atmodem_network.h"
#include "atmodem_modem.h"

/* Initializer Table */
TcoreObjectInitializer atmodem_init_table = {
	.modem_init = atmodem_modem_init,
	.sim_init = atmodem_sim_init,
	.sat_init = NULL,
	.sap_init = NULL,
	.network_init = atmodem_network_init,
	.ps_init = atmodem_ps_init,
	.call_init = atmodem_call_init,
	.ss_init = atmodem_ss_init,
	.sms_init = atmodem_sms_init,
	.phonebook_init = NULL,
	.gps_init = NULL,
};

/* Deinitializer Table */
TcoreObjectDeinitializer atmodem_deinit_table = {
	.modem_deinit = atmodem_modem_exit,
	.sim_deinit = atmodem_sim_exit,
	.sat_deinit = NULL,
	.sap_deinit = NULL,
	.network_deinit = atmodem_network_exit,
	.ps_deinit = atmodem_ps_exit,
	.call_deinit = atmodem_call_exit,
	.ss_deinit = atmodem_ss_exit,
	.sms_deinit = atmodem_sms_exit,
	.phonebook_deinit = NULL,
	.gps_deinit = NULL,
};

static gboolean on_load()
{
	dbg("Load!!!");

	return TRUE;
}

static gboolean on_init(TcorePlugin *p)
{
	dbg("Init!!!");

	tcore_check_return_value(p != NULL, FALSE);

	/* Initialize Modules (Core Objects) */
	if (tcore_object_init_objects(p, &atmodem_init_table)
			!= TEL_RETURN_SUCCESS) {
		err("Failed to initialize Core Objects");
		return FALSE;
	}

	/* Power ON modem */
	(void)g_idle_add((GSourceFunc)atmodem_modem_power_on_modem, (gpointer)p);

	dbg("Init - Successful");
	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	dbg("Unload!!!");
	tcore_check_return(p != NULL);

	/* Deinitialize Modules (Core Objects) */
	tcore_object_deinit_objects(p, &atmodem_deinit_table);
}

struct tcore_plugin_define_desc plugin_define_desc = {
	.name = "atmodem",
	.priority = TCORE_PLUGIN_PRIORITY_MID,
	.version = 1,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
