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

#ifndef __ATMODEM_NETWORK_H__
#define __ATMODEM_NETWORK_H__

gboolean atmodem_network_init(TcorePlugin *p, CoreObject *co);
void atmodem_network_exit(TcorePlugin *p, CoreObject *co);

#endif	/* __ATMODEM_NETWORK_H__ */
