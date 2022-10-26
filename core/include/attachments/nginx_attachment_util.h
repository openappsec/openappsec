// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __NGINX_ATTACHMENT_UTIL__
#define __NGINX_ATTACHMENT_UTIL__

#include <stdio.h>

#include "nginx_attachment_common.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define IP_STR_MAX_LEN 40

typedef const char * c_str;

int initAttachmentConfig(c_str conf_file);

ngx_http_inspection_mode_e getInspectionMode();
unsigned int getNumOfNginxIpcElements();
unsigned int getKeepAliveIntervalMsec();
unsigned int getDbgLevel();
int isDebugContext(c_str client, c_str server, unsigned int port, c_str method, c_str host, c_str uri);
c_str getStaticResourcesPath();

int isFailOpenMode();
unsigned int getFailOpenTimeout();

int isFailOpenHoldMode();
unsigned int getFailOpenHoldTimeout();

unsigned int getMaxSessionsPerMinute();
int isFailOpenOnSessionLimit();

unsigned int getRegistrationThreadTimeout();

unsigned int getReqProccessingTimeout();
unsigned int getReqHeaderThreadTimeout();
unsigned int getReqBodyThreadTimeout();

unsigned int getResProccessingTimeout();
unsigned int getResHeaderThreadTimeout();
unsigned int getResBodyThreadTimeout();

unsigned int getWaitingForVerdictThreadTimeout();

int isIPAddress(c_str ip_str);
int isSkipSource(c_str ip_str);

#ifdef __cplusplus
}
#endif

#endif // __NGINX_ATTACHMENT_UTIL__
