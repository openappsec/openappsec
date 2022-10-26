// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __FOG_REST_ERROR_H__
#define __FOG_REST_ERROR_H__

#include <string>

#include "rest.h"

class FogRestError : public ClientRest
{
public:
    S2C_LABEL_PARAM(string, message_id,   "messageId");
    S2C_LABEL_PARAM(string, message,      "message");
    S2C_LABEL_PARAM(string, reference_id, "referenceId");
    S2C_LABEL_PARAM(string, severity,     "severity");
};

#endif // __FOG_REST_ERROR_H__
