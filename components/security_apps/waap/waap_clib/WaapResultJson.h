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

#pragma once
#include "Waf2Engine.h"
#include "WaapAssetState.h"
#include <string>

std::string buildWaapResultJson(Waf2ScanResult *m_scanResult, const Waf2Transaction &t, bool bSendResponse,
    const std::string &normalizedUri, const std::string &uri, bool bForceBlock,
    bool bForceException);
