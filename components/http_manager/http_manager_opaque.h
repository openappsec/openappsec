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

#ifndef __HTTP_MANAGER_OPAQUE_H__
#define __HTTP_MANAGER_OPAQUE_H__

#include <unordered_map>

#include "buffer.h"
#include "table_opaque.h"
#include "nginx_attachment_common.h"

class HttpManagerOpaque : public TableOpaqueSerialize<HttpManagerOpaque>
{
public:
    HttpManagerOpaque();

    void setApplicationVerdict(const std::string &app_name, ngx_http_cp_verdict_e verdict);
    ngx_http_cp_verdict_e getApplicationsVerdict(const std::string &app_name) const;
    void setManagerVerdict(ngx_http_cp_verdict_e verdict) { manager_verdict = verdict; }
    ngx_http_cp_verdict_e getManagerVerdict() const { return manager_verdict; }
    ngx_http_cp_verdict_e getCurrVerdict() const;
    void saveCurrentDataToCache(const Buffer &full_data);
    void setUserDefinedValue(const std::string &value) { user_defined_value = value; }
    Maybe<std::string> getUserDefinedValue() const { return user_defined_value; }
    const Buffer & getPreviousDataCache() const { return prev_data_cache; }
    uint getAggeregatedPayloadSize() const { return aggregated_payload_size; }
    void updatePayloadSize(const uint curr_payload);
    void resetPayloadSize() { aggregated_payload_size = 0; }

// LCOV_EXCL_START - sync functions, can only be tested once the sync module exists
    template <typename T> void serialize(T &ar, uint) { ar(applications_verdicts, prev_data_cache); }
    static std::unique_ptr<TableOpaqueBase> prototype() { return std::make_unique<HttpManagerOpaque>(); }
// LCOV_EXCL_STOP

    static const std::string name() { return "HttpTransactionData"; }
    static uint currVer() { return 0; }
    static uint minVer() { return 0; }

private:
    std::unordered_map<std::string, ngx_http_cp_verdict_e> applications_verdicts;
    ngx_http_cp_verdict_e manager_verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
    Buffer prev_data_cache;
    uint aggregated_payload_size = 0;
    Maybe<std::string> user_defined_value = genError("uninitialized");
};

#endif // __HTTP_MANAGER_OPAQUE_H__
