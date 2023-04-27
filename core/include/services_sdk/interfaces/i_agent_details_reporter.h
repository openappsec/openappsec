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

#ifndef __I_AGENT_DETAILS_REPORTER_H__
#define __I_AGENT_DETAILS_REPORTER_H__

#include "cereal/archives/json.hpp"
#include <string>
#include <map>

#include "maybe_res.h"

class metaDataReport
{
public:
    metaDataReport() = default;
    metaDataReport(const metaDataReport &) = default;

    metaDataReport & operator<<(const std::pair<std::string, std::string> &data);
    bool operator==(const metaDataReport &other) const;
    void serialize(cereal::JSONOutputArchive &out_ar) const;

private:
    std::map<std::string, std::string> agent_details;
};

class I_AgentDetailsReporter
{
public:
    virtual void sendReport(
        const metaDataReport &agent_details,
        const Maybe<std::string> &policy_version,
        const Maybe<std::string> &platform,
        const Maybe<std::string> &architecture,
        const Maybe<std::string> &agent_version) = 0;

    virtual bool addAttr(const std::string &key, const std::string &val, bool allow_override = false) = 0;
    virtual bool addAttr(const std::map<std::string, std::string> &attr, bool allow_override = false) = 0;
    virtual void deleteAttr(const std::string &key) = 0;
    virtual bool sendAttributes() = 0;

protected:
    ~I_AgentDetailsReporter() = default;
};

#endif // __I_AGENT_DETAILS_REPORTER_H__
