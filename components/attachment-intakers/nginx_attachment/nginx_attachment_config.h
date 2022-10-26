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

#ifndef __NGINX_ATTACHMENT_CONFIG_H__
#define __NGINX_ATTACHMENT_CONFIG_H__

#include <string>
#include <vector>

#include "nginx_attachment_util.h"
#include "cereal/archives/json.hpp"

#include "generic_rulebase/triggers_config.h"
#include "http_configuration.h"

class HttpAttachmentConfig
{
public:
    void init();

    bool operator==(const HttpAttachmentConfig &other) const;

    void save(cereal::JSONOutputArchive &out_ar) const;

    unsigned int getDebugLevel() const { return conf_data.getNumericalValue("dbg_level"); }
    bool getIsFailOpenModeEnabled() const { return conf_data.getNumericalValue("is_fail_open_mode_enabled"); }

    bool
    getSessionsPerMinuteLimitVerdict() const
    {
        return conf_data.getNumericalValue("sessions_per_minute_limit_verdict");
    }

    unsigned int getMaxSessionsPerMinute() const { return conf_data.getNumericalValue("max_sessions_per_minute"); }
    unsigned int getNumOfNginxElements() const { return conf_data.getNumericalValue("num_of_nginx_ipc_elements"); }
    unsigned int getKeepAliveIntervalMsec() const { return conf_data.getNumericalValue("keep_alive_interval_msec"); }

private:
    void setGradualDeploymentIPs();

    void setWebTriggerConf();

    void setDebugLevel();

    void setFailOpenMode();

    void setFailOpenTimeout();

    void setFailOpenWaitMode();

    void setSessionsPerMinuteLimitVerdict();

    void setMaxSessionsPerMinute();

    void setNumOfNginxIpcElements();

    void setKeepAliveIntervalMsec();

    void setStaticResourcesPath();

    void setDebugByContextValues();

    WebTriggerConf web_trigger_conf;
    HttpAttachmentConfiguration conf_data;
};

#endif // __NGINX_ATTACHMENT_CONFIG_H__
