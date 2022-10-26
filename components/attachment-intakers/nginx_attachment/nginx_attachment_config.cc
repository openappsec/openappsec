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

#include "nginx_attachment_config.h"

#include <stdlib.h>

#include "nginx_attachment.h"
#include "config.h"
#include "singleton.h"
#include "i_gradual_deployment.h"
#include "debug.h"

USE_DEBUG_FLAG(D_NGINX_ATTACHMENT);

using namespace std;

using DebugLevel = ngx_http_cp_debug_level_e;

void
HttpAttachmentConfig::init()
{
    setDebugLevel();
    setGradualDeploymentIPs();
    setWebTriggerConf();
    setStaticResourcesPath();
    setFailOpenMode();
    setFailOpenTimeout();
    setFailOpenWaitMode();
    setSessionsPerMinuteLimitVerdict();
    setMaxSessionsPerMinute();
    setNumOfNginxIpcElements();
    setDebugByContextValues();
    setKeepAliveIntervalMsec();
}

bool
HttpAttachmentConfig::operator==(const HttpAttachmentConfig &other) const
{
    return
        web_trigger_conf == other.web_trigger_conf &&
        conf_data == other.conf_data;
}

void
HttpAttachmentConfig::save(cereal::JSONOutputArchive &out_ar) const
{
    conf_data.save(out_ar);
}

template <typename Conf, typename ...Strings>
static Conf
getAttachmentConf(const Conf &default_val, const string &profile_conf, const Strings & ...conf)
{
    const Conf &profile_settings = getProfileAgentSettingWithDefault<Conf>(default_val, profile_conf);
    return getConfigurationWithDefault<Conf>(profile_settings, conf...);
}

void
HttpAttachmentConfig::setGradualDeploymentIPs()
{
    auto i_gradual_deployment = Singleton::Consume<I_GradualDeployment>::by<NginxAttachment>();
    conf_data.setExcludeSources(i_gradual_deployment->getPolicy(I_GradualDeployment::AttachmentType::NGINX));
}

void
HttpAttachmentConfig::setWebTriggerConf()
{
    web_trigger_conf = getConfigurationWithDefault<WebTriggerConf>(
        WebTriggerConf::default_trigger_conf,
        "HTTP manager",
        "Web trigger conf"
    );
}

void
HttpAttachmentConfig::setDebugLevel() {
    string debug_level = getAttachmentConf<string>(
        "info",
        "agent.debug.flag.nginxModule",
        "HTTP manager",
        "Attachment debug level"
    );

    debug_level[0] = toupper(debug_level[0]);

    if (debug_level == "Trace") {
        conf_data.setNumericalValue("dbg_level", (unsigned int)DebugLevel::DBG_LEVEL_TRACE);
    } else if (debug_level == "Debug") {
        conf_data.setNumericalValue("dbg_level", (unsigned int)DebugLevel::DBG_LEVEL_DEBUG);
    } else if (debug_level == "Info") {
        conf_data.setNumericalValue("dbg_level", (unsigned int)DebugLevel::DBG_LEVEL_INFO);
    } else if (debug_level == "Warning") {
        conf_data.setNumericalValue("dbg_level", (unsigned int)DebugLevel::DBG_LEVEL_WARNING);
    } else if (debug_level == "Error") {
        conf_data.setNumericalValue("dbg_level", (unsigned int)DebugLevel::DBG_LEVEL_ERROR);
    } else {
        dbgWarning(D_NGINX_ATTACHMENT)
            << "Debug level \""
            << debug_level
            << "\" is not valid. using default level \"warning\"";
        conf_data.setNumericalValue("dbg_level", (unsigned int)DebugLevel::DBG_LEVEL_INFO);
    }
}

void
HttpAttachmentConfig::setFailOpenMode()
{
    bool is_fail_open_mode_enabled = getAttachmentConf<bool>(
        true,
        "agent.failOpenState.nginxModule",
        "HTTP manager",
        "Fail Open Mode state"
    );

    dbgTrace(D_NGINX_ATTACHMENT)
        << "Attachment failure mode is: "
        << (is_fail_open_mode_enabled ? "Enabled" : "Disabled");
    conf_data.setNumericalValue("is_fail_open_mode_enabled", is_fail_open_mode_enabled);
}

void
HttpAttachmentConfig::setFailOpenTimeout()
{
    conf_data.setNumericalValue("fail_open_timeout", getAttachmentConf<uint>(
        50,
        "agent.failOpenTimeout.nginxModule",
        "HTTP manager",
        "Fail Open timeout msec"
    ));

    conf_data.setNumericalValue("fail_open_hold_timeout", getAttachmentConf<uint>(
        150,
        "agent.failOpenWaitTimeout.nginxModule",
        "HTTP manager",
        "Fail Open wait timeout msec"
    ));

    conf_data.setNumericalValue("res_proccessing_timeout_msec", getAttachmentConf<uint>(
        3000,
        "agent.resProccessingTimeout.nginxModule",
        "HTTP manager",
        "NGINX response processing timeout msec"
    ));

    conf_data.setNumericalValue("req_proccessing_timeout_msec", getAttachmentConf<uint>(
        3000,
        "agent.reqProccessingTimeout.nginxModule",
        "HTTP manager",
        "NGINX request processing timeout msec"
    ));

    conf_data.setNumericalValue("registration_thread_timeout_msec", getAttachmentConf<uint>(
        100,
        "agent.registrationThreadTimeout.nginxModule",
        "HTTP manager",
        "NGINX registration thread timeout msec"
    ));

    conf_data.setNumericalValue("req_header_thread_timeout_msec", getAttachmentConf<uint>(
        100,
        "agent.reqHeaderThreadTimeout.nginxModule",
        "HTTP manager",
        "NGINX request header thread timeout msec"
    ));

    conf_data.setNumericalValue("req_body_thread_timeout_msec", getAttachmentConf<uint>(
        150,
        "agent.reqBodyThreadTimeout.nginxModule",
        "HTTP manager",
        "NGINX request body thread timeout msec"
    ));

    conf_data.setNumericalValue("res_header_thread_timeout_msec", getAttachmentConf<uint>(
        100,
        "agent.resHeaderThreadTimeout.nginxModule",
        "HTTP manager",
        "NGINX response header thread timeout msec"
    ));

    conf_data.setNumericalValue("res_body_thread_timeout_msec", getAttachmentConf<uint>(
        150,
        "agent.resBodyThreadTimeout.nginxModule",
        "HTTP manager",
        "NGINX response body thread timeout msec"
    ));

    conf_data.setNumericalValue("waiting_for_verdict_thread_timeout_msec", getAttachmentConf<uint>(
        150,
        "agent.waitThreadTimeout.nginxModule",
        "HTTP manager",
        "NGINX wait thread timeout msec"
    ));

    uint inspection_mode = getAttachmentConf<uint>(
        static_cast<uint>(ngx_http_inspection_mode_e::NON_BLOCKING_THREAD),
        "agent.inspectionMode.nginxModule",
        "HTTP manager",
        "NGINX inspection mode"
    );

    if (inspection_mode >= ngx_http_inspection_mode_e::INSPECTION_MODE_COUNT) {
        inspection_mode = ngx_http_inspection_mode_e::NON_BLOCKING_THREAD;
    }
    conf_data.setNumericalValue("nginx_inspection_mode", inspection_mode);
}

void
HttpAttachmentConfig::setFailOpenWaitMode()
{
    bool is_fail_open_mode_hold_enabled = getAttachmentConf<bool>(
        true,
        "agent.failOpenWaitState.nginxModule",
        "HTTP manager",
        "Fail Open Mode state"
    );

    dbgTrace(D_NGINX_ATTACHMENT)
        << "Attachment waiting failure mode is: "
        << (is_fail_open_mode_hold_enabled ? "Enabled" : "Disabled");
    conf_data.setNumericalValue("is_fail_open_mode_hold_enabled", is_fail_open_mode_hold_enabled);
}

void
HttpAttachmentConfig::setSessionsPerMinuteLimitVerdict()
{
    string sessions_per_minute_limit_verdict = getAttachmentConf<string>(
        "Accept",
        "agent.sessionsPerMinuteLimitVerdict.nginxModule",
        "HTTP manager",
        "Sessions Per Minute Limit Verdict"
    );

    dbgTrace(D_NGINX_ATTACHMENT)
        << "Attachment sessions per minute limit verdict is: "
        << sessions_per_minute_limit_verdict;

    conf_data.setStringValue("sessions_per_minute_limit_verdict", sessions_per_minute_limit_verdict);
}

void
HttpAttachmentConfig::setMaxSessionsPerMinute()
{
    uint max_sessions_per_minute = getAttachmentConf<uint>(
        0,
        "agent.maxSessionsPerMinute.nginxModule",
        "HTTP manager",
        "Max Sessions Per Minute"
    );

    dbgTrace(D_NGINX_ATTACHMENT)
        << "Attachment max sessions per minute is: "
        << max_sessions_per_minute;

    conf_data.setNumericalValue("max_sessions_per_minute", max_sessions_per_minute);
}

void
HttpAttachmentConfig::setNumOfNginxIpcElements()
{
    uint num_of_nginx_ipc_elements = getProfileAgentSettingWithDefault<uint>(
        NUM_OF_NGINX_IPC_ELEMENTS, "nginxAttachment.numOfNginxIpcElements"
    );
    dbgTrace(D_NGINX_ATTACHMENT)
        << "Number of NGINX IPC elements: "
        << num_of_nginx_ipc_elements;
    conf_data.setNumericalValue("num_of_nginx_ipc_elements", num_of_nginx_ipc_elements);
}

void
HttpAttachmentConfig::setKeepAliveIntervalMsec()
{
    uint keep_alive_interval_msec = getProfileAgentSettingWithDefault<uint>(
        300, "attachmentRegistrator.expirationCheckSeconds"
    );
    keep_alive_interval_msec = (keep_alive_interval_msec * 1000) / 2;
    dbgDebug(D_NGINX_ATTACHMENT)
        << "Interval keeps alives size: "
        << keep_alive_interval_msec << " msec";
    conf_data.setNumericalValue("keep_alive_interval_msec", keep_alive_interval_msec);
}

void
HttpAttachmentConfig::setStaticResourcesPath()
{
    string static_resources_path = getConfigurationWithDefault<string>(
        DEFAULT_STATIC_RESOURCES_PATH,
        "HTTP manager",
        "Static resources path"
    );
    dbgDebug(D_NGINX_ATTACHMENT) << "Static resources path is : " << static_resources_path;
    conf_data.setStringValue("static_resources_path", static_resources_path);
}

void
HttpAttachmentConfig::setDebugByContextValues()
{
    DebugConfig new_ctx_cfg;
    auto maybe_ctx_config = getSetting<DebugConfig>("HTTP manager", "debug context");
    if(!maybe_ctx_config.ok()) {
        dbgDebug(D_NGINX_ATTACHMENT) << "Failed to set context values. Setting default values";
        conf_data.setDebugContext(new_ctx_cfg);
        return;
    }
    new_ctx_cfg = maybe_ctx_config.unpack();
    conf_data.setDebugContext(new_ctx_cfg);
    dbgDebug(D_NGINX_ATTACHMENT)
        << "Setting context values : "
        << "client_ip: "
        << new_ctx_cfg.client
        << ", listening_ip: "
        << new_ctx_cfg.server
        << ", uri_prefix: "
        << new_ctx_cfg.uri
        << ", hostname: "
        << new_ctx_cfg.host
        << ", http_method: "
        << new_ctx_cfg.method
        << ", listening_port: "
        << new_ctx_cfg.port;
}
