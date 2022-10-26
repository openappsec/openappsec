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

#include "nginx_attachment_util.h"

#include <arpa/inet.h>

#include "http_configuration.h"

using namespace std;

static HttpAttachmentConfiguration conf_data;

int
initAttachmentConfig(c_str conf_file)
{
    return conf_data.init(conf_file);
}

ngx_http_inspection_mode_e
getInspectionMode()
{
    return static_cast<ngx_http_inspection_mode_e>(conf_data.getNumericalValue("nginx_inspection_mode"));
}

unsigned int
getNumOfNginxIpcElements()
{
    return conf_data.getNumericalValue("num_of_nginx_ipc_elements");
}

unsigned int
getKeepAliveIntervalMsec()
{
    return conf_data.getNumericalValue("keep_alive_interval_msec");
}

unsigned int
getDbgLevel()
{
    return conf_data.getNumericalValue("dbg_level");
}

int
isDebugContext(c_str client, c_str server, unsigned int port, c_str method, c_str host , c_str uri)
{
    auto &ctx = conf_data.getDebugContext();
    return
        (ctx.client == "" || ctx.client == client) &&
        (ctx.server == "" || ctx.server == server) &&
        (ctx.port == 0 || ctx.port == port) &&
        (ctx.method == "" || ctx.method == method) &&
        (ctx.host == "" || ctx.host == host) &&
        (ctx.uri == "" || ctx.uri == uri);
}

c_str
getStaticResourcesPath()
{
    return conf_data.getStringValue("static_resources_path").c_str();
}

int
isFailOpenMode()
{
    return conf_data.getNumericalValue("is_fail_open_mode_enabled");
}

unsigned int
getFailOpenTimeout()
{
    return conf_data.getNumericalValue("fail_open_timeout");
}

int
isFailOpenHoldMode()
{
    return conf_data.getNumericalValue("is_fail_open_mode_hold_enabled");
}

unsigned int
getFailOpenHoldTimeout()
{
    return conf_data.getNumericalValue("fail_open_hold_timeout");
}

unsigned int
getMaxSessionsPerMinute()
{
    return conf_data.getNumericalValue("max_sessions_per_minute");
}

int
isFailOpenOnSessionLimit()
{
    return conf_data.getStringValue("sessions_per_minute_limit_verdict") == "Accept";
}

unsigned int
getRegistrationThreadTimeout()
{
    return conf_data.getNumericalValue("registration_thread_timeout_msec");
}

unsigned int
getReqProccessingTimeout()
{
    return conf_data.getNumericalValue("req_proccessing_timeout_msec");
}

unsigned int
getReqHeaderThreadTimeout()
{
    return conf_data.getNumericalValue("req_header_thread_timeout_msec");
}

unsigned int
getReqBodyThreadTimeout()
{
    return conf_data.getNumericalValue("req_body_thread_timeout_msec");
}

unsigned int
getResProccessingTimeout()
{
    return conf_data.getNumericalValue("res_proccessing_timeout_msec");
}

unsigned int
getResHeaderThreadTimeout()
{
    return conf_data.getNumericalValue("res_header_thread_timeout_msec");
}

unsigned int
getResBodyThreadTimeout()
{
    return conf_data.getNumericalValue("res_body_thread_timeout_msec");
}

unsigned int
getWaitingForVerdictThreadTimeout()
{
    return conf_data.getNumericalValue("waiting_for_verdict_thread_timeout_msec");
}

int
isIPAddress(c_str ip_str)
{
    int address_family = AF_INET;
    for (int i = 0; ip_str[i]; ++i) {
        if (ip_str[i] == ':') address_family = AF_INET6;
    }

    char placeholder[16];
    return inet_pton(address_family, ip_str, placeholder);
}

struct IpAddress
{
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } ip;
    bool is_ipv4;

    bool
    operator<(const IpAddress &other) const
    {
        if (is_ipv4 != other.is_ipv4) return is_ipv4 < other.is_ipv4;
        if (is_ipv4) return memcmp(&ip.ipv4, &other.ip.ipv4, sizeof(struct in_addr)) < 0;
        return memcmp(&ip.ipv6, &other.ip.ipv6, sizeof(struct in6_addr)) < 0;
    }

    bool
    operator<=(const IpAddress &other) const
    {
        return !(other < *this);
    }
};

static IpAddress
createIPAddress(c_str ip_str)
{
    IpAddress res;

    for (int i = 0; ip_str[i]; ++i) {
        if (ip_str[i] == ':') {
            res.is_ipv4 = false;
            inet_pton(AF_INET6, ip_str, &res.ip.ipv6);
            return res;
        }
    }

    res.is_ipv4 = true;
    inet_pton(AF_INET, ip_str, &res.ip.ipv4);
    return res;
}

static bool
isIPInRange(const IpAddress &ip, const IpAddress &start, const IpAddress &end)
{
    if (ip.is_ipv4 != start.is_ipv4 || ip.is_ipv4 != end.is_ipv4) return false;
    return start <= ip && ip <= end;
}

static bool
isIPInRange(const IpAddress &ip, const string &range)
{
    auto delimiter = range.find('-');

    if (delimiter == string::npos) {
        if (!isIPAddress(range.c_str())) return false;
        auto address = createIPAddress(range.c_str());
        return isIPInRange(ip, address, address);
    }

    auto start_str = range.substr(0, delimiter);
    if (!isIPAddress(start_str.c_str())) return false;
    auto start_addr = createIPAddress(start_str.c_str());

    auto end_str = range.substr(delimiter + 1);
    if (!isIPAddress(end_str.c_str())) return false;
    auto end_addr = createIPAddress(end_str.c_str());

    return isIPInRange(ip, start_addr, end_addr);
}

int
isSkipSource(c_str ip_str)
{
    if (!isIPAddress(ip_str)) return 0;
    auto ip = createIPAddress(ip_str);

    for (auto &range : conf_data.getExcludeSources()) {
        if (isIPInRange(ip, range)) return 1;
    }

    return 0;
}
