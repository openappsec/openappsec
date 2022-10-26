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

#include "http_configuration.h"

#include <fstream>

#include "cereal/types/vector.hpp"

#define DEFAULT_KEEP_ALIVE_INTERVAL_MSEC 30000

using namespace std;

void
DebugConfig::save(cereal::JSONOutputArchive &archive) const
{
    archive(
        cereal::make_nvp("clientIp", client),
        cereal::make_nvp("listeningIp", server),
        cereal::make_nvp("uriPrefix", uri),
        cereal::make_nvp("hostName", host),
        cereal::make_nvp("httpMethod", method),
        cereal::make_nvp("listeningPort", port)
    );
}

void
DebugConfig::load(cereal::JSONInputArchive &archive)
{
    try {
        archive(
            cereal::make_nvp("clientIp", client),
            cereal::make_nvp("listeningIp", server),
            cereal::make_nvp("uriPrefix", uri),
            cereal::make_nvp("hostName", host),
            cereal::make_nvp("httpMethod", method),
            cereal::make_nvp("listeningPort", port)
        );
    } catch (const cereal::Exception &) {
        client = "";
        server = "";
        uri = "";
        host = "";
        method = "";
        port = 0;
    }
}

bool
DebugConfig::operator==(const DebugConfig &another) const
{
    return
        client == another.client &&
        server == another.server &&
        port == another.port &&
        method == another.method &&
        host == another.host &&
        uri == another.uri;
}

int
HttpAttachmentConfiguration::init(const string &conf_file)
{
    try {
        ifstream file(conf_file);
        cereal::JSONInputArchive ar(file);
        load(ar);
        return 1;
    } catch (exception &e) {
        return 0;
    }
}

void
HttpAttachmentConfiguration::save(cereal::JSONOutputArchive &archive) const
{
    archive(
        cereal::make_nvp("context_values", dbg),
        cereal::make_nvp("ip_ranges", exclude_sources),
        cereal::make_nvp("dbg_level", getNumericalValue("dbg_level")),
        cereal::make_nvp("static_resources_path", getStringValue("static_resources_path")),
        cereal::make_nvp("is_fail_open_mode_enabled", getNumericalValue("is_fail_open_mode_enabled")),
        cereal::make_nvp("fail_open_timeout", getNumericalValue("fail_open_timeout")),
        cereal::make_nvp("is_fail_open_mode_hold_enabled", getNumericalValue("is_fail_open_mode_hold_enabled")),
        cereal::make_nvp("fail_open_hold_timeout", getNumericalValue("fail_open_hold_timeout")),
        cereal::make_nvp("sessions_per_minute_limit_verdict", getStringValue("sessions_per_minute_limit_verdict")),
        cereal::make_nvp("max_sessions_per_minute", getNumericalValue("max_sessions_per_minute")),
        cereal::make_nvp("res_proccessing_timeout_msec", getNumericalValue("res_proccessing_timeout_msec")),
        cereal::make_nvp("req_proccessing_timeout_msec", getNumericalValue("req_proccessing_timeout_msec")),
        cereal::make_nvp("registration_thread_timeout_msec", getNumericalValue("registration_thread_timeout_msec")),
        cereal::make_nvp("req_header_thread_timeout_msec", getNumericalValue("req_header_thread_timeout_msec")),
        cereal::make_nvp("req_body_thread_timeout_msec", getNumericalValue("req_body_thread_timeout_msec")),
        cereal::make_nvp("res_header_thread_timeout_msec", getNumericalValue("res_header_thread_timeout_msec")),
        cereal::make_nvp("res_body_thread_timeout_msec", getNumericalValue("res_body_thread_timeout_msec")),
        cereal::make_nvp(
            "waiting_for_verdict_thread_timeout_msec",
            getNumericalValue("waiting_for_verdict_thread_timeout_msec")
        ),
        cereal::make_nvp("nginx_inspection_mode", getNumericalValue("inspection_mode")),
        cereal::make_nvp("num_of_nginx_ipc_elements", getNumericalValue("num_of_nginx_ipc_elements")),
        cereal::make_nvp("keep_alive_interval_msec", getNumericalValue("keep_alive_interval_msec"))
    );
}

void
HttpAttachmentConfiguration::load(cereal::JSONInputArchive &archive)
{
    try {
        archive(cereal::make_nvp("context_values", dbg));
    } catch (const cereal::Exception &) {
        dbg = DebugConfig();
    }

    try {
        archive(cereal::make_nvp("ip_ranges", exclude_sources));
    } catch (const cereal::Exception &) {
        exclude_sources = {};
    }

    try {
        string str;
        archive(cereal::make_nvp("static_resources_path", str));
        string_values["static_resources_path"] = str;
    } catch (const cereal::Exception &) {
        string_values.erase("static_resources_path");
    }

    try {
        string str;
        archive(cereal::make_nvp("sessions_per_minute_limit_verdict", str));
        string_values["sessions_per_minute_limit_verdict"] = str;
    } catch (const cereal::Exception &) {
        string_values.erase("sessions_per_minute_limit_verdict");
    }

    loadNumericalValue(archive, "dbg_level", 0);
    loadNumericalValue(archive, "is_fail_open_mode_enabled", 0);
    loadNumericalValue(archive, "fail_open_timeout", 50);
    loadNumericalValue(archive, "is_fail_open_mode_hold_enabled", 0);
    loadNumericalValue(archive, "fail_open_hold_timeout", 200);
    loadNumericalValue(archive, "sessions_per_minute_limit_verdict", 0);
    loadNumericalValue(archive, "max_sessions_per_minute", 0);
    loadNumericalValue(archive, "res_proccessing_timeout_msec", 3000);
    loadNumericalValue(archive, "req_proccessing_timeout_msec", 3000);
    loadNumericalValue(archive, "registration_thread_timeout_msec", 100);
    loadNumericalValue(archive, "req_header_thread_timeout_msec", 100);
    loadNumericalValue(archive, "req_body_thread_timeout_msec", 150);
    loadNumericalValue(archive, "res_header_thread_timeout_msec", 100);
    loadNumericalValue(archive, "res_body_thread_timeout_msec", 150);
    loadNumericalValue(archive, "waiting_for_verdict_thread_timeout_msec", 150);
    loadNumericalValue(archive, "nginx_inspection_mode", 0);
    loadNumericalValue(archive, "num_of_nginx_ipc_elements", 200);
    loadNumericalValue(archive, "keep_alive_interval_msec", DEFAULT_KEEP_ALIVE_INTERVAL_MSEC);
}

bool
HttpAttachmentConfiguration::operator==(const HttpAttachmentConfiguration &other) const
{
    return
        dbg == other.dbg &&
        numerical_values == other.numerical_values &&
        string_values == other.string_values &&
        exclude_sources == other.exclude_sources;
}

unsigned int
HttpAttachmentConfiguration::getNumericalValue(const string &key) const
{
    auto elem = numerical_values.find(key);
    return elem != numerical_values.end() ? elem->second : 0;
}

const string &
HttpAttachmentConfiguration::getStringValue(const string &key) const
{
    auto elem = string_values.find(key);
    return elem != string_values.end() ? elem->second : empty;
}

void
HttpAttachmentConfiguration::loadNumericalValue(
    cereal::JSONInputArchive &ar,
    const string &name,
    unsigned int default_value
)
{
    try {
        unsigned int value;
        ar(cereal::make_nvp(name, value));
        numerical_values[name] = value;
    } catch (const cereal::Exception &) {
        numerical_values[name] = default_value;
    }
}
