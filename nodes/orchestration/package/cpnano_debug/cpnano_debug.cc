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

#include <iostream>
#include <fstream>
#include <set>
#include <vector>
#include <map>
#include <algorithm>
#include <arpa/inet.h>
#include <functional>

#include "common.h"
#include "customized_cereal_map.h"
#include "enum_range.h"

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"

using namespace std;

static set<string> us_debug_flags = {
    "D_ALL",
#define DEFINE_FLAG(flag_name, parent_name) #flag_name,
#include "debug_flags.h"
#undef DEFINE_FLAG
};

static set<string> kernel_debug_flags = {
    "ALL",
#define DEFINE_KDEBUG_FLAG(flag_name) #flag_name,
#include "kdebug_flags.h"
#undef DEFINE_KDEBUG_FLAG
};

static set<string> debug_levels = { "Trace", "Debug", "Warning", "Info", "Error", "None" };
enum class DebugLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    None
};

static DebugLevel max_debug_level = DebugLevel::None;

static const vector<string> kernel_flags_in_user_space = {"D_MESSAGE_READER", "D_KERNEL_MESSAGE_READER"};

static const string section = "|--";
static const string vertical = "|  ";
static const string indent = "   ";

static const int error_exit_code = -1;
static const int ok_exit_code = 0;
static const int reload_settings_exit_code = 1;

enum class CliCommand { NONE, SHOW, SET, DELETE, ADD, DEFAULT, COUNT };

enum class Service {
    ORCHESTRATION,
    ACCESS_CONTROL,
    HTTP_MANAGER,
    REVERSE_PROXY_MANAGER,
    CAPSULE8,
    SDWAN,
    LOGGER_SDWAN,
    IOT_ENFORCE,
    IOT_DOCTOR,
    IOT_RISK,
    IOT_GW_SENSOR,
    IOT_SNMP,
    IOT_MS_DHCP,
    IOT_UNIX_DHCP,
    IOT_SYSLOG_DHCP,
    IOT_INFOBLOX_DHCP,
    IOT_CISCO_ISE,
    IOT_WLP,
    ATTACHMENT_REGISTRATOR,
    CPVIEW_METRIC_PROVIDER,
    HTTP_TRANSACTION_HANDLER,
    DEDICATED_NETWORK_HANDLER,
    HELLO_WORLD,
    IDA,
    IOT_ACCESS_CONTROL,
    HORIZON_TELEMETRY,

    COUNT
};

static bool
validateIpAddress(const string &ip_str)
{
    if (ip_str == "any" || ip_str == "" || ip_str == "*") return true;

    if (ip_str.find(':') == string::npos) {
        struct in_addr v4;
        if(inet_pton(AF_INET, ip_str.c_str(), &v4)!=0){
            return true;
        }
    } else {
        struct in6_addr v6;
        if(inet_pton(AF_INET6, ip_str.c_str(), &v6)!=0){
            return true;
        }
    }
    cout << "Received illegal IP address: " << ip_str << endl;
    return false;
}

static bool
validateNumericValue(const string &num_str)
{
    try {
        stoi(num_str);
        return true;
    } catch (const exception &e) {
        cout << "Failed to validate numeric value. Error: " << e.what() << endl;
        return false;
    }
}

static bool
validateGeneralString(const string &num_str)
{
    if (num_str.length() == 0) {
        cout << "Failed to validate string. Error: empty string" <<  endl;
        return false;
    }
    return true;
}

static string
getServiceString(const Service service)
{
    switch (service) {
        case (Service::ORCHESTRATION): return "orchestration";
        case (Service::ACCESS_CONTROL): return "access-control";
        case (Service::HTTP_MANAGER): return "http-manager";
        case (Service::HTTP_TRANSACTION_HANDLER): return "http-transaction-handler";
        case (Service::REVERSE_PROXY_MANAGER): return "reverse-proxy-manager";
        case (Service::CAPSULE8): return "capsule8";
        case (Service::IOT_ENFORCE): return "iot-enforce";
        case (Service::IOT_DOCTOR): return "iot-doctor";
        case (Service::IOT_RISK): return "iot-risk";
        case (Service::IOT_GW_SENSOR): return "iot-gw-sensor";
        case (Service::IOT_SNMP): return "iot-snmp";
        case (Service::IOT_MS_DHCP): return "iot-ms-dhcp";
        case (Service::IOT_UNIX_DHCP): return "iot-unix-dhcp";
        case (Service::IOT_SYSLOG_DHCP): return "iot-syslog-dhcp";
        case (Service::IOT_INFOBLOX_DHCP): return "iot-infoblox-dhcp";
        case (Service::IOT_CISCO_ISE): return "iot-cisco-ise";
        case (Service::ATTACHMENT_REGISTRATOR): return "attachment-registrator";
        case (Service::CPVIEW_METRIC_PROVIDER): return "cpview-metric-provider";
        case (Service::DEDICATED_NETWORK_HANDLER): return "dedicated-network-handler";
        case (Service::SDWAN): return "sdwan";
        case (Service::LOGGER_SDWAN): return "logger-sdwan";
        case (Service::IOT_WLP): return "workload-protection";
        case (Service::HELLO_WORLD): return "hello-world";
        case (Service::IDA): return "identity-awareness";
        case (Service::IOT_ACCESS_CONTROL): return "iot-access-control";
        case (Service::HORIZON_TELEMETRY): return "horizon-telemetry";
        default:
            cerr
                << "Internal Error: the provided service ("
                << static_cast<int>(service)
                << ") has no string representation"
                << endl;
            exit(error_exit_code);
    }
    return "";
}

static string
getDebugLevelString(const DebugLevel level)
{
    if (level == DebugLevel::Trace) return "Trace";
    if (level == DebugLevel::Debug) return "Debug";
    if (level == DebugLevel::Info) return "Info";
    if (level == DebugLevel::Warning) return "Warning";
    if (level == DebugLevel::Error) return "Error";
    if (level == DebugLevel::None) return "None";
    cerr
        << "Internal Error: the provided debug level ("
        << static_cast<int>(level)
        << ") has no string representation"
        << endl;
    exit(error_exit_code);
    return "";
}

DebugLevel
getDebugLevel(const string &level)
{
    if (level.compare("Trace") == 0) return DebugLevel::Trace;
    if (level.compare("Debug") == 0) return DebugLevel::Debug;
    if (level.compare("Info") == 0) return DebugLevel::Info;
    if (level.compare("Warning") == 0) return DebugLevel::Warning;
    if (level.compare("Error") == 0) return DebugLevel::Error;
    if (level.compare("None") == 0) return DebugLevel::None;
    cerr << "Internal Error: unknown debug level (" << level << ")" << endl;
    exit(error_exit_code);
    return DebugLevel::None;
}

using ServiceConfig = pair<string, string>;
static string filesystem_path = "/etc/cp";
static string log_files_path = "/var/log";

void
updatePaths()
{
    filesystem_path = getenv("CP_ENV_FILESYSTEM") ? getenv("CP_ENV_FILESYSTEM") : "/etc/cp";
    log_files_path = getenv("CP_ENV_LOG_FILE") ? getenv("CP_ENV_LOG_FILE") : "/var/log";
}

ServiceConfig
getServiceConfig (const Service service)
{
    switch (service) {
        case (Service::ORCHESTRATION):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-orchestration-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-orchestration.dbg"
            );
        case (Service::ACCESS_CONTROL):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-access-control-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-access-control.dbg"
            );
        case (Service::HTTP_MANAGER):
            return ServiceConfig(
                filesystem_path + "/cp-nano-http-manager-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-http-manager.dbg"
            );
        case (Service::HTTP_TRANSACTION_HANDLER):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-http-transaction-handler-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-http-transaction-handler.dbg"
            );
        case (Service::REVERSE_PROXY_MANAGER):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-reverse-proxy-manager-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-reverse-proxy-manager.dbg"
            );
        case (Service::CAPSULE8):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-capsule8-debug-conf.json",
                log_files_path + "/nano_agent/capsule8-checkpoint.dbg"
            );
        case (Service::IOT_ENFORCE):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-enforce-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-enforce.dbg"
            );
        case (Service::IOT_DOCTOR):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-doctor-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-doctor.dbg"
            );
        case (Service::IOT_RISK):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-risk-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-risk.dbg"
            );
        case (Service::IOT_GW_SENSOR):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-gw-sensor-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-gw-sensor.dbg"
            );
        case (Service::IOT_SNMP):
            return  ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-snmp-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-snmp.dbg"
            );
        case (Service::IOT_MS_DHCP):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-ms-dhcp-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-ms-dhcp.dbg"
            );
        case (Service::IOT_UNIX_DHCP):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-unix-dhcp-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-unix-dhcp.dbg"
            );
        case (Service::IOT_SYSLOG_DHCP):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-syslog-dhcp-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-syslog-dhcp.dbg"
            );
        case (Service::IOT_INFOBLOX_DHCP):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-infoblox-dhcp-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-infoblox-dhcp.dbg"
            );
        case (Service::IOT_CISCO_ISE):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-cisco-ise-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-cisco-ise.dbg"
            );
        case (Service::ATTACHMENT_REGISTRATOR):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-attachment-registrator-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-attachment-registrator.dbg"
            );
        case (Service::DEDICATED_NETWORK_HANDLER):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-dedicated-network-handler-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-dedicated-network-handler.dbg"
            );
        case (Service::SDWAN):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-sdwan-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-sdwan.dbg"
            );
        case (Service::LOGGER_SDWAN):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-logger-sdwan-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-logger-sdwan.dbg"
            );
        case (Service::IOT_WLP):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-workload-protection-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-workload-protection.dbg"
            );
        case (Service::CPVIEW_METRIC_PROVIDER):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-cpview-metric-provider-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-cpview-metric-provider.dbg"
            );
        case (Service::IDA):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-ida-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-ida.dbg"
            );
        case (Service::HELLO_WORLD):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-hello-world-conf.json",
                log_files_path + "/nano_agent/cp-nano-hello-world.dbg"
            );
        case (Service::IOT_ACCESS_CONTROL):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-iot-access-control-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-iot-access-control.dbg"
            );
        case (Service::HORIZON_TELEMETRY):
            return ServiceConfig(
                filesystem_path + "/conf/cp-nano-horizon-telemetry-debug-conf.json",
                log_files_path + "/nano_agent/cp-nano-horizon-telemetry.dbg"
            );
        default:
            cerr
                << "Internal Error: the provided service ("
                << static_cast<int>(service)
                << ") has no service config"
                << endl;
            exit(error_exit_code);
    }
    return ServiceConfig("", "");
}

void
sortMultimap(multimap<string, string> &unordered_map)
{
    vector<pair<string, string>> temp;
    temp.insert(temp.begin(), unordered_map.begin(), unordered_map.end());
    sort(temp.begin(), temp.end());
    unordered_map.clear();
    unordered_map.insert(temp.cbegin(), temp.cend());
}

static map<string, function<bool(string&)>> context_evaluators = {
    {"sourceIp", validateIpAddress},
    {"sourcePort", validateNumericValue},
    {"destinationIp", validateIpAddress},
    {"destinationPort", validateNumericValue},
    {"uriPrefix", validateGeneralString},
    {"httpMethod", validateGeneralString},
    {"hostName", validateGeneralString},
    {"protocol", validateNumericValue}
};

class Context
{
public:
    Context() = default;

    Context(Service _service) : ctx_values({}), context_as_str("()"), service(_service) {}

    void
    init()
    {
        for (auto ctx_eval_pair : context_evaluators) {
            ctx_values[ctx_eval_pair.first] = "";
        }
        ctx_values["sourcePort"] = "0";
        ctx_values["destinationPort"] = "0";
        ctx_values["protocol"] = "0";
    }

    void
    save(cereal::JSONOutputArchive &archive) const
    {
        try {
            switch(service) {
                case (Service::ACCESS_CONTROL): {

                    archive(
                        cereal::make_nvp("srcIp", ctx_values.at("sourceIp")),
                        cereal::make_nvp("destIp", ctx_values.at("destinationIp")),
                        cereal::make_nvp("protocol", stoi(ctx_values.at("protocol"))),
                        cereal::make_nvp("srcPort", stoi(ctx_values.at("sourcePort"))),
                        cereal::make_nvp("destPort", stoi(ctx_values.at("destinationPort")))
                    );
                    break;
                }
                case (Service::HTTP_MANAGER):
                case (Service::HTTP_TRANSACTION_HANDLER): {
                    int port = stoi(ctx_values.at("destinationPort"));
                    archive(
                        cereal::make_nvp("clientIp", ctx_values.at("sourceIp")),
                        cereal::make_nvp("listeningIp", ctx_values.at("destinationIp")),
                        cereal::make_nvp("listeningPort", port),
                        cereal::make_nvp("uriPrefix", ctx_values.at("uriPrefix")),
                        cereal::make_nvp("httpMethod", ctx_values.at("httpMethod")),
                        cereal::make_nvp("hostName", ctx_values.at("hostName"))
                    );
                    break;
                }
                default: {
                    archive(cereal::make_nvp("context", context_as_str));
                }
            }
        } catch (...) {
            archive.setNextName(nullptr);
        }
    }

    void
    load(cereal::JSONInputArchive &archive)
    {
        try {
            switch(service) {
                case (Service::ACCESS_CONTROL): {
                    int proto, dport, sport;
                    archive(
                        cereal::make_nvp("srcIp", ctx_values["sourceIp"]),
                        cereal::make_nvp("destIp", ctx_values["destinationIp"]),
                        cereal::make_nvp("protocol", proto),
                        cereal::make_nvp("srcPort", sport),
                        cereal::make_nvp("destPort", dport)
                    );
                    ctx_values["protocol"] = to_string(proto);
                    ctx_values["sourcePort"] = to_string(sport);
                    ctx_values["destinationPort"] = to_string(dport);
                    break;
                }
                case (Service::HTTP_MANAGER):
                case (Service::HTTP_TRANSACTION_HANDLER): {
                    int port;
                    archive(
                        cereal::make_nvp("clientIp", ctx_values["sourceIp"]),
                        cereal::make_nvp("listeningIp", ctx_values["destinationIp"]),
                        cereal::make_nvp("listeningPort", port),
                        cereal::make_nvp("uriPrefix", ctx_values["uriPrefix"]),
                        cereal::make_nvp("httpMethod", ctx_values["httpMethod"]),
                        cereal::make_nvp("hostName", ctx_values["hostName"])
                    );
                    ctx_values["destinationPort"] = to_string(port);
                    break;
                }
                default: {
                    archive(cereal::make_nvp("context", context_as_str));
                }
            }
        } catch (...) {
            archive.setNextName(nullptr);
        }
    }

    void addContext(string &ctx_key, string &ctx_val)
    {
        if (context_evaluators.find(ctx_key) == context_evaluators.end()) {
            cout << "Failed to add context. The key is not supported. Key: " << ctx_key << endl;
            return;
        }
        if (!context_evaluators[ctx_key](ctx_val)) {
            cout << "Failed to add context. The value is not supported. Value: " << ctx_val << endl;
            return;
        }
        ctx_values[ctx_key] = ctx_val;
    }
    string getString() const { return "()"; }

private:
    map<string, string> ctx_values;
    string context_as_str;
    Service service;
};

string operator+( const string &str, const Context &ctx) { return str + ctx.getString(); }

class HttpHandlerContext {
public:
    HttpHandlerContext() : context(Context(Service::HTTP_TRANSACTION_HANDLER)) {}

    void init() { context.init(); }

    void addContext(string &ctx_key, string &ctx_val) { context.addContext(ctx_key, ctx_val); }

    void
    save(cereal::JSONOutputArchive &archive) const
    {
        try {
            archive(cereal::make_nvp("debug context", context));
        } catch (...) {
        }
    }

    void
    load(cereal::JSONInputArchive &archive)
    {
        try {
            archive(cereal::make_nvp("debug context", context));
        } catch (...) {
        }
    }

private:
    Context context;
};

class DebugStreamConf
{
public:
    DebugStreamConf() {}

    DebugStreamConf(const string &output)
    {
        if (output != "FOG" && output != "STDOUT" && output.front() != '/') {
            streams["Output"] = log_files_path + "/" + output;
        } else {
            streams["Output"] = output;
        }
    }

    DebugStreamConf(const string &output, const map<string, string> &new_flags) : streams(new_flags)
    {
        if (output != "FOG" && output != "STDOUT" && output.front() != '/') {
            streams["Output"] = log_files_path + "/" + output;
        } else {
            streams["Output"] = output;
        }
    }

    void
    save(cereal::JSONOutputArchive &ar) const
    {
        for (const auto &pair : streams) {
            ar(cereal::make_nvp(pair.first, pair.second));
        }
    }

    void
    load(cereal::JSONInputArchive &ar)
    {
        try {
            cereal::load(ar, streams);
            if (streams["Output"].empty()) streams["Output"] = "STDOUT";
            if (streams["Output"] != "FOG" && streams["Output"] != "STDOUT" && streams["Output"].front() != '/') {
                streams["Output"] = log_files_path + "/" + streams["Output"];
            }
        } catch (exception &e) {
            cerr
                << "Error while parsing intelligence date file '"
                << "': "
                << e.what();
        }
    }

    map<string, string> streams;
};

class DebugConf {
public:
    DebugConf() {}

    void
    save(cereal::JSONOutputArchive &ar) const {
        ar(cereal::make_nvp("Streams", streams));
        try {
            cereal::make_nvp("Context", context);
        } catch (...) {
        }
    }

    void
    load(cereal::JSONInputArchive &ar)
    {
        ar(cereal::make_nvp("Streams", streams));
        try {
            cereal::make_nvp("Context", context);
        } catch (...) {
        }
    }

    void
    addDebug(const string &output, const string &default_output_stream, const map<string, string> &new_flags)
    {
        if (output == "") {
            if (streams.size() == 0) streams.push_back(DebugStreamConf(default_output_stream));

            for (DebugStreamConf &stream : streams) {
                for (const auto &flag : new_flags) {
                    stream.streams[flag.first] = flag.second;
                }
            }

            return;
        }

        bool does_stream_exist = false;
        for (DebugStreamConf &stream : streams) {
            if (stream.streams["Output"] != output) continue;

            does_stream_exist = true;
            for (const auto &flag : new_flags) {
                stream.streams[flag.first] = flag.second;
            }
        }
        if (!does_stream_exist) {
            streams.push_back(DebugStreamConf(output, new_flags));
        }
    }

    void
    removeDebug(const string &output, const vector<string> &flags)
    {
        if (output == "") {
            for (DebugStreamConf &stream : streams) {
                for (const string &flag : flags) {
                    stream.streams.erase(flag);
                }
            }
            return;
        }

        for (DebugStreamConf &stream : streams) {
            if (stream.streams["Output"] != output) continue;

            for (const string &flag : flags) {
                stream.streams.erase(flag);
            }
        }
    }

    void
    deleteStreams(const string &curr_output_stream)
    {
        if (streams.size() == 0) return;

        if (curr_output_stream == "") {
            streams.clear();
            return;
        }

        for (auto iterator = streams.begin(); iterator < streams.end(); iterator++) {
            if (iterator->streams["Output"] != curr_output_stream) continue;

            streams.erase(iterator);
            return;
        }
    }

    multimap<string, string>
    mapDebugConf(const string &service_name) const
    {
        multimap<string, string> debug_map;
        for (const DebugStreamConf &stream : streams) {
            string output_stream = stream.streams.find("Output")->second;
            if (output_stream.empty()) continue;

            output_stream = "Output: " + output_stream;
            debug_map.insert({ "context: " + context, output_stream });
            for (const auto &flag : stream.streams) {
                if (flag.first == "Output") continue;
                debug_map.insert({ output_stream, flag.first + " = " + flag.second });
            }
        }
        if (debug_map.empty()) debug_map.insert({ "context: " + context, "debugs are off" });
        debug_map.insert({ service_name, "context: " + context });
        return debug_map;
    }

private:
    vector<DebugStreamConf> streams;
    Context context;
};

class KernelModuleConf
{
public:
    KernelModuleConf() : context(Context(Service::ACCESS_CONTROL)) {}

    void initCtx() { context.init(); }

    void
    save(cereal::JSONOutputArchive &ar) const
    {
        ar(cereal::make_nvp("kernel debug", kernel_debug));
        try {
            ar(cereal::make_nvp("debug context", context));
        } catch(...) {
        }
    }

    void
    load(cereal::JSONInputArchive &ar)
    {
        ar(cereal::make_nvp("kernel debug", kernel_debug));
        try {
            ar(cereal::make_nvp("debug context", context));
        } catch(...) {
        }
    }

    void
    resetDebug()
    {
        kernel_debug.front().clear();
        kernel_debug.front()["All"] = "None";
    }

    void
    addDebug(const map<string, string> &new_flags)
    {
        kernel_debug.front().erase("All");
        for (const auto &flag : new_flags) {
            kernel_debug.front()[flag.first] = flag.second;
        }
    }

    void addContext(string &ctx_key, string &ctx_val) { context.addContext(ctx_key, ctx_val); }

    multimap<string, string>
    mapDebugConf(const string &service_name) const
    {
        multimap<string, string> debug_map;
        for (const map<string, string> &stream : kernel_debug) {
            if (stream.find("All") != stream.end() && stream.find("All")->second == "None") continue;
            for (const auto &flag : stream) {
                debug_map.insert({ "kernel debug", flag.first + " = " + flag.second });
            }
        }
        if (debug_map.empty()) debug_map.insert({ "kernel debug", "debugs are off" });
        debug_map.insert({ service_name, "kernel debug" });
        return debug_map;
    }

    bool
    checkIfHasKernelDebugFlags() const
    {
        auto stream_is_active = std::find_if(
            kernel_debug.begin(),
            kernel_debug.end(),
            [] (const map<string, string> &stream) -> bool
            {
                if (stream.find("ALL") != stream.end() && stream.find("ALL")->second == "None") {
                    return false;
                }
                return stream.size() > 0;
            }
        );

        return stream_is_active != kernel_debug.end();
    }

    DebugLevel
    getMinLevelKernel(vector<string> flags_to_ignore) const
    {
        DebugLevel min_level = max_debug_level;
        for (const map<string, string> &stream : kernel_debug) {
            if (stream.find("ALL") != stream.end() && stream.find("ALL")->second == "None") continue;
            for (const auto &flag : stream) {
                if (find(flags_to_ignore.begin(), flags_to_ignore.end(), flag.first) != flags_to_ignore.end()) {
                    continue;
                }
                DebugLevel new_level = getDebugLevel(flag.second);
                if (new_level < min_level) {
                    min_level = new_level;
                }
            }
        }
        return min_level;
    }

    void
    removeAllNoneFlag()
    {
        for (map<string, string> &stream : kernel_debug) {
            if (stream.size() > 0) {
                auto all_flag = stream.find("ALL");
                if (all_flag != stream.end() && all_flag->second == "None") {
                    stream.erase(all_flag);
                }
            }
        }
    }

private:
    vector<map<string, string>> kernel_debug;
    Context context;
};

class DebugCli
{
public:
    bool init(const vector<Service> &services_list);

    void set(const vector<string> &flags, const string &output = "") { changeFlags(output, flags, true); }
    void add(const vector<string> &flags, const string &output = "") { changeFlags(output, flags, false); }
    void setDefault();
    void show();
    void remove(const string &output = "");
    void resetContext(const vector<string> &context);

    static void listLegalFlags(bool should_indent = false);
    static void usage(const string &custom_error = "");

    static int main(vector<string> &args);

    static string caller;

private:
    void setContexts(const vector<string> &context);
    void changeFlags(const string &output, const vector<string> &flags, bool is_reset_needed);
    vector<DebugConf> loadDebugConf(cereal::JSONInputArchive &archive_in);
    void loadKernelModuleConf(stringstream &debug_stream);

    void saveDebugConf(Service service);

    KernelModuleConf kernel_debug_conf;
    HttpHandlerContext http_ctx;
    map<Service, vector<DebugConf>> services_debug_confs;
    Context context;
};

string DebugCli::caller = "cpnano_debug";

static void
printDebugTree(const multimap<string, string> &debugs, const string &parrent, const string &prefix, bool is_last)
{
    auto res_iter = debugs.equal_range(parrent);
    cout << prefix << section << parrent << endl;
    for (multimap<string, string>::const_iterator it = res_iter.first; it != res_iter.second; ++it) {
        bool last_iter = ++it == res_iter.second;
        --it;
        printDebugTree(debugs, it->second, is_last ? prefix + indent : prefix + vertical, last_iter);
    }
}

void
DebugCli::setContexts(const vector<string> &contexts)
{
    for (const string &maybe_context : contexts) {
        size_t delim = maybe_context.find('=');
        if (delim == string::npos || delim == 0 || delim == contexts.size() - 1) {
            cerr << "Ignoring illegal context: \"" << maybe_context << "\" (syntax is <context>=<value>)." << endl;
        }
        string context_key = maybe_context.substr(0, delim);
        string context_value = maybe_context.substr(delim + 1);\
        context.addContext(context_key, context_value);
        kernel_debug_conf.addContext(context_key, context_value);
        http_ctx.addContext(context_key, context_value);
    }
}

void
DebugCli::listLegalFlags(bool should_indent)
{
    string prefix = should_indent ? "\t" : "";
    cout
        << prefix << "Available Debug Levels: " << endl
        << prefix << "------------------------" << endl
        << prefix <<  "Trace, Debug, Warning, Info, Error, None" << endl << endl

        << prefix << "Available Nano Service Debug Flags:" << endl
        << prefix << "-----------------------------------" << endl;

    multimap<string, string> flags_hierarchy = {
#define DEFINE_FLAG(flag_name, parent_name) { #parent_name, #flag_name },
#include "debug_flags.h"
#undef DEFINE_FLAG
    };

    sortMultimap(flags_hierarchy);
    printDebugTree(flags_hierarchy, "D_ALL", prefix, true);
    cout << endl;

    cout
        << prefix << "Available Kernel Module Debug Flags:" << endl
        << prefix << "------------------------------------" << endl;

    flags_hierarchy.clear();
    flags_hierarchy = {
#define DEFINE_KDEBUG_FLAG(flag_name) { "ALL", #flag_name },
#include "kdebug_flags.h"
#undef DEFINE_KDEBUG_FLAG
    };

    sortMultimap(flags_hierarchy);
    printDebugTree(flags_hierarchy, "ALL", prefix, true);
}

vector<DebugConf>
DebugCli::loadDebugConf(cereal::JSONInputArchive &archive_in)
{
    vector<DebugConf> debug;
    try {
        archive_in(cereal::make_nvp("Debug", debug));
    } catch (exception &e) {
        cerr
            << "Failed to parse Debug configuration file:"
            << "With the following error: "
            << e.what();
        exit(error_exit_code);
    }
    return debug;
}

void
DebugCli::loadKernelModuleConf(stringstream &debug_stream)
{
    try {
        cereal::JSONInputArchive archive_in(debug_stream);
        archive_in(cereal::make_nvp("kernel module", kernel_debug_conf));
    } catch (exception &e) {
        cerr
            << "Failed to parse Debug configuration file:" << endl
            << debug_stream.str() << endl
            << "With the following error: " << e.what();
        exit(error_exit_code);
    }
}

bool
DebugCli::init(const vector<Service> &services_list)
{
    context.init();
    http_ctx.init();
    kernel_debug_conf.initCtx();

    for (const Service &service : services_list) {
        ifstream debug_conf_file(getServiceConfig(service).first);
        if (!debug_conf_file.is_open()) {
            continue;
        }

        stringstream debug_conf_stream;
        debug_conf_stream << debug_conf_file.rdbuf();
        debug_conf_file.close();

        cereal::JSONInputArchive archive_in(debug_conf_stream);
        vector<DebugConf> debug = loadDebugConf(archive_in);
        services_debug_confs[service] = debug;
        if (service == Service::ACCESS_CONTROL) {
            debug_conf_stream.clear();
            debug_conf_stream.seekg(0);
            loadKernelModuleConf(debug_conf_stream);
        }
        if (service == Service::HTTP_MANAGER || service == Service::HTTP_TRANSACTION_HANDLER) {
            try{
                archive_in(cereal::make_nvp("HTTP manager", http_ctx));
            } catch (...) {
                continue;
            }
        }
    }
    if (services_debug_confs.empty()) {
        cerr << "Cannot load any Debug configuration file" << endl;
        return false;
    }

    return true;
}

void
DebugCli::setDefault()
{
    map<string, string> default_stdout_us_flags = { {"D_ALL", "Info"} };
    map<string, string> default_fog_us_flags = { {"D_ALL", "Error"} };

    for (auto &service : services_debug_confs) {
        if (service.first == Service::ACCESS_CONTROL) {
            kernel_debug_conf.resetDebug();
        }

        vector<DebugConf> &debug_list = service.second;
        const string &default_file_stream = getServiceConfig(service.first).second;
        for (DebugConf &debug : debug_list) {
            if (service.first == Service::ACCESS_CONTROL) {
                debug.removeDebug("", kernel_flags_in_user_space);
                debug.removeDebug("FOG", kernel_flags_in_user_space);
            }

            debug.deleteStreams("");
            debug.deleteStreams("FOG");
            debug.addDebug("", default_file_stream, default_stdout_us_flags);
            debug.addDebug("FOG", default_file_stream, default_fog_us_flags);
        }
        saveDebugConf(service.first);
    }
}

void
DebugCli::saveDebugConf(Service service)
{
    const string &debug_conf_file = getServiceConfig(service).first;
    ofstream debug_conf_output(debug_conf_file, ofstream::out);
    cereal::JSONOutputArchive archive(debug_conf_output);
    archive(cereal::make_nvp("Debug", services_debug_confs[service]));
    if (service == Service::ACCESS_CONTROL) {
        archive(cereal::make_nvp("kernel module", kernel_debug_conf));
    }
    if (service == Service::HTTP_MANAGER || service == Service::HTTP_TRANSACTION_HANDLER) {
        try{
            archive(cereal::make_nvp("HTTP manager", http_ctx));
        } catch (...) {
        }
    }
}

void
DebugCli::show()
{
    for (const auto &service : services_debug_confs) {
        multimap<string, string> debug_map;
        const vector<DebugConf> &debug_conf = service.second;
        for (const DebugConf &debug : debug_conf) {
            multimap<string, string> debug_sub_map = debug.mapDebugConf(getServiceString(service.first));
            for (const auto &debug_map_section : debug_sub_map) {
                debug_map.insert(debug_map_section);
            }
        }
        if (service.first == Service::ACCESS_CONTROL) {
            multimap<string, string> debug_sub_map = kernel_debug_conf.mapDebugConf(getServiceString(service.first));
            for (const auto &debug_map_section : debug_sub_map) {
                debug_map.insert(debug_map_section);
            }
        }

        sortMultimap(debug_map);
        printDebugTree(
            debug_map,
            getServiceString(service.first),
            "",
            service.first == services_debug_confs.crbegin()->first
        );
    }
}

void
DebugCli::remove(const string &output)
{
    for (auto &service : services_debug_confs) {
        vector<DebugConf> &debug_list = service.second;
        for (DebugConf &debug : debug_list) {
            debug.deleteStreams(output);
        }
        if (service.first == Service::ACCESS_CONTROL) {
            kernel_debug_conf.resetDebug();
            kernel_debug_conf.initCtx();
        }
        if (service.first == Service::HTTP_MANAGER || service.first == Service::HTTP_TRANSACTION_HANDLER) {
            http_ctx.init();
        }
        context.init();
        saveDebugConf(service.first);
    }
}

void
DebugCli::changeFlags(const string &output, const vector<string> &flags, bool is_reset_needed)
{
    map<string, string> parsed_us_flags;
    map<string, string> parsed_k_flags;
    DebugLevel min_level_kernel = max_debug_level;
    vector<string> new_kernel_flags;
    for (const string &maybe_flag : flags) {
        size_t delim = maybe_flag.find('=');
        if (delim == string::npos || delim == 0 || delim == flags.size() - 1) {
            cerr << "Ignoring illegal flag: \"" << maybe_flag << "\" (syntax is <flag>=<level>)." << endl;
            continue;
        }
        string flag = maybe_flag.substr(0, delim);
        if (us_debug_flags.count(flag) == 0 && kernel_debug_flags.count(flag) == 0) {
            cerr
                << "Ignoring non existing flag: \""
                << flag
                << "\" (use "
                << DebugCli::caller
                << "--show available-flags to get list of possible flags)."
                << endl;
            continue;
        }
        string level = maybe_flag.substr(delim + 1);
        if (debug_levels.count(level) == 0) {
            cerr
                << "Ignoring flag with non existing level: \""
                << level
                << "\" (Use "
                << DebugCli::caller
                << "--show available-flags to get list of possible debug levels)."
                << endl;
            continue;
        }

        if (us_debug_flags.count(flag) > 0) {
            parsed_us_flags[flag] = level;
        } else {
            DebugLevel new_debug_level = getDebugLevel(level);
            if (new_debug_level < min_level_kernel) {
                min_level_kernel = new_debug_level;
            }
            parsed_k_flags[flag] = level;
            new_kernel_flags.push_back(flag);
        }
    }

    if (!is_reset_needed) {
        DebugLevel existing_min_level = kernel_debug_conf.getMinLevelKernel(new_kernel_flags);
        if (existing_min_level < min_level_kernel) {
            min_level_kernel = existing_min_level;
        }
    }

    if (!parsed_k_flags.empty()) {
        string new_debug_level = getDebugLevelString(min_level_kernel);
        for (string flag : kernel_flags_in_user_space) {
            parsed_us_flags[flag] = new_debug_level;
        }
        kernel_debug_conf.removeAllNoneFlag();
    }

    for (auto &service : services_debug_confs) {
        if (service.first == Service::ACCESS_CONTROL) {
            if (is_reset_needed) {
                kernel_debug_conf.resetDebug();
            }
            kernel_debug_conf.addDebug(parsed_k_flags);
        }
        vector<DebugConf> &debug_list = service.second;
        const string &default_file_stream = getServiceConfig(service.first).second;
        for (DebugConf &debug : debug_list) {
            if (service.first == Service::ACCESS_CONTROL) {
                if (parsed_k_flags.empty() && !kernel_debug_conf.checkIfHasKernelDebugFlags()) {
                    debug.removeDebug(output, kernel_flags_in_user_space);
                }
            }
            if (is_reset_needed) {
                debug.deleteStreams(output);
            }
            debug.addDebug(output, default_file_stream, parsed_us_flags);
        }
        saveDebugConf(service.first);
    }
}

void
DebugCli::usage(const string &custom_error)
{
    vector<string> services;
    for (Service srvc : makeRange<Service>()) {
        services.push_back(getServiceString(srvc));
    }

    if (custom_error.size() > 0) cerr << "Error: " << custom_error << endl;
    cerr
        << "Usage: " << DebugCli::caller
        << " <command [option]> [--service <nano services list>] [--flags <flags list>]" << endl
        << "Available commands :" << endl
        << "\t--show [\"available-flags\"]   : show current (or available) debug configuration" << endl
        << "\t--set [output stream]          : set debug configuration" << endl
        << "\t--add [output stream]          : add debug configuration" << endl
        << "\t--delete [output stream]       : turn off debug configuration" << endl
        << "\t--default                      : set all flags to default debug configuration" << endl
        << "\t\t output stream : specify which debug output to change (\"FOG\"|\"STDOUT\"|<file>)" << endl
        << "\t--service <nano services list> : specify which Nano service debug configuration will be changed" << endl
        << "\t\t Nano Services list : one or more from the following list separated by spaces : "
        << makeSeparatedStr(services, ", ") << endl
        << "\t--flags <flags list>           : "
        << "list of flags and debug levels to add/set (with format of <flag>=<level>)" << endl << endl;
}

void
DebugCli::resetContext(const vector<string> &contexts)
{
    context.init();
    for(auto &service: services_debug_confs) {
        if (service.first == Service::ACCESS_CONTROL) {
            kernel_debug_conf.initCtx();
        }
        if (service.first == Service::HTTP_MANAGER || service.first == Service::HTTP_TRANSACTION_HANDLER) {
            http_ctx.init();
        }
    }
    setContexts(contexts);
}

static CliCommand
convertStringToCliCommand(const string &input)
{
    if (input == "--show") return CliCommand::SHOW;
    if (input == "--set") return CliCommand::SET;
    if (input == "--delete") return CliCommand::DELETE;
    if (input == "--add") return CliCommand::ADD;
    if (input == "--default") return CliCommand::DEFAULT;
    if (input == "-h" || input == "--help") {
        DebugCli::usage();
        exit(ok_exit_code);
    }

    DebugCli::usage("Illegal command provided '" + input + "'");
    exit(error_exit_code);
}

static vector<Service>
extractServices(const vector<string> &args)
{
    vector<Service> services;
    for (const string &maybe_service : args) {
        if (getServiceString(Service::ORCHESTRATION).find(maybe_service) == 0) {
            services.push_back(Service::ORCHESTRATION);
        } else if (getServiceString(Service::ACCESS_CONTROL).find(maybe_service) == 0) {
            services.push_back(Service::ACCESS_CONTROL);
        } else if (getServiceString(Service::HTTP_MANAGER).find(maybe_service) == 0) {
            services.push_back(Service::HTTP_MANAGER);
        } else if (getServiceString(Service::REVERSE_PROXY_MANAGER).find(maybe_service) == 0) {
            services.push_back(Service::REVERSE_PROXY_MANAGER);
        } else if (getServiceString(Service::CAPSULE8).find(maybe_service) == 0) {
            services.push_back(Service::CAPSULE8);
        } else if (getServiceString(Service::IOT_ENFORCE).find(maybe_service) == 0) {
            services.push_back(Service::IOT_ENFORCE);
        } else if (getServiceString(Service::IOT_DOCTOR).find(maybe_service) == 0) {
            services.push_back(Service::IOT_DOCTOR);
        } else if (getServiceString(Service::IOT_RISK).find(maybe_service) == 0) {
            services.push_back(Service::IOT_RISK);
        } else if (getServiceString(Service::IOT_GW_SENSOR).find(maybe_service) == 0) {
            services.push_back(Service::IOT_GW_SENSOR);
        } else if (getServiceString(Service::IOT_SNMP).find(maybe_service) == 0) {
            services.push_back(Service::IOT_SNMP);
        } else if (getServiceString(Service::IOT_MS_DHCP).find(maybe_service) == 0) {
            services.push_back(Service::IOT_MS_DHCP);
        } else if (getServiceString(Service::IOT_UNIX_DHCP).find(maybe_service) == 0) {
            services.push_back(Service::IOT_UNIX_DHCP);
        } else if (getServiceString(Service::IOT_SYSLOG_DHCP).find(maybe_service) == 0) {
            services.push_back(Service::IOT_SYSLOG_DHCP);
        } else if (getServiceString(Service::IOT_INFOBLOX_DHCP).find(maybe_service) == 0) {
            services.push_back(Service::IOT_INFOBLOX_DHCP);
        } else if (getServiceString(Service::IOT_CISCO_ISE).find(maybe_service) == 0) {
            services.push_back(Service::IOT_CISCO_ISE);
        } else if (getServiceString(Service::ATTACHMENT_REGISTRATOR).find(maybe_service) == 0) {
            services.push_back(Service::ATTACHMENT_REGISTRATOR);
        } else if (getServiceString(Service::HTTP_TRANSACTION_HANDLER).find(maybe_service) == 0) {
            services.push_back(Service::HTTP_TRANSACTION_HANDLER);
        } else if (getServiceString(Service::DEDICATED_NETWORK_HANDLER).find(maybe_service) == 0) {
            services.push_back(Service::DEDICATED_NETWORK_HANDLER);
        } else if (getServiceString(Service::SDWAN).find(maybe_service) == 0) {
            services.push_back(Service::SDWAN);
        } else if (getServiceString(Service::LOGGER_SDWAN).find(maybe_service) == 0) {
            services.push_back(Service::LOGGER_SDWAN);
        } else if (getServiceString(Service::IOT_WLP).find(maybe_service) == 0) {
            services.push_back(Service::IOT_WLP);
        } else if (getServiceString(Service::IDA).find(maybe_service) == 0) {
            services.push_back(Service::IDA);
        } else if (getServiceString(Service::IOT_ACCESS_CONTROL).find(maybe_service) == 0) {
            services.push_back(Service::IOT_ACCESS_CONTROL);
        } else if (getServiceString(Service::HORIZON_TELEMETRY).find(maybe_service) == 0) {
            services.push_back(Service::HORIZON_TELEMETRY);
        } else {
            break;
        }
    }
    return services;
}

static vector<string>
extractRelevantArgs(const vector<string> &args)
{
    vector<string> relevant_args;
    for (const string &maybe_relevant : args) {
        if (maybe_relevant.find("--") == 0) break;
        relevant_args.push_back(maybe_relevant);
    }
    return relevant_args;
}

static bool
isOutputStream(const string &maybe_stream)
{
    return
        maybe_stream == "STDOUT" ||
        maybe_stream == "FOG" ||
        maybe_stream.find("/tmp/") == 0 ||
        maybe_stream.find("/var/log/") == 0 ||
        maybe_stream.find(log_files_path) == 0;
}

int
DebugCli::main(vector<string> &args)
{
    CliCommand command = convertStringToCliCommand(args.front());
    args.erase(args.begin());

    string output_stream;
    if (!args.empty()) {
        switch (command) {
            case (CliCommand::SHOW): {
                if (string("available-flags").find(args.front()) == 0) {
                    listLegalFlags();
                    return ok_exit_code;
                }
                break;
            }
            case (CliCommand::DEFAULT):
                break;
            case (CliCommand::DELETE):
            case (CliCommand::SET):
            case (CliCommand::ADD): {
                if (isOutputStream(args.front())) {
                    output_stream = args.front();
                    args.erase(args.begin());
                }
                break;
            }
            default: {
                usage("No command was provided");
                return error_exit_code;
            }
        }
    }

    vector<Service> services;
    vector<string> flags;
    vector<string> context_raw;
    while (!args.empty()) {
        vector<Service> services_to_add;
        vector<string> flags_to_add;
        vector<string> context_to_add;
        string arg = args.front();
        args.erase(args.begin());
        if (arg == "--service") {
            services_to_add = extractServices(args);
            services.insert(services.end(), services_to_add.begin(), services_to_add.end());
            if (services_to_add.size() == 0) {
                usage("No service was provided");
                return error_exit_code;
            }
            for (uint i = 0 ; i < services_to_add.size() ; i++) {
                args.erase(args.begin());
            }
            continue;
        }

        if (arg == "--flags") {
            flags_to_add = extractRelevantArgs(args);
            flags.insert(flags.end(), flags_to_add.begin(), flags_to_add.end());
            if (flags_to_add.size() == 0) {
                usage("No Flags were provided");
                return error_exit_code;
            }
            for (uint i = 0 ; i < flags_to_add.size() ; i++) {
                args.erase(args.begin());
            }
            continue;
        }

        if (arg == "--context") {
            context_to_add = extractRelevantArgs(args);
            context_raw.insert(context_raw.end(), context_to_add.begin(), context_to_add.end());
            if (context_to_add.size() == 0) {
                usage("No Context was provided");
            }
            for (uint i = 0 ; i < context_to_add.size() ; i++) {
                args.erase(args.begin());
            }
            continue;
        }

        cerr << "Notice: Ignoring unsupported argument \"" << arg << "\"" << endl;
    }

    if (services.empty()) {
        for (Service srvc : makeRange<Service>()) {
            services.push_back(srvc);
        }
    }
    DebugCli debug;
    if (!debug.init(services)) {
        usage();
        return error_exit_code;
    }
    switch (command) {
        case (CliCommand::SHOW): {
            debug.show();
            return ok_exit_code;
        }
        case (CliCommand::DELETE): {
            debug.remove(output_stream);
            break;
        }
        case (CliCommand::SET): {
            if (flags.empty() && context_raw.empty()) {
                usage("No Flags or Context were provided");
                return error_exit_code;
            }
            debug.resetContext(context_raw);
            debug.set(flags, output_stream);
            break;
        }
        case (CliCommand::ADD): {
            if (flags.empty() && context_raw.empty()) {
                usage("No Flags or Context were provided");
                return error_exit_code;
            }
            debug.setContexts(context_raw);
            debug.add(flags, output_stream);
            break;
        }
        case (CliCommand::DEFAULT): {
            debug.resetContext(context_raw);
            debug.setDefault();
            break;
        }
        default: {
            return error_exit_code;
        }
    }

    return reload_settings_exit_code;
}

bool
handleCpnanoInvocation(vector<string> &args)
{
    DebugCli::caller = "cpnano --debug";
    args.erase(args.begin());

    if (!args.empty() && (args.front() == "--debug" || args.front() == "-d")) args.erase(args.begin());
    if (args.empty()) {
        DebugCli::usage("No arguments were provided");
        return false;
    }

    return true;
}

int
main(int argc, char **argv)
{
    updatePaths();
    static const string cpnano = "cpnano";
    if (argc < 2) {
        DebugCli::usage("No arguments were provided");
        exit(error_exit_code);
    }

    vector<string> args(argv + 1, argv + argc);

    // cpnano had called this tool
    if (args.front().find(cpnano) != string::npos && !handleCpnanoInvocation(args)) exit(error_exit_code);

    int ret = DebugCli::main(args);
    exit(ret);
}
