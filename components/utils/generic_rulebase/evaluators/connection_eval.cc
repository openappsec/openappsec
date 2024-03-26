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

#include "generic_rulebase/evaluators/connection_eval.h"

#include <vector>
#include <string>

#include "generic_rulebase/rulebase_config.h"
#include "config.h"
#include "debug.h"
#include "ip_utilities.h"

using namespace std;
USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

string IpAddressMatcher::ctx_key = "ipAddress";
string SourceIpMatcher::ctx_key = "sourceIP";
string DestinationIpMatcher::ctx_key = "destinationIP";
string SourcePortMatcher::ctx_key = "sourcePort";
string ListeningPortMatcher::ctx_key = "listeningPort";
string IpProtocolMatcher::ctx_key = "ipProtocol";
string UrlMatcher::ctx_key = "url";

Maybe<IPAddr>
getIpAddrFromEnviroment(I_Environment *env, Context::MetaDataType enum_data_type, const string &str_data_type)
{
    auto ip_str = env->get<string>(enum_data_type);
    if (!ip_str.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to get " << str_data_type << " from the enviroment.";
        return genError("Failed to get " + str_data_type + " from the enviroment.");
    }
    return IPAddr::createIPAddr(ip_str.unpack());
}

bool
checkIfIpInRangesVec(const vector<CustomRange<IPAddr>> &values, const IPAddr &ip_to_check)
{
    if (values.size() == 0) {
        dbgTrace(D_RULEBASE_CONFIG) << "Ip addersses vector empty. Match is true.";
        return true;
    }
    for (const CustomRange<IPAddr> &range : values) {
        if (range.contains(ip_to_check)) {
            dbgTrace(D_RULEBASE_CONFIG) << "Ip adderss matched: " << ip_to_check;
            return true;
        }
    }
    dbgTrace(D_RULEBASE_CONFIG) << "Ip adderss not match: " << ip_to_check;
    return false;
}


IpAddressMatcher::IpAddressMatcher(const vector<string> &params)
{
    for (const string &param : params) {
        Maybe<CustomRange<IPAddr>> ip_range = CustomRange<IPAddr>::createRange(param);
        if (!ip_range.ok()) {
            dbgWarning(D_RULEBASE_CONFIG) << "Failed to create ip. Error: " + ip_range.getErr();
            continue;
        }
        values.push_back(ip_range.unpack());
    }
}

Maybe<bool, Context::Error>
IpAddressMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<IpAddressMatcher>();
    Maybe<IPAddr> subject_ip = getIpAddrFromEnviroment(
        env,
        Context::MetaDataType::SubjectIpAddr,
        "subject ip address"
    );
    if (subject_ip.ok() && checkIfIpInRangesVec(values, subject_ip.unpack())) return true;

    Maybe<IPAddr> other_ip = getIpAddrFromEnviroment(
        env,
        Context::MetaDataType::OtherIpAddr,
        "other ip address"
    );
    if (other_ip.ok() && checkIfIpInRangesVec(values, other_ip.unpack())) return true;
    if (!subject_ip.ok() && !other_ip.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Error in getting subject ip and other ip from the enviroment";
        return false;
    }
    dbgTrace(D_RULEBASE_CONFIG) << "Ip adderss didn't match";
    return false;
}

SourceIpMatcher::SourceIpMatcher(const vector<string> &params)
{
    for (const string &param : params) {
        Maybe<CustomRange<IPAddr>> ip_range = CustomRange<IPAddr>::createRange(param);
        if (!ip_range.ok()) {
            dbgWarning(D_RULEBASE_CONFIG) << "Failed to create source ip. Error: " + ip_range.getErr();
            continue;
        }
        values.push_back(ip_range.unpack());
    }
}

Maybe<bool, Context::Error>
SourceIpMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<SourceIpMatcher>();
    auto direction_maybe = env->get<string>(Context::MetaDataType::Direction);
    if (!direction_maybe.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to get direction from the enviroment.";
        return false;
    }
    string direction = direction_maybe.unpack();
    if (direction == "incoming") {
        Maybe<IPAddr> other_ip = getIpAddrFromEnviroment(
            env,
            Context::MetaDataType::OtherIpAddr,
            "other ip address"
        );
        return other_ip.ok() && checkIfIpInRangesVec(values, other_ip.unpack());
    } else if (direction == "outgoing") {
        Maybe<IPAddr> subject_ip = getIpAddrFromEnviroment(
            env,
            Context::MetaDataType::SubjectIpAddr,
            "subject ip address"
        );
        return subject_ip.ok() && checkIfIpInRangesVec(values, subject_ip.unpack());
    }
    dbgTrace(D_RULEBASE_CONFIG) << "Source ip adderss didn't match";
    return false;
}

DestinationIpMatcher::DestinationIpMatcher(const vector<string> &params)
{
    for (const string &param : params) {
        Maybe<CustomRange<IPAddr>> ip_range = CustomRange<IPAddr>::createRange(param);
        if (!ip_range.ok()) {
            dbgWarning(D_RULEBASE_CONFIG) << "Failed to create destination ip. Error: " + ip_range.getErr();
            continue;
        }
        values.push_back(ip_range.unpack());
    }
}

Maybe<bool, Context::Error>
DestinationIpMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<DestinationIpMatcher>();
    auto direction_maybe = env->get<string>(Context::MetaDataType::Direction);
    if (!direction_maybe.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to get direction.";
        return false;
    }
    string direction = direction_maybe.unpack();
    if (direction == "outgoing") {
        Maybe<IPAddr> other_ip = getIpAddrFromEnviroment(
            env,
            Context::MetaDataType::OtherIpAddr,
            "other ip address"
        );
        return other_ip.ok() && checkIfIpInRangesVec(values, other_ip.unpack());
    } else if (direction == "incoming") {
        Maybe<IPAddr> subject_ip = getIpAddrFromEnviroment(
            env,
            Context::MetaDataType::SubjectIpAddr,
            "subject ip address"
        );
        return subject_ip.ok() && checkIfIpInRangesVec(values, subject_ip.unpack());
    }
    dbgTrace(D_RULEBASE_CONFIG) << "Destination ip adderss didn't match";
    return false;
}

SourcePortMatcher::SourcePortMatcher(const vector<string> &params)
{
    for (const string &param : params) {
        Maybe<CustomRange<PortNumber>> port_range = CustomRange<PortNumber>::createRange(param);
        if (!port_range.ok()) {
            dbgWarning(D_RULEBASE_CONFIG) << "Failed to create source port.";
            continue;
        }
        values.push_back(port_range.unpack());
    }
}

Maybe<bool, Context::Error>
SourcePortMatcher::evalVariable() const
{
    dbgTrace(D_RULEBASE_CONFIG) << "Source is not a match";
    return false;
}


ListeningPortMatcher::ListeningPortMatcher(const vector<string> &params)
{
    for (const string &param : params) {
        Maybe<CustomRange<PortNumber>> port_range = CustomRange<PortNumber>::createRange(param);
        if (!port_range.ok()) {
            dbgWarning(D_RULEBASE_CONFIG) << "Failed to create listening port range.";
            continue;
        }
        values.push_back(port_range.unpack());
    }
}

Maybe<bool, Context::Error>
ListeningPortMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<ListeningPortMatcher>();
    auto port_str = env->get<string>(Context::MetaDataType::Port);
    if (!port_str.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to get port from the enviroment.";
        return false;
    }
    PortNumber port;
    if (ConnKeyUtil::fromString(port_str.unpack(), port)) {
        if (values.size() == 0) return true;
        for (const CustomRange<PortNumber> &port_range : values) {
            if (port_range.contains(port)) {
                dbgTrace(D_RULEBASE_CONFIG) << "Listening port is a match. Value: " << port_str.unpack();
                return true;
            }
        }
    }
    dbgTrace(D_RULEBASE_CONFIG) << "Listening port is not a match. Value: " << port_str.unpack();
    return false;
}

IpProtocolMatcher::IpProtocolMatcher(const vector<string> &params)
{
    for (const string &param : params) {
        Maybe<CustomRange<IPProto>> proto_range = CustomRange<IPProto>::createRange(param);
        if (!proto_range.ok()) {
            dbgWarning(D_RULEBASE_CONFIG) << "Failed to create ip protocol.";
            continue;
        }
        values.push_back(proto_range.unpack());
    }
}

Maybe<bool, Context::Error>
IpProtocolMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<IpProtocolMatcher>();
    auto proto_str = env->get<string>(Context::MetaDataType::Protocol);
    if (!proto_str.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to get ip protocol from the enviroment.";
        return false;
    }
    IPProto protocol;
    if (ConnKeyUtil::fromString(proto_str.unpack(), protocol)) {
        if (values.size() == 0) return true;
        for (const CustomRange<IPProto> &proto_range : values) {
            if (proto_range.contains(protocol)) {
                dbgTrace(D_RULEBASE_CONFIG) << "Ip protocol is a match. Value: " << proto_str.unpack();
                return true;
            }
        }
    }
    dbgTrace(D_RULEBASE_CONFIG) << "Source port is not a match. Value: " << proto_str.unpack();
    return false;
}

UrlMatcher::UrlMatcher(const vector<string> &params) : values(params) {}

Maybe<bool, Context::Error>
UrlMatcher::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<UrlMatcher>();
    auto curr_url_ctx = env->get<string>(Context::MetaDataType::Url);
    if (!curr_url_ctx.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to get URL from the enviroment.";
        return false;
    }
    
    if (values.size() == 0) {
        dbgTrace(D_RULEBASE_CONFIG) << "Matched URL on \"any\". Url: " << *curr_url_ctx;
        return true;
    }

    for (const string &url : values) {
        if (*curr_url_ctx == url) {
            dbgTrace(D_RULEBASE_CONFIG) << "Matched URL. Value: " << *curr_url_ctx;
            return true;
        }
    }

    dbgTrace(D_RULEBASE_CONFIG) << "URL is not a match. Value: " << *curr_url_ctx;
    return false;
}
