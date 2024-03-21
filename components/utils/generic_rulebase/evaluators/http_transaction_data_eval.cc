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

#include "generic_rulebase/evaluators/http_transaction_data_eval.h"

#include <boost/lexical_cast.hpp>
#include <algorithm>

#include "http_transaction_data.h"
#include "environment/evaluator_templates.h"
#include "i_environment.h"
#include "singleton.h"
#include "debug.h"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

using namespace std;
using namespace EnvironmentHelper;

EqualHost::EqualHost(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams("EqualHost", params.size(), 1, 1);
    host = params[0];
}

Maybe<bool, Context::Error>
EqualHost::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<EqualHost>();
    auto host_ctx = env->get<string>(HttpTransactionData::host_name_ctx);

    if (!host_ctx.ok())
    {
        return false;
    }

    std::string lower_host_ctx = host_ctx.unpack();
    std::transform(lower_host_ctx.begin(), lower_host_ctx.end(), lower_host_ctx.begin(), ::tolower);

    std::string lower_host = host;
    std::transform(lower_host.begin(), lower_host.end(), lower_host.begin(), ::tolower);


    if (lower_host_ctx == lower_host) return true;
    size_t pos = lower_host_ctx.find_last_of(':');
    if (pos == string::npos) return false;
    lower_host_ctx = string(lower_host_ctx.data(), pos);
    return lower_host_ctx == lower_host;
}

WildcardHost::WildcardHost(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams("WildcardHost", params.size(), 1, 1);
    host = params[0];
}

Maybe<bool, Context::Error>
WildcardHost::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<WildcardHost>();
    auto host_ctx = env->get<string>(HttpTransactionData::host_name_ctx);

    if (!host_ctx.ok())
    {
        return false;
    }

    string lower_host_ctx = host_ctx.unpack();
    transform(lower_host_ctx.begin(), lower_host_ctx.end(), lower_host_ctx.begin(), ::tolower);

    dbgTrace(D_RULEBASE_CONFIG) << "found host in current context: " << lower_host_ctx;

    size_t pos = lower_host_ctx.find_first_of(".");
    if (pos == string::npos) {
        return false;
    }

    lower_host_ctx = "*" + lower_host_ctx.substr(pos, lower_host_ctx.length());

    string lower_host = host;
    transform(lower_host.begin(), lower_host.end(), lower_host.begin(), ::tolower);

    dbgTrace(D_RULEBASE_CONFIG)
        << "trying to match host context with its corresponding wildcard address: "
        << lower_host_ctx
        << ". Matcher host: "
        << lower_host;

    if (lower_host_ctx == lower_host) return true;
    pos = lower_host_ctx.find_last_of(':');
    if (pos == string::npos) return false;
    lower_host_ctx = string(lower_host_ctx.data(), pos);
    return lower_host_ctx == lower_host;
}

EqualListeningIP::EqualListeningIP(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams("EqualListeningIP", params.size(), 1, 1);

    auto maybe_ip = IPAddr::createIPAddr(params[0]);
    if (!maybe_ip.ok()) reportWrongParamType(getName(), params[0], "Not a valid IP Address");

    listening_ip = maybe_ip.unpack();
}

Maybe<bool, Context::Error>
EqualListeningIP::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<EqualListeningIP>();
    auto listening_ip_ctx = env->get<IPAddr>(HttpTransactionData::listening_ip_ctx);
    return listening_ip_ctx.ok() &&  listening_ip_ctx.unpack() == listening_ip;
}

EqualListeningPort::EqualListeningPort(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams("EqualListeningPort", params.size(), 1, 1);

    try {
        listening_port = boost::lexical_cast<PortNumber>(params[0]);
    } catch (boost::bad_lexical_cast const&) {
        reportWrongParamType(getName(), params[0], "Not a valid port number");
    }
}

Maybe<bool, Context::Error>
EqualListeningPort::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<EqualListeningPort>();
    auto port_ctx = env->get<PortNumber>(HttpTransactionData::listening_port_ctx);

    return port_ctx.ok() && port_ctx.unpack() == listening_port;
}

BeginWithUri::BeginWithUri(const vector<string> &params)
{
    if (params.size() != 1) reportWrongNumberOfParams("BeginWithUri", params.size(), 1, 1);
    uri_prefix = params[0];
}

Maybe<bool, Context::Error>
BeginWithUri::evalVariable() const
{
    I_Environment *env = Singleton::Consume<I_Environment>::by<BeginWithUri>();
    auto uri_ctx = env->get<string>(HttpTransactionData::uri_ctx);

    if (!uri_ctx.ok())
    {
        return false;
    }

    std::string lower_uri_ctx = uri_ctx.unpack();
    std::transform(lower_uri_ctx.begin(), lower_uri_ctx.end(), lower_uri_ctx.begin(), ::tolower);

    std::string lower_uri_prefix = uri_prefix;
    std::transform(lower_uri_prefix.begin(), lower_uri_prefix.end(), lower_uri_prefix.begin(), ::tolower);

    return lower_uri_ctx.find(lower_uri_prefix) == 0;
}
