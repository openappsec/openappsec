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

#include "generic_rulebase/evaluators/query_eval.h"

#include <vector>
#include <string>
#include <map>

#include "generic_rulebase/rulebase_config.h"
#include "generic_rulebase/zones_config.h"
#include "i_environment.h"
#include "singleton.h"
#include "config.h"
#include "debug.h"
#include "enum_range.h"

using namespace std;

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

QueryMatcher::QueryMatcher(const vector<string> &params)
{
    if (params.size() < 1) reportWrongNumberOfParams(QueryMatcher::getName(), params.size(), 1);

    key = params.front();
    if (key == "any") {
        is_any = true;
    } else {
        values.reserve(params.size() - 1);
        for (uint i = 1; i < params.size() ; i++) {
            if (params[i] == "any") {
                values.clear();
                break;
            }
            values.insert(params[i]);
        }
    }
}

const string
QueryMatcher::contextKeyToString(Context::MetaDataType type)
{
    if (type == Context::MetaDataType::SubjectIpAddr || type == Context::MetaDataType::OtherIpAddr) return "ip";
    return Context::convertToString(type);
}

class QueryMatchSerializer
{
public:
    static const string req_attr_ctx_key;

    template <typename Archive>
    void
    serialize(Archive &ar)
    {
        I_Environment *env = Singleton::Consume<I_Environment>::by<QueryMatcher>();
        auto req_attr = env->get<string>(req_attr_ctx_key);
        if (!req_attr.ok()) return;

        try {
            ar(cereal::make_nvp(*req_attr, value));
            dbgDebug(D_RULEBASE_CONFIG)
                << "Found value for requested attribute. Tag: "
                << *req_attr
                << ", Value: "
                << value;
        } catch (exception &e) {
            dbgDebug(D_RULEBASE_CONFIG) << "Could not find values for requested attribute. Tag: " << *req_attr;
            ar.finishNode();
        }
    }

    template <typename Values>
    bool
    matchValues(const Values &requested_vals) const
    {
        return value != "" && (requested_vals.empty() || requested_vals.count(value) > 0);
    }

private:
    string value;
};

const string QueryMatchSerializer::req_attr_ctx_key = "requested attribute key";

Maybe<bool, Context::Error>
QueryMatcher::evalVariable() const
{
    if (is_any) return true;

    I_Environment *env = Singleton::Consume<I_Environment>::by<QueryMatcher>();
    auto local_asset_ctx = env->get<bool>("is local asset");
    bool is_remote_asset = local_asset_ctx.ok() && !(*local_asset_ctx);

    QueryRequest request;
    for (Context::MetaDataType name : makeRange<Context::MetaDataType>()) {
        auto val = env->get<string>(name);
        if (val.ok()) {
            if ((name == Context::MetaDataType::SubjectIpAddr && is_remote_asset) ||
                (name == Context::MetaDataType::OtherIpAddr && !is_remote_asset)) {
                continue;
            }

            request.addCondition(Condition::EQUALS, contextKeyToString(name), *val);
        }
    }
    if (request.empty()) return false;

    request.setRequestedAttr(key);
    ScopedContext req_attr_key;
    req_attr_key.registerValue<string>(QueryMatchSerializer::req_attr_ctx_key, key);

    I_Intelligence_IS_V2 *intelligence = Singleton::Consume<I_Intelligence_IS_V2>::by<Zone>();
    auto query_res = intelligence->queryIntelligence<QueryMatchSerializer>(request);
    if (!query_res.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to perform intelligence query. Error: " << query_res.getErr();
        return false;
    }

    for (const AssetReply<QueryMatchSerializer> &asset : query_res.unpack()) {
        if (asset.matchValues<unordered_set<string>>(values)) return true;
    }

    return false;
}
