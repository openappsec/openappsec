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

#ifndef __RULES_CONFIG_SECTION_H__
#define __RULES_CONFIG_SECTION_H__

#include <string>
#include <algorithm>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "k8s_policy_common.h"

USE_DEBUG_FLAG(D_K8S_POLICY);
// LCOV_EXCL_START Reason: no test exist
class AssetUrlParser
{
public:
    std::string query_string, asset_uri, protocol, asset_url, port;

    AssetUrlParser()
    {}

    AssetUrlParser(const std::string &asset)
    {
        parse(asset);
    }

private:
    static AssetUrlParser
    parse(const std::string &uri)
    {
        AssetUrlParser result;

        using iterator_t = std::string::const_iterator;

        if (uri.length() == 0) return result;

        iterator_t uri_end = uri.end();

        // get query start
        iterator_t query_start = std::find(uri.begin(), uri_end, '?');

        // protocol
        iterator_t protocol_start = uri.begin();
        iterator_t protocol_end = std::find(protocol_start, uri_end, ':');            //"://");

        if (protocol_end != uri_end) {
            std::string http_protocol = &*(protocol_end);
            if ((http_protocol.length() > 3) && (http_protocol.substr(0, 3) == "://")) {
                result.protocol = std::string(protocol_start, protocol_end);
                protocol_end += 3;   //      ://
            } else {
                protocol_end = uri.begin();  // no protocol
            }
        } else {
            protocol_end = uri.begin();  // no protocol
        }

        // URL
        iterator_t host_start = protocol_end;
        iterator_t path_start = std::find(host_start, uri_end, '/');

        iterator_t host_end = std::find(protocol_end, (path_start != uri_end) ? path_start : query_start, ':');

        result.asset_url = std::string(host_start, host_end);

        // port
        if ((host_end != uri_end) && ((&*(host_end))[0] == ':')) { // we have a port
            host_end++;
            iterator_t portEnd = (path_start != uri_end) ? path_start : query_start;
            result.port = std::string(host_end, portEnd);
        }

        // URI
        if (path_start != uri_end) result.asset_uri = std::string(path_start, query_start);

        // query
        if (query_start != uri_end) result.query_string = std::string(query_start, uri.end());

        return result;
    }   // Parse
};  // uri

class PracticeSection
{
public:
    PracticeSection(const std::string &_id, const std::string &_type, const std::string &_practice_name)
    {
        auto maybe_type = string_to_practice_type.find(_type);
        if (maybe_type == string_to_practice_type.end()) {
            dbgError(D_K8S_POLICY) << "Illegal pracrtice type: " << _type;
            return;
        }

        type = _type;
        name = _practice_name;
        id = _id;
    }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("practiceId",   id),
            cereal::make_nvp("practiceName", name),
            cereal::make_nvp("practiceType", type)
        );
    }

    const std::string & getPracticeId() const { return id; }
    const std::string & getPracticeName() const { return name; }

private:
    std::string id;
    std::string name;
    std::string type;
};

class ParametersSection
{
public:
    ParametersSection(
        const std::string &_id,
        const std::string &_name)
            :
        name(_name),
        id(_id)
        {
            if (_id.empty() && _name.empty()) {
                dbgError(D_K8S_POLICY) << "Illegal Parameter values. Name and ID are empty";
                return;
            }
        }

    const std::string & getId() const { return id; }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("parameterId",   id),
            cereal::make_nvp("parameterName", name),
            cereal::make_nvp("parameterType", type)
        );
    }

private:
    std::string name;
    std::string id;
    std::string type = "Exception";
};

class RulesTriggerSection
{
public:
    RulesTriggerSection(
        const std::string &_name,
        const std::string &_id,
        const std::string &_type)
            :
        name(_name),
        id(_id)
    {
        if (_name.empty() && _id.empty()) {
            dbgError(D_K8S_POLICY) << "Illegal values for trigger. Name and ID are empty";
            return;
        }
        auto maybe_type = string_to_trigger_type.find(_type);
        if (maybe_type == string_to_trigger_type.end()) {
            dbgError(D_K8S_POLICY) << "Illegal trigger type in rule: " << _type;
            return;
        }
        type = _type;
    }

    const std::string & getId() const { return id; }
    const std::string & getName() const { return id; }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("triggerId",   id),
            cereal::make_nvp("triggerName", name),
            cereal::make_nvp("triggerType", type)
        );
    }

private:
    std::string name;
    std::string id;
    std::string type;
};

class RulesConfigRulebase
{
public:
    RulesConfigRulebase()
    {}

    RulesConfigRulebase(
        const std::string &_name,
        const std::string &_url,
        const std::string &_uri,
        std::vector<PracticeSection> _practices,
        std::vector<ParametersSection> _parameters,
        std::vector<RulesTriggerSection> _triggers)
            :
        name(_name),
        practices(_practices),
        parameters(_parameters),
        triggers(_triggers)
    {
        try {
            id = _url+_uri;
            bool any = _name == "Any" && _url == "Any" && _uri == "Any";
            if (_uri != "/") {
                context = any ? "All()" : "Any("
                    "All("
                        "Any("
                            "EqualHost(" + _url + ")"
                        "),"
                        "EqualListeningPort(80)" +
                        std::string(_uri.empty() ? "" : ",BeginWithUri(" + _uri + ")") +
                    "),"
                    "All("
                        "Any("
                            "EqualHost(" + _url + ")"
                        "),"
                        "EqualListeningPort(443)" +
                        std::string(_uri.empty() ? "" : ",BeginWithUri(" + _uri + ")") +
                    ")"
                ")";
            } else {
                context = any ? "All()" : "Any("
                    "All("
                        "Any("
                            "EqualHost(" + _url + ")"
                        "),"
                        "EqualListeningPort(80)"
                    "),"
                    "All("
                        "Any("
                            "EqualHost(" + _url + ")"
                        "),"
                        "EqualListeningPort(443)"
                    ")"
                ")";
            }
        } catch (const boost::uuids::entropy_error &e) {
            dbgWarning(D_K8S_POLICY) << "Failed to generate rule UUID. Error: " << e.what();
        }
    }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        std::string empty_str = "";
        out_ar(
            cereal::make_nvp("assetId",    id),
            cereal::make_nvp("assetName",  name),
            cereal::make_nvp("ruleId",     id),
            cereal::make_nvp("ruleName",   name),
            cereal::make_nvp("context",    context),
            cereal::make_nvp("priority",   1),
            cereal::make_nvp("isCleanup",  false),
            cereal::make_nvp("parameters", parameters),
            cereal::make_nvp("practices",  practices),
            cereal::make_nvp("triggers",   triggers),
            cereal::make_nvp("zoneId",     empty_str),
            cereal::make_nvp("zoneName",   empty_str)
        );
    }

    const std::string & getRuleId() const { return id; }
    const std::string & getAssetName() const { return name; }
    const std::string & getRuleName() const { return name; }
    const std::string & getAsstId() const { return id; }
    const std::string & getPracticeId() const { return practices[0].getPracticeId(); }
    const std::string & getPracticeName() const { return practices[0].getPracticeName(); }
    const std::vector<PracticeSection> & getPractice() const { return practices; }
    const std::vector<ParametersSection> & getParameters() const { return parameters; }
    const std::vector<RulesTriggerSection> & getTriggers() const { return triggers; }


private:
    std::string context;
    std::string id;
    std::string name;
    std::vector<PracticeSection> practices;
    std::vector<ParametersSection> parameters;
    std::vector<RulesTriggerSection> triggers;
};

class RulesConfigWrapper
{
public:
    class RulesConfig
    {
    public:
        RulesConfig(const std::vector<RulesConfigRulebase> &_rules_config)
                :
            rules_config(_rules_config)
        {
            sort(rules_config.begin(), rules_config.end(), sortBySpecific);
        }

        void
        serialize(cereal::JSONOutputArchive &out_ar) const
        {
            out_ar(
                cereal::make_nvp("rulesConfig", rules_config)
            );
        }

    private:
        static bool
        sortBySpecific(const RulesConfigRulebase &first, const RulesConfigRulebase &second)
        {
            return sortBySpecificAux(first.getAssetName(), second.getAssetName());
        }

        static bool
        sortBySpecificAux(const std::string &first, const std::string &second)
        {
            if (first.empty()) return false;
            if (second.empty()) return true;

            AssetUrlParser first_parsed = AssetUrlParser(first);
            AssetUrlParser second_parsed = AssetUrlParser(second);

            // sort by URL
            if (first_parsed.asset_url == "*" && second_parsed.asset_url != "*") return false;
            if (second_parsed.asset_url == "*" && first_parsed.asset_url != "*") return true;

            // sort by port
            if (first_parsed.port == "*" && second_parsed.port != "*") return false;
            if (second_parsed.port == "*" && first_parsed.port != "*") return true;

            // sort by URI
            if (first_parsed.asset_uri == "*" && second_parsed.asset_uri != "*") return false;
            if (second_parsed.asset_uri == "*" && first_parsed.asset_uri != "*") return true;

            if (first_parsed.asset_uri.empty()) return false;
            if (second_parsed.asset_uri.empty()) return true;

            if (second_parsed.asset_uri.find(first_parsed.asset_uri) != std::string::npos) return false;
            if (first_parsed.asset_uri.find(second_parsed.asset_uri) != std::string::npos) return true;

            if (first_parsed.asset_url.empty()) return false;
            if (second_parsed.asset_url.empty()) return false;

            return second < first;
        }

        std::vector<RulesConfigRulebase> rules_config;
    };

    RulesConfigWrapper(const std::vector<RulesConfigRulebase> &_rules_config)
        :
    rules_config_rulebase(RulesConfig(_rules_config))
    {}

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("rulebase", rules_config_rulebase)
        );
    }

private:
    RulesConfig rules_config_rulebase;
};
// LCOV_EXCL_STOP
#endif // __RULES_CONFIG_SECTION_H__
