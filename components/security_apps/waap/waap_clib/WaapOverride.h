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

#pragma once
#include <cereal/types/vector.hpp>
#include <boost/regex.hpp>
#include <boost/regex/pattern_except.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <vector>
#include <string>
#include <memory>
#include "debug.h"
#include "CidrMatch.h"
#include "DecisionType.h"
#include "RegexComparator.h"
#include "agent_core_utilities.h"

USE_DEBUG_FLAG(D_WAAP_OVERRIDE);

namespace Waap {
namespace Override {
using boost::algorithm::to_lower_copy;

class Match {
public:
    bool operator==(const Match &other) const;

    template <typename _A>
    void serialize(_A &ar) {
        // Read the value of "op"
        ar(cereal::make_nvp("operator", m_op));
        m_op = to_lower_copy(m_op);
        m_isCidr = false;
        m_value = "";
        m_isValid = true;

        if (m_op == "basic") {
            // If op == "BASIC" - read numeric value
            ar(cereal::make_nvp("tag", m_tag));
            m_tag = to_lower_copy(m_tag);

            if (m_tag != "sourceip" && m_tag != "sourceidentifier" && m_tag != "url" && m_tag != "hostname" &&
                m_tag != "keyword" && m_tag != "indicator" && m_tag != "paramname" && m_tag != "paramvalue" &&
                m_tag != "paramlocation" && m_tag != "responsebody" &&  m_tag != "headername" &&
                m_tag != "headervalue" && m_tag != "method") {
                m_isValid = false;
                dbgDebug(D_WAAP_OVERRIDE) << "Invalid override tag: " << m_tag;
            }

            try {
                ar(cereal::make_nvp("values", m_values));
                dbgDebug(D_WAAP_OVERRIDE) << "Values list is missing, using single value instead.";
            } catch (const cereal::Exception &e) {
                // The name "value" here is misleading. The real meaning is "regex pattern string"
                ar(cereal::make_nvp("value", m_value));
                m_values.insert(m_value);
            }

            if (m_tag == "sourceip" || m_tag == "sourceidentifier") {
                m_isCidr = true;
                m_ip_addr_values.resize(m_values.size());

                int val_idx = 0;
                for (const auto &cur_val : m_values) {
                    if (!Waap::Util::isCIDR(cur_val, m_ip_addr_values[val_idx])) {
                        dbgDebug(D_WAAP_OVERRIDE) << "Invalid value in list of IP addresses: " << cur_val;
                        m_isValid = false;
                        break;
                    }
                    val_idx++;
                }
                sortAndMergeCIDRs();
                dbgTrace(D_WAAP_OVERRIDE) << "CIDR list: " << cidrsToString(m_ip_addr_values);
            }
            m_isOverrideResponse = (m_tag == "responsebody" || m_tag == "responseBody");

            if (!m_isCidr) {
                for (const auto &cur_val : m_values) {
                    try {
                        m_valuesRegex.emplace(std::make_shared<boost::regex>(cur_val));
                    }
                    catch (const boost::regex_error &err) {
                        dbgDebug(D_WAAP_OVERRIDE)
                            << "Waap::Override::Match(): Failed to compile regex pattern '"
                            << cur_val
                            << "' on position "
                            << err.position()
                            <<  ". Reason: '"
                            << err.what()
                            << "'";
                        m_isValid = false;
                        m_valuesRegex.clear();
                        break;
                    }
                }
            }
        }
        else {
            // If op is "AND" or "OR" - get two operands
            if (m_op == "and" || m_op == "or") {
                m_operand1 = std::make_shared<Match>();
                ar(cereal::make_nvp("operand1", *m_operand1));
                m_operand2 = std::make_shared<Match>();
                ar(cereal::make_nvp("operand2", *m_operand2));
                m_isOverrideResponse = m_operand1->m_isOverrideResponse || m_operand2->m_isOverrideResponse;
                m_isValid = m_operand1->m_isValid && m_operand2->m_isValid;
            }
            else if (m_op == "not") {
                // If op is "NOT" get one operand
                m_operand1 = std::make_shared<Match>();
                ar(cereal::make_nvp("operand1", *m_operand1));
                m_isOverrideResponse = m_operand1->m_isOverrideResponse;
                m_isValid = m_operand1->m_isValid;
            }
            else {
                dbgDebug(D_WAAP_OVERRIDE) << "Invalid override operator: " << m_op;
                m_isValid = false;
            }
        }

        finalizeStructure();
    }

    template<typename TestFunctor>
    bool match(TestFunctor testFunctor) const {
        if (m_op == "basic" && m_isCidr) {
            bool result = testFunctor(m_tag, m_ip_addr_values);
            dbgTrace(D_WAAP_OVERRIDE)
                << "Override matching CIDR list: "
                << cidrsToString(m_ip_addr_values)
                << " result: "
                << result;
            return result;
        }
        else if (m_op == "basic" && !m_valuesRegex.empty()) {
            bool result = testFunctor(m_tag, m_valuesRegex);
            dbgTrace(D_WAAP_OVERRIDE)
                << "Override matching regex list: "
                << regexSetToString(m_valuesRegex)
                << " result: "
                << result;
            return result;
        }
        if (m_op == "and") {
            if (shouldDecomposeAnd()) {
                bool result = m_operand1->match(testFunctor) && m_operand2->match(testFunctor);
                dbgTrace(D_WAAP_OVERRIDE) << "Override matching decomposed AND result: " << result;
                return result;
            }
            bool needHdr = m_hasHdrPair;
            bool needPar = m_hasParPair;
            if (needHdr || needPar) {
                bool result = matchFamilyScoped(testFunctor, needHdr, needPar);
                dbgTrace(D_WAAP_OVERRIDE) << "Override family-scoped AND result: " << result;
                return result;
            }
            bool result = m_operand1->match(testFunctor) && m_operand2->match(testFunctor);
            dbgTrace(D_WAAP_OVERRIDE) << "Override matching logical AND result: " << result;
            return result;
        }
        if (m_op == "or") {
            bool result = m_operand1->match(testFunctor) || m_operand2->match(testFunctor);
            dbgTrace(D_WAAP_OVERRIDE) << "Override matching logical OR result: " << result;
            return result;
        }
        if (m_op == "not") {
            bool result = !m_operand1->match(testFunctor);
            dbgTrace(D_WAAP_OVERRIDE) << "Override matching logical NOT result: " << result;
            return result;
        }

        // unknown operator. this should not occur
        dbgDebug(D_WAAP_OVERRIDE) << "Invalid override operator " << m_op;
        return false;
    }

    bool isOverrideResponse() const { return m_isOverrideResponse; }

    bool isValidMatch() const { return m_isValid; }

    template<typename TestFunctor>
    bool matchPositional(
        TestFunctor &f,
        bool isHeader,
        const std::string &boundName,
        const std::string &boundValue) const
    {
        const std::pair<std::string, std::string> bound(boundName, boundValue);
        return isHeader ? matchBound(f, &bound, nullptr) : matchBound(f, nullptr, &bound);
    }

    template<typename TestFunctor>
    bool matchBound(
        TestFunctor &f,
        const std::pair<std::string, std::string> *hdr,
        const std::pair<std::string, std::string> *par) const
    {
        if (m_op == "basic") {
            if (m_isCidr) return f(m_tag, m_ip_addr_values);
            const std::string *bound = nullptr;
            if (hdr != nullptr && m_tag == hdrNameTag()) bound = &hdr->first;
            else if (hdr != nullptr && m_tag == hdrValueTag()) bound = &hdr->second;
            else if (par != nullptr && m_tag == parNameTag()) bound = &par->first;
            else if (par != nullptr && m_tag == parValueTag()) bound = &par->second;
            if (bound == nullptr) return f(m_tag, m_valuesRegex);
            boost::cmatch what;
            for (const auto &rx : m_valuesRegex) {
                if (NGEN::Regex::regexMatch(__FILE__, __LINE__, bound->c_str(), what, *rx)) return true;
            }
            return false;
        }
        if (m_op == "and") {
            return m_operand1->matchBound(f, hdr, par) && m_operand2->matchBound(f, hdr, par);
        }
        if (m_op == "or") {
            return m_operand1->matchBound(f, hdr, par) || m_operand2->matchBound(f, hdr, par);
        }
        if (m_op == "not") {
            return !m_operand1->match(f);
        }
        return false;
    }

private:
    static const std::string &hdrNameTag()  { static const std::string t = "headername";  return t; }
    static const std::string &hdrValueTag() { static const std::string t = "headervalue"; return t; }
    static const std::string &parNameTag()  { static const std::string t = "paramname";   return t; }
    static const std::string &parValueTag() { static const std::string t = "paramvalue";  return t; }

    template<typename TestFunctor>
    bool matchFamilyScoped(TestFunctor &f, bool needHdr, bool needPar) const {
        if (needHdr && needPar) {
            const auto &hdrs = f.getHeaderPairs();
            const auto &pars = f.getParamPairs();
            for (const auto &h : hdrs) {
                if (!matchBound(f, &h, nullptr)) continue;
                for (const auto &p : pars) {
                    if (matchBound(f, &h, &p)) return true;
                }
            }
            return false;
        }
        if (needHdr) {
            const auto &hdrs = f.getHeaderPairs();
            for (const auto &h : hdrs) {
                if (matchBound(f, &h, nullptr)) return true;
            }
            return false;
        }
        const auto &pars = f.getParamPairs();
        for (const auto &p : pars) {
            if (matchBound(f, nullptr, &p)) return true;
        }
        return false;
    }

    struct PairCounts {
        unsigned hN = 0;
        unsigned hV = 0;
        unsigned pN = 0;
        unsigned pV = 0;
    };

    unsigned countLeavesWithTag(const std::string &tag) const {
        if (tag == hdrNameTag()) return m_leaves.hN;
        if (tag == hdrValueTag()) return m_leaves.hV;
        if (tag == parNameTag()) return m_leaves.pN;
        if (tag == parValueTag()) return m_leaves.pV;
        return 0u;
    }

    bool containsPair(const std::string &nameTag, const std::string &valueTag) const {
        return countLeavesWithTag(nameTag) > 0 && countLeavesWithTag(valueTag) > 0;
    }

    bool hasFullPair() const { return m_hasHdrPair || m_hasParPair; }

    bool shouldDecomposeAnd() const { return m_shouldDecompose; }

    bool splitsFamily(unsigned nameLeaves, unsigned valueLeaves, bool op1Full, bool op2Full) const {
        if (nameLeaves == 0 || valueLeaves == 0) return false;
        return !op1Full && !op2Full;
    }

    void finalizeStructure() {
        if (m_op == "basic" && !m_isCidr) {
            m_leaves.hN = (m_tag == hdrNameTag()) ? 1u : 0u;
            m_leaves.hV = (m_tag == hdrValueTag()) ? 1u : 0u;
            m_leaves.pN = (m_tag == parNameTag()) ? 1u : 0u;
            m_leaves.pV = (m_tag == parValueTag()) ? 1u : 0u;
            m_andLeaves = m_leaves;
        } else {
            const PairCounts z;
            const PairCounts &a = m_operand1 ? m_operand1->m_leaves : z;
            const PairCounts &b = m_operand2 ? m_operand2->m_leaves : z;
            m_leaves.hN = a.hN + b.hN;
            m_leaves.hV = a.hV + b.hV;
            m_leaves.pN = a.pN + b.pN;
            m_leaves.pV = a.pV + b.pV;
            if (m_op == "and" && m_operand1 && m_operand2) {
                m_andLeaves.hN = m_operand1->m_andLeaves.hN + m_operand2->m_andLeaves.hN;
                m_andLeaves.hV = m_operand1->m_andLeaves.hV + m_operand2->m_andLeaves.hV;
                m_andLeaves.pN = m_operand1->m_andLeaves.pN + m_operand2->m_andLeaves.pN;
                m_andLeaves.pV = m_operand1->m_andLeaves.pV + m_operand2->m_andLeaves.pV;
            } else {
                m_andLeaves = PairCounts();
            }
        }
        m_hasHdrPair = m_leaves.hN > 0 && m_leaves.hV > 0;
        m_hasParPair = m_leaves.pN > 0 && m_leaves.pV > 0;

        m_shouldDecompose = false;
        if (m_op == "and" && m_operand1 && m_operand2) {
            if (m_operand1->hasFullPair() || m_operand2->hasFullPair()) {
                bool hdrSplit = splitsFamily(m_leaves.hN, m_leaves.hV,
                    m_operand1->m_hasHdrPair, m_operand2->m_hasHdrPair);
                bool parSplit = splitsFamily(m_leaves.pN, m_leaves.pV,
                    m_operand1->m_hasParPair, m_operand2->m_hasParPair);
                m_shouldDecompose = !hdrSplit && !parSplit;
            } else {
                m_shouldDecompose = m_andLeaves.hN > 1 || m_andLeaves.hV > 1
                    || m_andLeaves.pN > 1 || m_andLeaves.pV > 1;
            }
        }
    }

    void sortAndMergeCIDRs() {
        if (m_ip_addr_values.empty()) return;
        std::sort(m_ip_addr_values.begin(), m_ip_addr_values.end());

        size_t mergedIndex = 0;
        for (size_t i = 1; i < m_ip_addr_values.size(); ++i) {
            Waap::Util::CIDRData &current = m_ip_addr_values[mergedIndex];
            Waap::Util::CIDRData &next = m_ip_addr_values[i];

            if (!doesFirstCidrContainSecond(current, next)) {
                ++mergedIndex;
                if (i != mergedIndex) m_ip_addr_values[mergedIndex] = next;
            }
        }

        m_ip_addr_values.resize(mergedIndex + 1);
    }

    PairCounts m_leaves;
    PairCounts m_andLeaves;
    bool m_hasHdrPair = false;
    bool m_hasParPair = false;
    bool m_shouldDecompose = false;

    std::string m_op;
    std::shared_ptr<Match> m_operand1;
    std::shared_ptr<Match> m_operand2;
    std::string m_tag;
    std::string m_value;
    std::set<std::string> m_values;
    std::vector<Waap::Util::CIDRData> m_ip_addr_values;
    std::set<std::shared_ptr<boost::regex>, Waap::Util::RegexComparator> m_valuesRegex;
    bool m_isCidr;
    bool m_isOverrideResponse;
    bool m_isValid;
};

class Behavior
{
public:
    Behavior();
    bool operator==(const Behavior &other) const;

    template <typename _A>
    void serialize(_A &ar) {
        try
        {
            ar(cereal::make_nvp("action", m_action));
            m_action = to_lower_copy(m_action);
        }
        catch (std::runtime_error& e) {
            ar.setNextName(nullptr);
            m_action = "";
        }

        try
        {
            ar(cereal::make_nvp("log", m_log));
            m_log = to_lower_copy(m_log);
        }
        catch (const std::runtime_error& e) {
            ar.setNextName(nullptr);
            m_log = "";
        }

        try
        {
            ar(cereal::make_nvp("httpSourceId", m_sourceIdentifier));
        }
        catch (const std::runtime_error & e) {
            ar.setNextName(nullptr);
            m_sourceIdentifier = "";
        }

        if (!m_log.size() && !m_action.size() && !m_sourceIdentifier.size())
        {
            dbgDebug(D_WAAP_OVERRIDE) << "Override does not contain any relevant action";
        }
    }

    const std::string &getParentId() const;
    const std::string &getAction() const;
    const std::string &getLog() const;
    const std::string &getSourceIdentifier() const;
    void setParentId(const std::string& id);
private:
    std::string m_id;
    std::string m_action;
    std::string m_log;
    std::string m_sourceIdentifier;
};

class Rule {
public:

    Rule(): m_match(), m_isChangingRequestData(false), isValid(true){}

    bool operator==(const Rule &other) const;

    template <typename _A>
    void serialize(_A &ar) {
        try {
            ar(cereal::make_nvp("parsedMatch", m_match));
        }
        catch(const cereal::Exception &e)
        {
            dbgDebug(D_WAAP_OVERRIDE) << "An override rule was not loaded, parsedMatch error:" << e.what();
            isValid = false;
        }

        try {
            ar(cereal::make_nvp("id", m_id));
        }
        catch (const cereal::Exception &e)
        {
            dbgDebug(D_WAAP_OVERRIDE) << "An override rule has no id.";
            m_id.clear();
        }
        if (!m_match.isValidMatch()) {
            dbgDebug(D_WAAP_OVERRIDE) << "An override rule was not load";
            isValid = false;
        }

        ar(cereal::make_nvp("parsedBehavior", m_behaviors));

        m_isChangingRequestData = false;

        for (std::vector<Waap::Override::Behavior>::iterator it = m_behaviors.begin();
            it != m_behaviors.end();
            ++it)
        {
            Behavior& behavior = *it;
            behavior.setParentId(m_id);
            if (!behavior.getSourceIdentifier().empty()) // this rule changes data in request itself
            {
                m_isChangingRequestData = true;
                break;
            }
        }
    }

    template<typename TestFunctor>
    void match(TestFunctor testFunctor, std::vector<Behavior> &matchedBehaviors,
        std::set<std::string> &matchedOverrideIds) const
    {
        if (m_match.match(testFunctor)) {
            // extend matchedBehaviors list with all behaviors on this rule
            std::string overrideId = getId();
            dbgTrace(D_WAAP_OVERRIDE) << "Override rule matched id: " << overrideId <<
                ". Adding " << m_behaviors.size() << " new behaviors:";
            if (!overrideId.empty()) {
                matchedOverrideIds.insert(overrideId);
            }
            for (const Behavior &behavior : m_behaviors) {
                dbgTrace(D_WAAP_OVERRIDE) << "Behavior: action='" << behavior.getAction() << "', log='" <<
                    behavior.getLog() << "', sourceIdentifier='" << behavior.getSourceIdentifier() << "'";
                matchedBehaviors.push_back(behavior);
            }
            return;
        }
        dbgTrace(D_WAAP_OVERRIDE) << "Rule not matched";
    }


    bool isChangingRequestData() const {
        return m_isChangingRequestData;
    }
    bool isOverrideResponse() const {
        return m_match.isOverrideResponse();
    }

    const std::string &getId() const {
        return m_id;
    }

    bool isValidRule() const {
        return isValid;
    }

private:
    Match m_match;
    bool  m_isChangingRequestData;
    std::vector<Behavior> m_behaviors;
    std::string m_id;
    bool isValid;
};

class ExceptionsByPractice
{
public:
    template <typename _A>
    void serialize(_A& ar)
    {
        ar(
            cereal::make_nvp("WebApplicationExceptions", m_web_app_ids),
            cereal::make_nvp("APIProtectionExceptions", m_api_protect_ids),
            cereal::make_nvp("AntiBotExceptions", m_anti_bot_ids)
        );
        m_all_ids.insert(m_web_app_ids.begin(), m_web_app_ids.end());
        m_all_ids.insert(m_api_protect_ids.begin(), m_api_protect_ids.end());
        m_all_ids.insert(m_anti_bot_ids.begin(), m_anti_bot_ids.end());
    }

    bool operator==(const ExceptionsByPractice &other) const;
    const std::vector<std::string>& getExceptionsOfPractice(DecisionType practiceType) const;
    const std::set<std::string>& getAllExceptions() const;
    bool isIDInWebApp(const std::string &id) const;
private:
    std::vector<std::string> m_web_app_ids;
    std::vector<std::string> m_api_protect_ids;
    std::vector<std::string> m_anti_bot_ids;
    std::set<std::string> m_all_ids;
};

class Policy {
public:
    template <typename _A>
    Policy(_A &ar) {
        try {
            ar(
                cereal::make_nvp("exceptionsPerPractice", m_exceptionsByPractice)
            );
        }
        catch (std::runtime_error & e) {
            ar.setNextName(nullptr);
            dbgInfo(D_WAAP_OVERRIDE) << "Failed to load exceptions per practice, error: ", e.what();
            m_exceptionsByPractice = ExceptionsByPractice();
        }
        std::vector<Waap::Override::Rule> rules;
        ar(cereal::make_nvp("overrides", rules));
        m_isOverrideResponse = false;
        for (std::vector<Waap::Override::Rule>::const_iterator it = rules.begin(); it != rules.end(); ++it) {
            const Waap::Override::Rule& rule = *it;
            if (!rule.isValidRule()) {
                dbgWarning(D_WAAP_OVERRIDE) << "rule is not valid";
                continue;
            }
            if (rule.isChangingRequestData())
            {
                m_RequestOverrides.push_back(rule);
            }
            else
            {
                m_ResponseOverrides.push_back(rule);
            }
            m_isOverrideResponse |= rule.isOverrideResponse();
        }
    }

    bool operator==(const Policy &other) const;

    template <typename TestFunctor>
    void match(TestFunctor &testFunctor, std::vector<Behavior> &matchedBehaviors, bool requestOverrides,
        std::set<std::string> &matchedOverrideIds) const
    {
        // Run all rules and collect matched behaviors

        const std::vector<Waap::Override::Rule>& rules = requestOverrides ? m_RequestOverrides : m_ResponseOverrides;
        dbgTrace(D_WAAP_OVERRIDE) << "Start matching override rules ...";
        for (const Waap::Override::Rule &rule : rules) {
            if (m_exceptionsByPractice.getAllExceptions().size() > 0 &&
                !m_exceptionsByPractice.isIDInWebApp(rule.getId())
            ) {
                dbgInfo(D_WAAP_OVERRIDE)
                << "match rule id is not in web application exceptions by practice: "
                << rule.getId();
                continue;
            }
            dbgTrace(D_WAAP_OVERRIDE) << "Matching override rule ...";
            rule.match(testFunctor, matchedBehaviors, matchedOverrideIds);
        }
        dbgTrace(D_WAAP_OVERRIDE) << "Finished matching override rules.";
    }

    bool isOverrideResponse() const {
        return m_isOverrideResponse;
    }

    bool isValidRules() {
        return !m_RequestOverrides.empty() || !m_ResponseOverrides.empty();
    }

    const ExceptionsByPractice& getExceptionsByPractice() const {
        return m_exceptionsByPractice;
    }
private:
    std::vector<Waap::Override::Rule> m_RequestOverrides; //overrides that change request data
    std::vector<Waap::Override::Rule> m_ResponseOverrides; //overrides that change response/log data
    ExceptionsByPractice m_exceptionsByPractice;
    bool m_isOverrideResponse;
};

struct State {
    // whether to force block regardless of stage2 response (and even if bSendRequest and/or bSendResponse are false)
    bool bForceBlock;
    std::set<std::string> forceBlockIds;
    // exception (allow) was matched, so this request won't be blocked.
    bool bForceException;
    std::set<std::string> forceExceptionIds;
    // overrides decision in case log should be ignored
    bool bSupressLog;
    // user identfier override to be applied
    bool bSourceIdentifierOverride;
    std::string sSourceIdentifierMatch;

    State();

    // Compute overrides from override policy
    template<typename Functor>
    void applyOverride(const Waap::Override::Policy &policy, Functor functor,
        std::set<std::string> &matchedOverrideIds, bool requestOverrides)
    {
        // Collect all behaviors from matched rules
        std::vector<Waap::Override::Behavior> matchedBehaviors;
        policy.match(functor, matchedBehaviors, requestOverrides, matchedOverrideIds);

        dbgTrace(D_WAAP_OVERRIDE) << "applyOverride(): " << matchedBehaviors.size() << " detected override actions";

        // Apply all detected behaviors
        for (auto &matchedBehavior : matchedBehaviors) {
            dbgTrace(D_WAAP_OVERRIDE) << "applyOverride(): found override action: " << matchedBehavior.getAction();
            if (matchedBehavior.getAction() == "accept") {
                dbgTrace(D_WAAP_OVERRIDE) << "applyOverride(): setting bForceException due to override behavior.";
                bForceException = true;
                forceExceptionIds.insert(matchedBehavior.getParentId());
            }
            else if (matchedBehavior.getAction() == "reject") {
                dbgTrace(D_WAAP_OVERRIDE) << "applyOverride(): setting bForceBlock due to override behavior.";
                bForceBlock = true;
                forceBlockIds.insert(matchedBehavior.getParentId());
            }

            if (matchedBehavior.getLog() == "ignore")
            {
                dbgTrace(D_WAAP_OVERRIDE) << "applyOverride(): setting bSupressLog due to override behavior.";
                bSupressLog = true;
            }

            sSourceIdentifierMatch = matchedBehavior.getSourceIdentifier();
            if (sSourceIdentifierMatch.size())
            {
                dbgTrace(D_WAAP_OVERRIDE) << "applyOverride(): setting bSourceIdentifier -"
                    << "Override due to override behavior: "
                    << sSourceIdentifierMatch.c_str();
                bSourceIdentifierOverride = true;
            }
        }
    }
};

}
}
