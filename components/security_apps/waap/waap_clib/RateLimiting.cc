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

#include <memory>
#include <chrono>
#include <boost/regex.hpp>

#include "RateLimiting.h"
#include "Waf2Engine.h"
#include "agent_core_utilities.h"

#define RATE_LIMITING_LRU_SIZE 10000

namespace Waap {
namespace RateLimiting {

bool Policy::getRateLimitingEnforcementStatus()
{
    return m_rateLimiting.enable;
}

bool
EntryKey::operator==(EntryKey const& other) const
{
    return url == other.url && source == other.source;
}

bool
Policy::RateLimitingEnforcement::operator==(const Policy::RateLimitingEnforcement &other) const
{
    return enable == other.enable;
}

bool
Policy::operator==(const Policy &other) const {
    return rules == other.rules && m_rateLimiting == other.m_rateLimiting;
}

bool
Policy::Rule::operator==(const Policy::Rule &other) const {
    return action == other.action && rate == other.rate &&
        sourceFilter == other.sourceFilter && uriFilter == other.uriFilter;
}

bool
Policy::Rule::Action::operator==(const Policy::Rule::Action &other) const {
    return quarantineTimeSeconds == other.quarantineTimeSeconds &&
        type == other.type;
}

bool
Policy::Rule::Rate::operator==(const Policy::Rule::Rate &other) const {
    return events == other.events && interval == other.interval;
}

bool
Policy::Rule::SourceFilter::operator==(const Policy::Rule::SourceFilter &other) const {
    if (!(groupBy == other.groupBy && scope == other.scope))
    {
        return false;
    }

    if (specific_source_regexes_pattern.size() != other.specific_source_regexes_pattern.size())
    {
        return false;
    }

    for(size_t i=0; i<specific_source_regexes_pattern.size(); i++)
    {
        if(specific_source_regexes_pattern[i] != other.specific_source_regexes_pattern[i])
        {
            return false;
        }
    }

    return true;
}

bool
Policy::Rule::UriFilter::operator==(const Policy::Rule::UriFilter &other) const {
    if (!(groupBy == other.groupBy && scope == other.scope))
    {
        return false;
    }

    if (specific_uri_regexes_pattern.size() != other.specific_uri_regexes_pattern.size())
    {
        return false;
    }

    for(size_t i=0; i<specific_uri_regexes_pattern.size(); i++)
    {
        if (specific_uri_regexes_pattern[i] != other.specific_uri_regexes_pattern[i])
        {
            return false;
        }
    }

    return true;
}

TrackEntry::TrackEntry(unsigned int events, std::chrono::seconds interval)
:eventRateLimiter(events, interval), state(MEASURING), quarantinedUntil()
{
}

bool
TrackEntry::event(std::chrono::seconds now)
{
    // Release temporary block when time arrives
    if (state == TrackEntry::State::QUARANTINED) {
        if (now >= quarantinedUntil) {
            // Release blocking state
            state = TrackEntry::State::MEASURING;
        }
    }

    // Count this event, the result will be true if rate limiter not saturated (should allow), or false if it
    // is (should block).
    return eventRateLimiter.event(now);
}

void
TrackEntry::quarantineUntil(std::chrono::seconds until)
{
    state = TrackEntry::State::QUARANTINED;
    quarantinedUntil = until;
}

bool
TrackEntry::isBlocked() const
{
    return state != TrackEntry::State::MEASURING;
}

State::State(const std::shared_ptr<Policy> &policy)
:policy(policy), perRuleTrackingTable()
{
    // For each rule create separate rate limiter states tracking table
    for (unsigned ruleId=0; ruleId < policy->rules.size(); ++ruleId) {
        perRuleTrackingTable.push_back(std::make_shared<EntriesLru>(RATE_LIMITING_LRU_SIZE));
    }
}

static bool
matchOneOfRegexes(const std::string& value, const std::vector<std::shared_ptr<boost::regex>> &regexesList)
{
    for (auto &regex : regexesList) {
        if (regex != nullptr && NGEN::Regex::regexMatch(__FILE__, __LINE__, value, *regex)) {
            return true;
        }
    }

    return false;
}

bool
State::execute(const std::string& sourceIdentifier, const std::string& uriStr, std::chrono::seconds now, bool& log)
{
    bool allow = true;
    log = false;

    // Run rules one by one.
    for (unsigned ruleId=0; ruleId < policy->rules.size(); ++ruleId) {
        const Policy::Rule &rule = policy->rules[ruleId];
        const Policy::Rule::UriFilter &uriFilter = rule.uriFilter;
        const Policy::Rule::SourceFilter &sourceFilter = rule.sourceFilter;
        const Policy::Rule::Rate &rate = rule.rate;
        const Policy::Rule::Action &action = rule.action;

        // Get rate limiter states tracking table specific to current rule
        std::shared_ptr<EntriesLru> table = perRuleTrackingTable[ruleId];

        // Build a key to look up an entry
        EntryKey entryKey;

        // Filter out unmatched Urls
        if (uriFilter.scope == Waap::RateLimiting::Policy::Rule::UriFilter::Scope::SPECIFIC
            && !matchOneOfRegexes(uriStr, uriFilter.specific_uri_regexes))
        {
            continue;
        }

        // Filter out unmatched Sources
        if (sourceFilter.scope == Waap::RateLimiting::Policy::Rule::SourceFilter::Scope::SPECIFIC
            && !matchOneOfRegexes(sourceIdentifier, sourceFilter.specific_source_regexes))
        {
            continue;
        }

        if (uriFilter.groupBy == Policy::Rule::UriFilter::GroupBy::URL) {
            // Include the HTTP source ID in the key
            entryKey.url = uriStr;
        }

        if (sourceFilter.groupBy == Policy::Rule::SourceFilter::GroupBy::SOURCE) {
            // Include the HTTP source ID in the key
            entryKey.source = sourceIdentifier;
        }

        // Find entry in LRU, or create new
        std::shared_ptr<TrackEntry> trackEntry;
        if (!table->get(entryKey, trackEntry)) {
            trackEntry = std::make_shared<TrackEntry>(rate.events, std::chrono::seconds(rate.interval));
        }

        // Insert or update an entry in LRU (this moves entry up if exist, or inserts new, possibly expiring old ones
        // to keep the LRU size under control).
        table->insert(std::make_pair(entryKey, trackEntry));

        // Count this event in the entry's rate limiter. Release temporary block if time arrived.
        if (trackEntry->event(now) == false) {
            // TrackEntry's rate limiter is saturated (too many requests) - act according to rule's Action
            switch (action.type) {
                case Policy::Rule::Action::Type::DETECT:
                    // log block action.
                    log = true;
                    // Detect
                    break;
                case Policy::Rule::Action::Type::QUARANTINE:
                    // Mark this entry blocked temorarily, for at least X seconds
                    trackEntry->quarantineUntil(now + std::chrono::seconds(action.quarantineTimeSeconds));
                    break;
                case Policy::Rule::Action::Type::RATE_LIMIT:
                    // log block action.
                    log = true;
                    // Block this event only
                    allow = false;
                    break;
            }
        }

        // If at least one of the rules says "block" - block the request
        if (trackEntry->isBlocked()) {
            // log block action.
            log = true;
            allow = false;
        }
    }

    return allow;
}

}
}
