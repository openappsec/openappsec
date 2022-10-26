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

// #define WAF2_LOGGING_ENABLE
#include "BehaviorAnalysis.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <set>
#include <functional>
#include <math.h>
#include <stdio.h>
#include <iostream>
#include <assert.h>

static const int BUCKET_SIZE = 300;

#define INITIAL_COUNT 1000
#define INITIAL_VARIANCE 100.0
#define INITIAL_MEAN 40.0

void TopBucket::addKeys(std::string& uri, std::string& ip, std::string& ua, std::string& ua_ip)
{
    m_ips.addKeys(ip);
    m_userAgents.addKeys(ua);
    m_ipUserAgents.addKeys(ua_ip);
}

void TopBucket::putAttack(std::string& url,
    double score,
    std::string& ip,
    std::string& ua,
    std::string& ua_ip,
    const std::string &location)
{
    // Only punish reputation is score is above 1.0 and attack location comes from specific places.
    // For example, avoid punishing reputation for attacks coming from referer_param, header, or cookie.
    if (score > 1.0 && (location == "url" || location == "url_param" || location=="body")) {
        m_ips.putAttack(true, score, ip);
        m_userAgents.putAttack(true, score, ua);
        m_ipUserAgents.putAttack(true, score, ua_ip);
    }
    getInfo(ip, ua, ua_ip);
}

void TopBucket::cleanSources()
{
    m_ips.cleanSources();
    m_userAgents.cleanSources();
    m_ipUserAgents.cleanSources();
}

void TopBucket::evaluateAvg()
{
    m_avgCount = m_ipUserAgents.getSourcesAvg();
}

bool TopBucket::isSourceEmpty(SourceType sourceType)
{
    switch (sourceType)
    {
    case IP_SOURCE_TYPE:
        return m_ips.empty();
    case UA_SOURCE_TYPE:
        return m_userAgents.empty();
    case UA_IP_SOURCE_TYPE:
        return m_ipUserAgents.empty();
    default:
        return false;
    }
}

double TopBucket::getAvgCount()
{
    return m_avgCount;
}

ReputationData TopBucket::getInfo(std::string& ip, std::string& ua, std::string& uaIp)
{
    ReputationData output;
    output.ipReputation = m_ips.getInfo(ip, m_avgCount);
    output.uaReputation = m_userAgents.getInfo(ua, m_avgCount);
    output.uaIpReputation = m_ipUserAgents.getInfo(uaIp, m_avgCount);

    output.absoluteReputation = (output.ipReputation.reputation + output.uaReputation.reputation +
        output.uaIpReputation.reputation) / 3;

    m_behaviorAnalyzer->updateAvrageAndVariance(output.absoluteReputation);

    output.relativeReputation = m_behaviorAnalyzer->getRelativeReputation(output.absoluteReputation);

    return output;
}

Source::Source() : sources()
{
}

Source::~Source()
{
    for (auto source : sources) {
        delete source.second;
    }
    sources.clear();
}

void Source::cleanSources()
{
    for (auto source = sources.begin(); source != sources.end();) {
        if (!source->second->to_remove) {
            source->second->to_remove = true;
            source++;
        }
        else {
            delete source->second;
            sources.erase(source++);
        }
    }
}

double Source::getSourcesAvg()
{
    unsigned int sum = 0;

    if (sources.empty())
    {
        return 0;
    }

    for (auto source : sources) {
        sum += source.second->countLegit;
    }

    return (double)sum / sources.size();
}

void Source::putAttack(bool missedUrl, double score, std::string& source)
{
    if (sources.find(source) == sources.end()) {
        sources[source] = new Counters(); // init counters to 0
    }

    assert(missedUrl != false || score > 0);

    if (missedUrl) {
        sources[source]->missed_urls++;
    }
    // Larger value slows down the absolute score reduction during attacks.
    const double velocity = 8;
    sources[source]->attacksScoreSum += round(score, 5) * velocity;
}

// TODO: rename
void Source::addKeys(std::string& source)
{
    if (sources.find(source) == sources.end()) {
        sources[source] = new Counters(); // init counters to 0
    }

    Counters* counters = sources[source];
    counters->countLegit++;
}

// assuming count>0 param>0 return value in range (0,100]:
// for count << param -> 100
// for count >> param -> 0
double Source::calcDiff(double count, double param)
{
    double res = (double)(int)((((param + 1) * 100)) / (param + count + 1));
    return res;
}

Source::Info Source::getInfo(std::string& source, double avgCount)
{
    double  missed_urls = 0.0, legit_vs_attacks = 0.0, reputation = 0.0, coverage = 0.0;

    if (source.find("to_remove") != std::string::npos) {
        sources[source]->to_remove = false;
    }

    if (sources.find(source) == sources.end()) {
        sources[source] = new Counters(); // init counters to 0
    }
    // range (0, 5/6*100]
    missed_urls = 100 - calcDiff(5, sources[source]->missed_urls);

    coverage = (int)((100 - calcDiff(4, 40)) * 4 / 5 + 60); // = 67.1111111111
    // range - [20, 100)
    // assuming avg count > 0 -> max(40 - avg, 1) => [1,40)
    // count -> 0 & attack -> 0 : legit/attack -> 20
    // count -> 0 & attack -> inf : legit/attack -> 20
    // count -> inf & attack -> 0 : legit/attack -> 100+

    double spcDiff = calcDiff(sources[source]->countLegit + std::max(40 - (int)avgCount, 1) + 20,
        sources[source]->attacksScoreSum * 4);

    legit_vs_attacks = (double)(100 - (spcDiff)) * 4 / 5 + 20;

    coverage = (int)((coverage + missed_urls) / 2);

    reputation = (double)(coverage * legit_vs_attacks * missed_urls) / 100 / 100;

    Source::Info info = { reputation, coverage, legit_vs_attacks,
    {sources[source]->countLegit, sources[source]->attacksScoreSum}};

    return info;
}

bool Source::empty()
{
    return sources.empty();
}

size_t Source::size() {
    return sources.size();
}

BehaviorAnalyzer::BehaviorAnalyzer() :
    m_count(INITIAL_COUNT),
    m_variance(INITIAL_VARIANCE),
    m_reputation_mean(INITIAL_MEAN)
{
}

BehaviorAnalyzer::~BehaviorAnalyzer()
{
    for (auto bucket : m_buckets) {
        delete bucket.second;
    }
    m_buckets.clear();
}

ReputationData BehaviorAnalyzer::analyze_behavior(BehaviorAnalysisInputData& data)
{
    ReputationData output;
    std::string &siteId = data.site_id;

    if (m_count % COUNTER_BACKUP_THRESHOLD == 0)
    {
        // TODO: backup

        // calculate average per bucket
        for (auto bucket : m_buckets) {
            bucket.second->evaluateAvg();
        }
        // reset
        for (auto bucket : m_buckets) {
            bucket.second->cleanSources();
        }
    }

    if (m_buckets.find(siteId) == m_buckets.end()){
        m_buckets[siteId] = new TopBucket(this);
    }

    std::string& source = data.source_identifier;
    std::string& userAgent = data.user_agent;
    std::string userAgentSource = userAgent + " " + source;

    if (data.keyword_matches.empty() == false)
    {
        // Two cases here:
        // 1. No probing - always punish reputation
        // 2. If there's probing - only punish if too many keyword matches (strong suspipion)
        if (data.keyword_matches.size() > 2 ||
            std::find(data.keyword_matches.begin(), data.keyword_matches.end(), "probing") ==
                data.keyword_matches.end())
        {
            // Punish reputation conditionally, see TopBucket::putAttack() for the details
            m_buckets[siteId]->putAttack(data.short_uri,
                data.score * data.fp_mitigation_score / 10,
                source,
                userAgent,
                userAgentSource,
                data.location);
        }
    }
    else
    {
        quickLearn(siteId, source, userAgent, data.uri);
    }

    output = m_buckets[siteId]->getInfo(source, userAgent, userAgentSource);

    return output;
}

bool BehaviorAnalyzer::isSourceEmpty(std::string siteId, SourceType sourceType)
{
    return m_buckets[siteId]->isSourceEmpty(sourceType);
}

void BehaviorAnalyzer::clearSources()
{
    for (auto bucket : m_buckets) {
        bucket.second->cleanSources();
    }
}

size_t BehaviorAnalyzer::getCount()
{
    return m_count;
}

double BehaviorAnalyzer::getAvgCount(std::string& siteId)
{
    if (m_buckets.find(siteId) == m_buckets.end())
    {
        return -1.0;
    }
    return m_buckets[siteId]->getAvgCount();
}

double BehaviorAnalyzer::getReputationMean() const
{
    return m_reputation_mean;
}

double BehaviorAnalyzer::getVariance() const
{
    return m_variance;
}

void BehaviorAnalyzer::quickLearn(std::string& siteId, std::string& source, std::string& userAgent, std::string& uri)
{
    if (m_buckets.find(siteId) == m_buckets.end())
    {
        m_buckets[siteId] = new TopBucket(this);
    }
    std::string userAgentSource = userAgent + " " + source;
    m_buckets[siteId]->addKeys(uri, source, userAgent, userAgentSource);
}

double BehaviorAnalyzer::getRelativeReputation(double reputation)
{
    // Larger value slows down the relative score reduction during attacks.
    const double viscosity = 0.15;

    double score = 0.0;
    double mean = (m_reputation_mean + 100) / 2;
    double standardDeviation = sqrt(m_variance); // variance is pow2 of standardDeviation
    standardDeviation = (standardDeviation / viscosity + 5) / 2;
    score = errorProbabilityScore((reputation - mean) / standardDeviation);
    return 10 * score;
}

double BehaviorAnalyzer::errorProbabilityScore(double score)
{
    double probScore = 0.5 + 0.5 * erf(score / 2);

    //round to 3 decimal points
    probScore = round(probScore, 3);

    return probScore;
}

void BehaviorAnalyzer::updateAvrageAndVariance(double reputation)
{
    double prev_mean = m_reputation_mean;
    if (reputation > 1.0)
    {
        m_reputation_mean = (double)(m_reputation_mean * m_count + reputation) / (m_count + 1L);

        // variance induction step
        m_variance = (m_variance * m_count + pow((reputation - prev_mean), 2)) / (m_count + 1)
            - pow((m_reputation_mean - prev_mean), 2);

        m_count++;
    }
}

Counters::Counters() : countLegit(0), attacksScoreSum(0.0), missed_urls(0), to_remove(false)
{
}

double round(double val, unsigned char precision) {
    unsigned int factor = pow(10, precision);

    return round(val * factor) / factor;
}

bool compareWithDelta(double rhs, double lhs, double delta) {
    return fabs(rhs - lhs) <= delta;
}


bool operator==(const ReputationData& lhs, const ReputationData& rhs)
{
    bool res = (lhs.ipReputation == rhs.ipReputation &&
        lhs.uaReputation == rhs.uaReputation &&
        lhs.uaIpReputation == rhs.uaIpReputation &&
        compareWithDelta(lhs.absoluteReputation, rhs.absoluteReputation, 0.0001) &&
        compareWithDelta(lhs.relativeReputation, rhs.relativeReputation, 0.0001 ));
    if (!res)
    {
        std::printf("lhs: {absolute rep: %f, reputation: %f} , rhs: {absolute rep: %f, reputation: %f}\n",
            lhs.absoluteReputation, lhs.relativeReputation, rhs.absoluteReputation, rhs.relativeReputation);
    }
    return res;
}


bool operator==(const Source::Info& lhs, const Source::Info& rhs)
{
    bool res = compareWithDelta(lhs.coverage, rhs.coverage, 0.0001) &&
        compareWithDelta(lhs.legitVsAttacks, rhs.legitVsAttacks, 0.0001) &&
        compareWithDelta(lhs.reputation, rhs.reputation, 0.0001) &&
        lhs.stats == rhs.stats;
    if (!res)
    {
        std::printf("\tlhs: {coverage: %f, legitVsAttack: %f, reputation: %f}\n",
            lhs.coverage, lhs.legitVsAttacks, lhs.reputation);
        std::printf("\trhs: {coverage: %f, legitVsAttack: %f, reputation: %f}\n",
            rhs.coverage, rhs.legitVsAttacks, rhs.reputation);
    }
    return res;
}

bool operator==(const Source::Stats& lhs, const Source::Stats& rhs) {
    bool res = (compareWithDelta(lhs.attacks, rhs.attacks, 0.0001) &&
        lhs.countLegit == rhs.countLegit);
    if (!res)
    {
        std::printf("\t\tlhs: {attacks: %f, count: %u}\n",
            lhs.attacks, lhs.countLegit);
        std::printf("\t\trhs: {attacks: %f, count: %u}\n",
            rhs.attacks, rhs.countLegit);
    }
    return res;
}
