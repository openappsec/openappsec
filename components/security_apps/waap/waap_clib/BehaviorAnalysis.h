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

#ifndef __WAF2_BEHAVIOR_H__f1edd27e
#define __WAF2_BEHAVIOR_H__f1edd27e

#include <string>
#include <vector>
#include <map>
#include <set>
#include <string.h>
#include <math.h>
#include <boost/noncopyable.hpp>

#define MAX_NUM_OF_KEYS_IN_COUNTER 100
#define COUNTER_BACKUP_THRESHOLD 200000
#define MAX_RELATIVE_REPUTATION 10.0


class Counters {
public:
    Counters();
    unsigned int countLegit;
    double attacksScoreSum;
    long int missed_urls;
    bool to_remove;
};

typedef enum _SourceType {
    IP_SOURCE_TYPE,
    UA_SOURCE_TYPE,
    UA_IP_SOURCE_TYPE
}SourceType;

class BehaviorAnalyzer;

class Source : public boost::noncopyable
{
public:

    typedef struct _Stats {
        unsigned int countLegit;
        double attacks;
    }Stats;
    typedef struct _Info {
        double reputation;
        double coverage;
        double legitVsAttacks;
        Source::Stats stats;
    }Info;

    Source();
    ~Source();

    void cleanSources();
    double getSourcesAvg();
    size_t size();

    void putAttack(bool missedUrl, double score, std::string& source);
    void addKeys(std::string& source);
    static double calcDiff(double count, double param);


    Info getInfo(std::string& source, double avgCount);

    // function for unit tests
    bool empty();

private:
    std::map<std::string, Counters*> sources; // key is either (source_ip) or (useragent+source_ip)
    //std::set<std::string> urls; // set of URLs visited by this source
};
#if 0
class Bucket {
public:
    size_t add(const std::string& key);
    void clean();
    bool exist(const std::string& key) const;
    size_t get(const std::string& key) const;
    size_t size() const { return _data.size(); }
private:
    std::map<std::string, size_t> _data;
};
#endif
typedef struct _ReputationData {
    Source::Info ipReputation;
    Source::Info uaReputation;
    Source::Info uaIpReputation;
    double relativeReputation; // the absolute reputation relative to the average
    double absoluteReputation;
}ReputationData;

double round(double val, unsigned char precision);

bool operator==(const Source::Stats& lhs, const Source::Stats& rhs);

bool operator==(const Source::Info& lhs, const Source::Info& rhs);

bool operator==(const ReputationData& lhs, const ReputationData& rhs);


class TopBucket {
private:
    Source m_ips;
    Source m_userAgents;
    Source m_ipUserAgents;
    BehaviorAnalyzer* m_behaviorAnalyzer;
    double m_avgCount;

public:
    TopBucket(BehaviorAnalyzer* behaviorAnalyzer) : m_behaviorAnalyzer(behaviorAnalyzer), m_avgCount(20) {}

    void addKeys(std::string& uri, std::string& ip, std::string& ua, std::string& ua_ip);
    void putAttack(std::string& uri,
        double score, std::string& ip,
        std::string& ua,
        std::string& ua_ip,
        const std::string& location);
    void cleanSources();
    void evaluateAvg();

    bool isSourceEmpty(SourceType sourceType);
    double getAvgCount();

    ReputationData getInfo(std::string& ip, std::string& ua, std::string& uaIp);
};


struct BehaviorAnalysisInputData {
    std::string site_id;
    std::string source_identifier;
    std::string user_agent;
    std::string short_uri; // data['short_uri'] (see fix_data_keys...)
    std::string uri; // data['uri'] (see fix_data_keys...)
    std::vector<std::string> keyword_matches;
    double score;
    double fp_mitigation_score; // calculated outside before analyze_behavior() !!!
    std::string location;
};

class BehaviorAnalyzer {
public:
    BehaviorAnalyzer();
    ~BehaviorAnalyzer();

    ReputationData analyze_behavior(BehaviorAnalysisInputData& data);

    void clearSources();

    void quickLearn(std::string& siteId, std::string& sourceIp, std::string& userAgent, std::string& uri);
    double getRelativeReputation(double reputation);
    void updateAvrageAndVariance(double reputation);

    // unit test related functions
    bool isSourceEmpty(std::string siteId, SourceType sourceType);
    size_t getCount();
    double getAvgCount(std::string& siteId);
    double getReputationMean() const;
    double getVariance() const;

private:
    double errorProbabilityScore(double score);
    // TODO: move to SMEM
    size_t m_count;
    double m_variance;
    double m_reputation_mean;
    std::map<std::string, TopBucket*> m_buckets;
};
#endif // __WAF2_BEHAVIOR_H__f1edd27e
