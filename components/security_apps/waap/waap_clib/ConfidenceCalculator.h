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
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <algorithm>
#include "i_serialize.h"
#include <cereal/archives/json.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/list.hpp>
#include <cereal/types/utility.hpp>
#include "debug.h"
#include "Waf2Util.h"
#include <ostream>
#include "i_ignoreSources.h"
#include "TuningDecisions.h"

USE_DEBUG_FLAG(D_WAAP_CONFIDENCE_CALCULATOR);

class WaapComponent;

struct ConfidenceCalculatorParams
{
    size_t minSources;
    size_t minIntervals;
    std::chrono::minutes intervalDuration;
    double ratioThreshold;
    bool learnPermanently;

    template <class Archive>
    void serialize(Archive& ar)
    {
        size_t duration = intervalDuration.count();
        ar(cereal::make_nvp("minSources", minSources),
            cereal::make_nvp("minIntervals", minIntervals),
            cereal::make_nvp("intervalDuration", duration),
            cereal::make_nvp("ratioThreshold", ratioThreshold),
            cereal::make_nvp("learnPermanently", learnPermanently));
        intervalDuration = std::chrono::minutes(duration);
    }

    bool operator==(const ConfidenceCalculatorParams& other);
    friend std::ostream& operator<<(std::ostream& os, const ConfidenceCalculatorParams& ccp);
};

class ConfidenceCalculator : public SerializeToLocalAndRemoteSyncBase
{
public:
    typedef std::string Key;
    typedef std::string Val;
    template<typename K, typename V>
    using UMap = std::unordered_map<K, V>;
    // key -> val -> sources set
    typedef std::unordered_set<std::string> SourcesSet;
    typedef UMap<Val, SourcesSet> SourcesCounters;
    typedef UMap<Key, SourcesCounters> KeyValSourcesLogger;

    // key -> list of values sets
    typedef std::set<Val> ValuesSet;
    typedef std::pair<ValuesSet, size_t> ValueSetWithTime;
    typedef std::list<ValuesSet> ValuesList;
    typedef UMap<Key, ValuesList> WindowsConfidentValuesList;
    typedef UMap<Key, UMap<Val, double>> ConfidenceLevels;
    typedef UMap<Key, int> WindowsCounter;
    typedef UMap<Key, ValueSetWithTime> ConfidenceSet;

    ConfidenceCalculator(size_t minSources,
        size_t minIntervals,
        std::chrono::minutes intervalDuration,
        double ratioThreshold,
        const Val &nullObj,
        const std::string& backupPath,
        const std::string& remotePath,
        const std::string& assetId,
        TuningDecision* tuning = nullptr,
        I_IgnoreSources* ignoreSrc = nullptr);

    ~ConfidenceCalculator();

    void setOwner(const std::string& owner);

    void hardReset();
    void reset();
    bool reset(ConfidenceCalculatorParams& params);

    virtual bool postData();
    virtual void pullData(const std::vector<std::string>& files);
    virtual void processData();
    virtual void postProcessedData();
    virtual void pullProcessedData(const std::vector<std::string>& files);
    virtual void updateState(const std::vector<std::string>& files);

    virtual void serialize(std::ostream& stream);
    virtual void deserialize(std::istream& stream);

    void mergeFromRemote(const ConfidenceSet& remote_confidence_set, bool is_first_pull);

    bool is_confident(const Key &key, const Val &value) const;

    void calcConfidentValues();

    ValuesSet getConfidenceValues(const Key &key) const;
    size_t getLastConfidenceUpdate();

    void log(const Key &key, const Val &value, const std::string &source);

    void logSourceHit(const Key &key, const std::string &source);

    void calculateInterval();

    static void mergeConfidenceSets(ConfidenceSet& confidence_set,
                                    const ConfidenceSet& confidence_set_to_merge,
                                    size_t& last_indicators_update);
private:
    void loadVer0(cereal::JSONInputArchive& archive);
    void loadVer1(cereal::JSONInputArchive& archive);
    void loadVer2(cereal::JSONInputArchive& archive);
    void loadVer3(cereal::JSONInputArchive& archive);
    bool tryParseVersionBasedOnNames(
        cereal::JSONInputArchive& archive,
        const std::string &params_field_name,
        const std::string &indicators_update_field_name,
        const std::string &windows_summary_field_name,
        const std::string &confident_sets_field_name);
    void convertWindowSummaryToConfidenceLevel(const WindowsConfidentValuesList& windows);

    std::string getParamName(const Key& key);
    size_t sumSourcesWeight(const SourcesSet& sources);
    void mergeSourcesCounter(const Key& key, const SourcesCounters& counters);
    void removeBadSources(SourcesSet& sources, const std::vector<std::string>* badSources);

    ConfidenceCalculatorParams m_params;
    Val m_null_obj;
    KeyValSourcesLogger m_time_window_logger;
    KeyValSourcesLogger m_time_window_logger_backup;
    ConfidenceSet m_confident_sets;
    ConfidenceLevels m_confidence_level;
    WindowsCounter m_windows_counter;
    size_t m_last_indicators_update;
    I_IgnoreSources* m_ignoreSources;
    TuningDecision* m_tuning;
};
