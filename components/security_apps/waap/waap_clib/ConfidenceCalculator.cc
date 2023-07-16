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

#include "ConfidenceCalculator.h"
#include <cereal/types/unordered_set.hpp>
#include "waap.h"
#include "ConfidenceFile.h"
#include "i_agent_details.h"
#include "i_messaging.h"
#include "i_mainloop.h"
#include <math.h>

USE_DEBUG_FLAG(D_WAAP);

#define SYNC_WAIT_TIME std::chrono::seconds(300) // 5 minutes in seconds
#define SCORE_THRESHOLD 100.0
#define BUSY_WAIT_TIME std::chrono::microseconds(100000) // 0.1 seconds
#define WAIT_LIMIT 10
#define BENIGN_PARAM_FACTOR 2

double logn(double x, double n)
{
    return std::log(x) / std::log(n);
}

ConfidenceCalculator::ConfidenceCalculator(size_t minSources,
    size_t minIntervals,
    std::chrono::minutes intervalDuration,
    double ratioThreshold,
    const Val &nullObj,
    const std::string &backupPath,
    const std::string &remotePath,
    const std::string &assetId,
    TuningDecision* tuning,
    I_IgnoreSources* ignoreSrc) :
    SerializeToLocalAndRemoteSyncBase(intervalDuration,
        SYNC_WAIT_TIME,
        backupPath,
        (remotePath == "") ? remotePath : remotePath + "/Confidence",
        assetId,
        "ConfidenceCalculator"),
    m_params({ minSources, minIntervals, intervalDuration, ratioThreshold, true }),
    m_null_obj(nullObj),
    m_time_window_logger(),
    m_confident_sets(),
    m_confidence_level(),
    m_last_indicators_update(0),
    m_ignoreSources(ignoreSrc),
    m_tuning(tuning)
{
    restore();
}

ConfidenceCalculator::~ConfidenceCalculator()
{
    m_time_window_logger.clear();
    m_confident_sets.clear();
}

void ConfidenceCalculator::hardReset()
{
    m_time_window_logger.clear();
    m_confidence_level.clear();
    m_confident_sets.clear();
    std::remove(m_filePath.c_str());
}


void ConfidenceCalculator::reset()
{
    m_time_window_logger.clear();
    if (!m_params.learnPermanently)
    {
        hardReset();
    }
}

bool ConfidenceCalculator::reset(ConfidenceCalculatorParams& params)
{
    if (params == m_params)
    {
        return false;
    }
    dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -"
        " resetting the ConfidenceCalculatorParams: " << params;
    m_params = params;
    reset();
    setInterval(m_params.intervalDuration);
    return true;
}


class WindowLogPost : public RestGetFile
{
public:
    WindowLogPost(ConfidenceCalculator::KeyValSourcesLogger& _window_logger)
        : window_logger(_window_logger)
    {
    }

private:
    C2S_PARAM(ConfidenceCalculator::KeyValSourcesLogger, window_logger)
};

class WindowLogGet : public RestGetFile
{
public:
    WindowLogGet() : window_logger()
    {
    }

    Maybe<ConfidenceCalculator::KeyValSourcesLogger> getWindowLogger()
    {
        return window_logger.get();
    }

private:
    S2C_PARAM(ConfidenceCalculator::KeyValSourcesLogger, window_logger)
};

bool ConfidenceCalculator::postData()
{
    m_time_window_logger_backup = m_time_window_logger;
    m_time_window_logger.clear();
    std::string url = getPostDataUrl();

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Sending the data to: " << url;

    WindowLogPost currentWindow(m_time_window_logger_backup);
    bool ok = sendNoReplyObjectWithRetry(currentWindow,
        I_Messaging::Method::PUT,
        url);
    if (!ok) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to post collected data to: " << url;
    }
    return ok;
}

void ConfidenceCalculator::pullData(const std::vector<std::string>& files)
{
    if (getIntervalsCount() == m_params.minIntervals)
    {
        mergeProcessedFromRemote();
    }
    std::string url = getPostDataUrl();
    std::string sentFile = url.erase(0, strlen("/storage/waap/"));
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "pulling files, skipping: " << sentFile;
    for (auto file : files)
    {
        if (file == sentFile)
        {
            continue;
        }
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Pulling the file: " << file;
        WindowLogGet getWindow;
        bool ok = sendObjectWithRetry(getWindow,
            I_Messaging::Method::GET,
            getUri() + "/" + file);

        if (!ok) {
            dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get file: " << file;
            continue;
        }

        KeyValSourcesLogger remoteLogger = getWindow.getWindowLogger().unpack();
        for (auto& log : remoteLogger)
        {
            std::string key = log.first;
            for (auto& entry : log.second)
            {
                std::string value = entry.first;
                for (auto& source : entry.second)
                {
                    m_time_window_logger_backup[key][value].insert(source);
                }
            }
        }
    }
}

void ConfidenceCalculator::processData()
{
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " - processing the confidence data";
    if (m_time_window_logger_backup.empty())
    {
        m_time_window_logger_backup = m_time_window_logger;
        m_time_window_logger.clear();
    }
    calculateInterval();
}

void ConfidenceCalculator::updateState(const std::vector<std::string>& files)
{
    pullProcessedData(files);
}

void ConfidenceCalculator::pullProcessedData(const std::vector<std::string>& files)
{
    dbgTrace(D_WAAP) << "Fetching the confidence set object";
    bool is_first_pull = true;
    bool is_ok = false;
    for (auto file : files)
    {
        ConfidenceFileDecryptor getConfFile;
        bool res = sendObjectWithRetry(getConfFile,
            I_Messaging::Method::GET,
            getUri() + "/" + file);
        is_ok |= res;
        if (res && getConfFile.getConfidenceSet().ok())
        {
            mergeFromRemote(getConfFile.getConfidenceSet().unpack(), is_first_pull);
            is_first_pull = false;
        }
        if (res && getConfFile.getConfidenceLevels().ok())
        {
            m_confidence_level = getConfFile.getConfidenceLevels().unpackMove();
        }
    }
    // is_ok = false -> no file was downloaded and merged
    if (!is_ok) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get the remote state";
    }
}

void ConfidenceCalculator::postProcessedData()
{
    if (getIntervalsCount() < m_params.minIntervals)
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Not sending the processed data - not enough windows";
        return;
    }
    std::string postUrl = getUri() + "/" + m_remotePath + "/processed/confidence.data";
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Posting the confidence set object to: " << postUrl;
    ConfidenceFileEncryptor postConfFile(m_confident_sets, m_confidence_level);
    sendNoReplyObjectWithRetry(postConfFile,
        I_Messaging::Method::PUT,
        postUrl);
}

void ConfidenceCalculator::serialize(std::ostream& stream)
{
    cereal::JSONOutputArchive archive(stream);

    archive(
        cereal::make_nvp("version", 3),
        cereal::make_nvp("params", m_params),
        cereal::make_nvp("last_indicators_update", m_last_indicators_update),
        cereal::make_nvp("confidence_levels", m_confidence_level),
        cereal::make_nvp("confident_sets", m_confident_sets)
    );
}
void ConfidenceCalculator::deserialize(std::istream& stream)
{
    size_t version;
    cereal::JSONInputArchive archive(stream);
    try
    {
        archive(cereal::make_nvp("version", version));
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        version = 0;
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to load the file version: " << e.what();
    }
    switch (version)
    {
    case 3:
        loadVer3(archive);
        break;
    case 2:
        loadVer2(archive);
        break;
    case 1:
        loadVer1(archive);
        break;
    case 0:
        loadVer0(archive);
        break;
    default:
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to deserialize, unknown version: " << version;
        break;
    }
}

void ConfidenceCalculator::loadVer0(cereal::JSONInputArchive& archive)
{
    if (!tryParseVersionBasedOnNames(
        archive,
        std::string("params"),
        std::string("last_indicators_update"),
        std::string("windows_summary_list"),
        std::string("confident_sets")
    ))
    {
        tryParseVersionBasedOnNames(
            archive,
            std::string("m_params"),
            std::string("m_lastIndicatorsUpdate"),
            std::string("m_windows_summary_list"),
            std::string("m_confident_sets")
        );
    }

}

void ConfidenceCalculator::convertWindowSummaryToConfidenceLevel(const WindowsConfidentValuesList& windows)
{
    for (const auto& windowKey : windows)
    {
        for (const auto& window : windowKey.second)
        {
            for (const auto& value : window)
            {
                m_confidence_level[windowKey.first][value] += std::ceil(SCORE_THRESHOLD / m_params.minIntervals);
            }
        }
    }
}

void ConfidenceCalculator::loadVer2(cereal::JSONInputArchive& archive)
{
    ConfidenceCalculatorParams params;
    ConfidenceSet confidenceSets;
    ConfidenceLevels confidenceLevels;
    archive(
        cereal::make_nvp("params", params),
        cereal::make_nvp("last_indicators_update", m_last_indicators_update),
        cereal::make_nvp("confidence_levels", confidenceLevels),
        cereal::make_nvp("confident_sets", confidenceSets)
    );
    reset(params);
    for (auto& confidentSet : confidenceSets)
    {
        m_confident_sets[normalize_param(confidentSet.first)] = confidentSet.second;
    }
    for (auto& confidenceLevel : confidenceLevels)
    {
        std::string normParam = normalize_param(confidenceLevel.first);
        if (m_confidence_level.find(normParam) == m_confidence_level.end())
        {
            m_confidence_level[normParam] = confidenceLevel.second;
        }
        else
        {
            for (auto& valueLevelItr : confidenceLevel.second)
            {
                if (m_confidence_level[normParam].find(valueLevelItr.first) == m_confidence_level[normParam].end())
                {
                    m_confidence_level[normParam][valueLevelItr.first] = valueLevelItr.second;
                }
                else
                {
                    double maxScore = std::max(m_confidence_level[normParam][valueLevelItr.first],
                        valueLevelItr.second);
                    m_confidence_level[normParam][valueLevelItr.first] = maxScore;
                }
            }
        }
    }
}

void ConfidenceCalculator::loadVer3(cereal::JSONInputArchive& archive)
{
    ConfidenceCalculatorParams params;
    archive(
        cereal::make_nvp("params", params),
        cereal::make_nvp("last_indicators_update", m_last_indicators_update),
        cereal::make_nvp("confidence_levels", m_confidence_level),
        cereal::make_nvp("confident_sets", m_confident_sets)
    );
    reset(params);
}


void ConfidenceCalculator::loadVer1(cereal::JSONInputArchive& archive)
{
    WindowsConfidentValuesList windows_summary_list;
    ConfidenceCalculatorParams params;

    archive(
        cereal::make_nvp("params", params),
        cereal::make_nvp("last_indicators_update", m_last_indicators_update),
        cereal::make_nvp("windows_summary_list", windows_summary_list),
        cereal::make_nvp("confident_sets", m_confident_sets)
    );
    reset(params);

    convertWindowSummaryToConfidenceLevel(windows_summary_list);
}

bool ConfidenceCalculator::tryParseVersionBasedOnNames(
    cereal::JSONInputArchive& archive,
    const std::string &params_field_name,
    const std::string &indicators_update_field_name,
    const std::string &windows_summary_field_name,
    const std::string &confident_sets_field_name)
{
    bool result = true;
    try
    {
        ConfidenceCalculatorParams temp_params;
        archive(cereal::make_nvp(params_field_name, temp_params));
        reset(temp_params);
        m_params = temp_params;
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to load configuration of WAAP parameters from the learned data file: "
            << e.what();
        result = false;
    }

    try
    {
        size_t temp_last_indicator_update = 0;
        archive(cereal::make_nvp(indicators_update_field_name, temp_last_indicator_update));
        m_last_indicators_update = temp_last_indicator_update;
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to load the update date for indicators from the learned data file: "
            << e.what();
        result = false;
    }

    try
    {
        WindowsConfidentValuesList temp_windows_summary_list;
        archive(cereal::make_nvp(windows_summary_field_name, temp_windows_summary_list));
        convertWindowSummaryToConfidenceLevel(temp_windows_summary_list);
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to load windows summary list from the learned data file: " << e.what();
        result = false;
    }

    try
    {
        std::unordered_map<Key, ValuesSet> temp_confident_sets;
        archive(cereal::make_nvp(confident_sets_field_name, temp_confident_sets));
        size_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
            Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime()).count();
        for (auto setItr : temp_confident_sets)
        {
            m_confident_sets[setItr.first] = std::pair<ValuesSet, size_t>(setItr.second, current_time);
        }
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to load confident sets from the learned data file: " << e.what();
        result = false;
    }

    return result;
}

void ConfidenceCalculator::mergeConfidenceSets(
    ConfidenceSet& confidence_set,
    const ConfidenceSet& confidence_set_to_merge,
    size_t& last_indicators_update
)
{
    for (auto& set : confidence_set_to_merge)
    {
        size_t num_of_values = confidence_set[set.first].first.size();
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Merging the set for the key: " << set.first <<
            ". Number of present values: " << num_of_values;
        for (auto& value : set.second.first)
        {
            confidence_set[normalize_param(set.first)].first.insert(value);
        }

        confidence_set[set.first].second = std::max<size_t>(confidence_set[set.first].second, set.second.second);
        last_indicators_update = std::max<size_t>(last_indicators_update, confidence_set[set.first].second);
    }
};

void ConfidenceCalculator::mergeFromRemote(const ConfidenceSet& remote_confidence_set, bool is_first_pull)
{
    if (is_first_pull) {
        m_confident_sets.clear();
    }
    mergeConfidenceSets(m_confident_sets, remote_confidence_set, m_last_indicators_update);
}

bool ConfidenceCalculator::is_confident(const Key &key, const Val &value) const
{
    auto confidentSetItr = m_confident_sets.find(key);
    if (confidentSetItr == m_confident_sets.end())
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to find the key(" << key << ")";
        return false;
    }

    const ValuesSet& confidentValues = confidentSetItr->second.first;
    if (confidentValues.find(value) != confidentValues.end())
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " confident that " << value << " should be filtered for " << key;
        return true;
    }
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
        " failed to find the value(" << value << ")";
    return false;
}

void ConfidenceCalculator::calcConfidentValues()
{
    std::unordered_map<Key, ValueSetWithTime> confidenceSetCopy = m_confident_sets;
    if (!m_params.learnPermanently)
    {
        m_confident_sets.clear();
    }

    for (auto& confidenceLevels : m_confidence_level)
    {
        Key key = confidenceLevels.first;
        for (auto& valConfidenceLevel : confidenceLevels.second)
        {
            Val value = valConfidenceLevel.first;
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "key: " << key << ", value: " << value
                << ", confidence level: " << valConfidenceLevel.second;
            if (valConfidenceLevel.second >= SCORE_THRESHOLD)
            {
                size_t confidenceValuesSize = m_confident_sets[key].first.size();
                m_confident_sets[key].first.insert(value);
                if (m_confident_sets[key].first.size() > confidenceValuesSize)
                {
                    std::chrono::seconds current_time = std::chrono::duration_cast<std::chrono::seconds>(
                                        Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime());
                    m_confident_sets[key].second = current_time.count();
                    m_last_indicators_update = std::chrono::duration_cast<std::chrono::minutes>(current_time).count();
                }
            }
        }
    }

}

ConfidenceCalculator::ValuesSet ConfidenceCalculator::getConfidenceValues(const Key &key) const
{
    auto confidentSetItr = m_confident_sets.find(key);
    if (confidentSetItr == m_confident_sets.end())
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << ";" <<
            " failed to find the key(" << key << ")";
        return ValuesSet();
    }
    return confidentSetItr->second.first;
}

size_t ConfidenceCalculator::getLastConfidenceUpdate()
{
    return m_last_indicators_update;
}

void ConfidenceCalculator::log(const Key &key, const Val &value, const std::string &source)
{
    m_time_window_logger[key][value].insert(source);
    if (value != m_null_obj)
    {
        logSourceHit(key, source);
    }
}

void ConfidenceCalculator::logSourceHit(const Key &key, const std::string &source)
{
    log(key, m_null_obj, source);
}

void ConfidenceCalculator::mergeSourcesCounter(const Key& key, const SourcesCounters& counters)
{
    if (key.rfind("url#", 0) == 0 && m_owner == "TypeIndicatorFilter")
    {
        return;
    }
    SourcesCounters& currentCounters = m_time_window_logger[key];
    for (auto& counter : counters)
    {
        SourcesSet& srcSet = currentCounters[counter.first];
        srcSet.insert(counter.second.begin(), counter.second.end());
    }
}

void ConfidenceCalculator::removeBadSources(SourcesSet& sources, const std::vector<std::string>* badSources)
{
    if (badSources == nullptr)
    {
        return;
    }
    for (auto badSource : *badSources)
    {
        sources.erase(badSource);
    }
}

size_t ConfidenceCalculator::sumSourcesWeight(const SourcesSet& sources)
{
    size_t sourcesWeights = sources.size();
    if (m_tuning == nullptr)
    {
        return sourcesWeights;
    }
    for (const auto& source : sources)
    {
        if (m_tuning->getDecision(source, SOURCE) == BENIGN)
        {
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "increasing source weight";
            sourcesWeights += m_params.minSources - 1;
        }
    }
    return sourcesWeights;
}

void ConfidenceCalculator::calculateInterval()
{
    std::vector<std::string>* sourcesToIgnore = nullptr;
    if (m_ignoreSources != nullptr)
    {
        int waitItr = 0;
        while (!m_ignoreSources->ready() && waitItr < WAIT_LIMIT)
        {
            Singleton::Consume<I_MainLoop>::by<WaapComponent>()->yield(BUSY_WAIT_TIME);
            waitItr++;
        }
        if (waitItr == WAIT_LIMIT && !m_ignoreSources->ready())
        {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                " - wait for ignore sources ready timeout";
        }
        sourcesToIgnore = m_ignoreSources->getSourcesToIgnore();
    }

    for (auto sourcesCtrItr : m_time_window_logger_backup)
    {
        SourcesCounters& srcCtrs = sourcesCtrItr.second;
        Key key = sourcesCtrItr.first;
        ValuesSet summary;
        double factor = 1.0;
        if (m_tuning != nullptr)
        {
            std::string param_name = key;
            auto param_name_pos = key.find("#");
            if (param_name_pos != std::string::npos && (param_name_pos + 1) <= key.size()) {
                param_name = key.substr(param_name_pos + 1); // not always accurate but good enough
            }
            if (m_tuning->getDecision(param_name, PARAM_NAME) == BENIGN)
            {
                factor = BENIGN_PARAM_FACTOR;
            }
        }

        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " calculate window summary for the parameter: " << key;
        // get all unique sources from the null object counter
        SourcesSet& sourcesUnion = srcCtrs[m_null_obj];
        removeBadSources(sourcesUnion, sourcesToIgnore);
        size_t numOfSources = sumSourcesWeight(sourcesUnion);

        m_windows_counter[key]++;
        if (numOfSources < m_params.minSources)
        {
            // not enough sources to learn from
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
                " not enough sources to learn for " << key << " - needed: " <<
                m_params.minSources << ", have: " << sourcesUnion.size();
            mergeSourcesCounter(key, srcCtrs);
            continue;
        }
        for (auto srcSets : srcCtrs)
        {
            // log the ratio of unique sources from all sources for each value
            SourcesSet& currentSourcesSet = srcSets.second;
            Val value = srcSets.first;
            if (value == m_null_obj)
            {
                continue;
            }
            removeBadSources(currentSourcesSet, sourcesToIgnore);
            size_t currentSourcesCount = sumSourcesWeight(currentSourcesSet);
            auto& confidenceLevel = m_confidence_level[key][value];
            if (currentSourcesCount == 0)
            {
                confidenceLevel -= std::ceil(SCORE_THRESHOLD / m_params.minIntervals);
                continue;
            }
            double ratio = ((double)currentSourcesCount / numOfSources);

            double diff = std::ceil(SCORE_THRESHOLD / m_params.minIntervals) * (ratio / m_params.ratioThreshold) *
                logn(currentSourcesCount, m_params.minSources) * factor;

            confidenceLevel += diff;
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " - key: " << key <<
                " value: " << value << "confidence level: " << confidenceLevel;
        }
        m_windows_counter[key] = 0;
    }

    for (auto& keyMap : m_confidence_level)
    {
        for (auto& valMap : keyMap.second)
        {
            if (m_time_window_logger_backup.find(keyMap.first) != m_time_window_logger_backup.end() &&
                m_time_window_logger_backup[keyMap.first].find(valMap.first) ==
                m_time_window_logger_backup[keyMap.first].end())
            {
                // reduce confidence when value do not appear
                valMap.second *= m_params.ratioThreshold;
            }
        }
    }

    m_time_window_logger_backup.clear();
    calcConfidentValues();
}

void ConfidenceCalculator::setOwner(const std::string& owner)
{
    m_owner = owner + "/ConfidenceCalculator";
}

bool ConfidenceCalculatorParams::operator==(const ConfidenceCalculatorParams& other)
{
    return (minSources == other.minSources &&
        minIntervals == other.minIntervals &&
        intervalDuration == other.intervalDuration &&
        ratioThreshold == other.ratioThreshold &&
        learnPermanently == other.learnPermanently);
}

std::ostream& operator<<(std::ostream& os, const ConfidenceCalculatorParams& ccp)
{
    os << "min sources: " << ccp.minSources <<
        " min intervals: " << ccp.minIntervals <<
        " interval duration(minutes): " << ccp.intervalDuration.count() <<
        " ratio threshold: " << ccp.ratioThreshold <<
        " should keep indicators permanently: " << ccp.learnPermanently;
    return os;
}
