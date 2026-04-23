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
#include <unistd.h>
#include "waap.h"
#include "ConfidenceFile.h"
#include "i_agent_details.h"
#include "i_mainloop.h"
#include "buffered_compressed_stream.h"
#include <sys/stat.h>
#include <math.h>
#include <dirent.h> // For DIR, opendir, readdir, closedir
#include <cctype>  // For isdigit

using namespace std;

USE_DEBUG_FLAG(D_WAAP);

#define SYNC_WAIT_TIME chrono::seconds(300) // 5 minutes in seconds
#define SCORE_THRESHOLD 100.0
#define BUSY_WAIT_TIME chrono::microseconds(100000) // 0.1 seconds
#define WAIT_LIMIT 10
#define BENIGN_PARAM_FACTOR 2
#define MAX_TRACKING_KEYS 1000 // Maximum number of keys to track

double logn(double x, double n)
{
    return log(x) / log(n);
}

ConfidenceCalculator::ConfidenceCalculator(
    size_t minSources,
    size_t minIntervals,
    chrono::minutes intervalDuration,
    double ratioThreshold,
    const Val &nullObj,
    const string &backupPath,
    const string &remotePath,
    const string &assetId,
    TuningDecision* tuning,
    I_IgnoreSources* ignoreSrc) :
    SerializeToLocalAndRemoteSyncBase(intervalDuration,
        SYNC_WAIT_TIME,
        backupPath,
        (remotePath == "") ? remotePath : remotePath + "/Confidence",
        assetId,
        "ConfidenceCalculator"),
    m_params({ minSources, minIntervals, intervalDuration, ratioThreshold, true, defaultConfidenceMemUsage}),
    m_null_obj(nullObj),
    m_time_window_logger(make_shared<ConfidenceCalculator::KeyValSourcesLogger>()),
    m_time_window_logger_backup(nullptr),
    m_confident_sets(),
    m_confidence_level(),
    m_last_indicators_update(0),
    m_latest_index(0),
    m_ignoreSources(ignoreSrc),
    m_tuning(tuning),
    m_estimated_memory_usage(0),
    m_post_index(0),
    m_mainLoop(Singleton::Consume<I_MainLoop>::by<WaapComponent>()),
    m_routineId(0),
    m_filesToRemove(),
    m_indicator_tracking_keys(),
    m_tracking_keys_received(false)
{
    restore();

    extractLowConfidenceKeys(m_confidence_level);

    // Start asynchronous deletion of existing carry-on data files
    garbageCollector();
}

ConfidenceCalculator::~ConfidenceCalculator()
{
    m_time_window_logger->clear();
    m_time_window_logger.reset();
    m_confident_sets.clear();
    if (!m_path_to_backup.empty()) {
        remove(m_path_to_backup.c_str());
        m_path_to_backup = "";
    }
    if (m_time_window_logger_backup) {
        m_time_window_logger_backup->clear();
        m_time_window_logger_backup.reset();
    }
}

void ConfidenceCalculator::hardReset()
{
    if (m_time_window_logger) {
        m_time_window_logger->clear();
        m_time_window_logger = make_shared<ConfidenceCalculator::KeyValSourcesLogger>();
    }
    if (m_time_window_logger_backup) {
        m_time_window_logger_backup->clear();
        m_time_window_logger_backup.reset();
    }
    m_estimated_memory_usage = 0;
    m_confidence_level.clear();
    m_confident_sets.clear();
    m_indicator_tracking_keys.clear();
    m_tracking_keys_received = false;
    remove(m_filePath.c_str());
}

void ConfidenceCalculator::reset()
{
    if (m_time_window_logger) {
        m_time_window_logger->clear();
        m_time_window_logger = make_shared<ConfidenceCalculator::KeyValSourcesLogger>();
    }
    m_estimated_memory_usage = 0;
    if (!m_params.learnPermanently)
    {
        hardReset();
    }
}

bool ConfidenceCalculator::reset(ConfidenceCalculatorParams &params)
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
    WindowLogPost(std::shared_ptr<ConfidenceCalculator::KeyValSourcesLogger> _window_logger_ptr)
    {
        // Initialize the RestParam with a reference to the shared data
        // do not copy the shared pointer, but move it to avoid copying - do not use the ptr after it
        window_logger = std::move(*_window_logger_ptr);
    }

    ~WindowLogPost()
    {
        // Container will be automatically cleaned up when RestParam goes out of scope
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

void ConfidenceCalculator::saveTimeWindowLogger()
{
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Saving the time window logger to: " << m_path_to_backup;
    if (m_path_to_backup != "") // remove old file from exceed memory cap flow
    {
        remove(m_path_to_backup.c_str());
        m_path_to_backup = "";
        m_mainLoop->yield(false);
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Yielded after removing old backup file";
    }
    // create temp file with random name
    char temp_filename[] = "/tmp/waap_confidence_XXXXXX.gz";
    int fd = mkstemps(temp_filename, 3);
    if (fd == -1) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to create temporary file. errono: " << errno;
        m_time_window_logger_backup = m_time_window_logger;
        return;
    }
    close(fd);
    m_mainLoop->yield(false);
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Yielded after creating temp file: " << temp_filename;

    m_path_to_backup = temp_filename;

    try {
        ofstream file(m_path_to_backup, ios::binary);
        if (!file.is_open()) {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to open file: " << m_path_to_backup
                << ", errno: " << errno << ", strerror: " << strerror(errno);
            m_time_window_logger_backup = m_time_window_logger;
            return;
        }

        BufferedCompressedOutputStream compressed_out(file);
        {
            cereal::JSONOutputArchive archive(compressed_out);
            archive(cereal::make_nvp("logger", *m_time_window_logger));
        }
        compressed_out.close();
        file.close();

        m_mainLoop->yield(false);
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "JSON serialized and compressed to file: " << m_path_to_backup;
    }
    catch (const std::exception &e) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to serialize and compress data: " << e.what();
        m_time_window_logger_backup = m_time_window_logger;
        m_path_to_backup = "";
        return;
    }

    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Finished writing the backup file: " << m_path_to_backup;
}

shared_ptr<ConfidenceCalculator::KeyValSourcesLogger> ConfidenceCalculator::loadTimeWindowLogger()
{
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Loading the time window logger from: " << m_path_to_backup;
    if (m_path_to_backup.empty()) {
        dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "No backup file path set, cannot load logger";
        return nullptr;
    }

    ifstream file(m_path_to_backup);
    if (!file.is_open()) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to open file: " << m_path_to_backup
            << ", errno: " << errno << ", strerror: " << strerror(errno);
        return nullptr;
    }

    auto window_logger = make_shared<KeyValSourcesLogger>();

    try {
        BufferedCompressedInputStream compressed_in(file);
        cereal::JSONInputArchive archive(compressed_in);
        archive(cereal::make_nvp("logger", *window_logger));
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Successfully deserialized logger from JSON";
    } catch (cereal::Exception &e) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to load the time window logger: " << e.what();
        file.close();
        return nullptr;
    }

    file.close();

    return window_logger;
}

bool ConfidenceCalculator::postData()
{
    if (m_time_window_logger->empty())
    {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "No data to post, skipping";
        return true; // Nothing to post
    }
    saveTimeWindowLogger();
    m_mainLoop->yield(false);
    WindowLogPost currentWindow(m_time_window_logger);
    m_mainLoop->yield(false);
    m_time_window_logger = make_shared<ConfidenceCalculator::KeyValSourcesLogger>();
    string url = getPostDataUrl() + to_string(m_post_index++);

    m_estimated_memory_usage = 0;
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Sending the data to: " << url;

    bool ok = sendNoReplyObjectWithRetry(currentWindow,
        HTTPMethod::PUT,
        url);
    if (!ok) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to post collected data to: " << url;
    }
    return ok;
}

void ConfidenceCalculator::pullData(const vector<string> &files)
{
    if (getIntervalsCount() == m_params.minIntervals)
    {
        mergeProcessedFromRemote();
    }
    if (m_time_window_logger_backup == nullptr)
    {
        m_time_window_logger_backup = loadTimeWindowLogger();
        if (m_time_window_logger_backup == nullptr)
        {
            dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to load the time window logger";
            return;
        }
    }
    string url = getPostDataUrl();
    string sentFile = url.erase(0, strlen("/storage/waap/"));
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "pulling files, skipping: " << sentFile;
    for (const auto &file : files) // Use const reference to avoid copying
    {
        if (file == sentFile)
        {
            continue;
        }
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Pulling the file: " << file;
        WindowLogGet getWindow;
        bool ok = sendObjectWithRetry(getWindow,
            HTTPMethod::GET,
            getUri() + "/" + file);

        if (!ok) {
            dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get file: " << file;
            continue;
        }

        KeyValSourcesLogger remoteLogger = getWindow.getWindowLogger().unpack();
        for (const auto &log : remoteLogger) // Use const reference
        {
            const string &key = log.first;
            for (const auto &entry : log.second) // Use const reference
            {
                const string &value = entry.first;
                for (const auto &source : entry.second) // Use const reference
                {
                    (*m_time_window_logger_backup)[key][value].insert(source);
                }
            }
        }
    }
}

void ConfidenceCalculator::processData()
{
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " - processing the confidence data";
    m_post_index = 0;
    if (m_time_window_logger_backup == nullptr || m_time_window_logger_backup->empty())
    {
        if (!m_path_to_backup.empty())
        {
            m_time_window_logger_backup = loadTimeWindowLogger();
            m_mainLoop->yield(false);
            if (m_time_window_logger_backup == nullptr)
            {
                dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to load the time window logger";
                return;
            }
        } else {
            m_time_window_logger_backup = m_time_window_logger;
            m_time_window_logger = make_shared<ConfidenceCalculator::KeyValSourcesLogger>();
            m_estimated_memory_usage = 0;
        }
    }
    calculateInterval();
    // clear temp data
    m_time_window_logger_backup->clear();
    m_time_window_logger_backup.reset();
    if (!m_path_to_backup.empty())
    {
        remove(m_path_to_backup.c_str());
        m_path_to_backup.clear();
    }
}

void ConfidenceCalculator::updateState(const vector<string> &files)
{
    pullProcessedData(files);
    // clear temp data
    if (m_time_window_logger_backup)
    {
        m_time_window_logger_backup->clear();
        m_time_window_logger_backup.reset();
    }
}

Maybe<string> ConfidenceCalculator::getRemoteStateFilePath() const
{
    return m_remotePath + "/remote/confidence.data";
}

void ConfidenceCalculator::pullProcessedData(const vector<string> &files)
{
    dbgTrace(D_WAAP) << "Fetching the confidence set object";
    m_post_index = 0;
    bool is_first_pull = true;
    bool is_ok = false;
    for (const auto &file : files) // Use const reference to avoid copying
    {
        ConfidenceFileDecryptor getConfFile;
        bool res = sendObject(getConfFile,
            HTTPMethod::GET,
            getUri() + "/" + file);
        is_ok |= res;
        if (res && getConfFile.getConfidenceSet().ok())
        {
            mergeFromRemote(getConfFile.getConfidenceSet().unpackMove(), is_first_pull);
            is_first_pull = false;
        }
        if (res && getConfFile.getTrackingKeys().ok())
        {
            auto trackingKeys = getConfFile.getTrackingKeys().unpackMove();
            m_indicator_tracking_keys = unordered_set<string>(trackingKeys.begin(), trackingKeys.end());
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Received tracking keys: " << m_indicator_tracking_keys.size();
            m_tracking_keys_received = true;
        }
        if (res && getConfFile.getConfidenceLevels().ok())
        {
            // write to disk the confidence levels
            saveConfidenceLevels(getConfFile.getConfidenceLevels().unpackMove());
        }
        else
        {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get tracking keys from file: " << file;
        }
    }
    // is_ok = false -> no file was downloaded and merged
    if (!is_ok) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get the remote state";
        return;
    }
    if (m_path_to_backup != "")
    {
        remove(m_path_to_backup.c_str());
        m_path_to_backup = "";
    }
}

void ConfidenceCalculator::postProcessedData()
{
    if (getIntervalsCount() < m_params.minIntervals)
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Not sending the processed data - not enough windows";
        return;
    }
    string postUrl = getUri() + "/" + m_remotePath + "/processed/confidence.data";
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Posting the confidence set object to: " << postUrl;
    ConfidenceFileEncryptor postConfFile(m_confident_sets, m_confidence_level);
    sendNoReplyObjectWithRetry(postConfFile,
        HTTPMethod::PUT,
        postUrl);
}

void ConfidenceCalculator::serialize(ostream &stream)
{
    cereal::JSONOutputArchive archive(stream);

    archive(
        cereal::make_nvp("version", 3),
        cereal::make_nvp("params", m_params),
        cereal::make_nvp("last_indicators_update", m_last_indicators_update),
        cereal::make_nvp("confidence_levels", m_confidence_level),
        cereal::make_nvp("confident_sets", m_confident_sets),
        cereal::make_nvp("latest_index", m_latest_index + getIntervalsCount())
    );
}
void ConfidenceCalculator::deserialize(istream &stream)
{
    size_t version;
    cereal::JSONInputArchive archive(stream);
    try
    {
        archive(cereal::make_nvp("version", version));
    }
    catch (runtime_error & e) {
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

void ConfidenceCalculator::loadVer0(cereal::JSONInputArchive &archive)
{
    if (!tryParseVersionBasedOnNames(
        archive,
        string("params"),
        string("last_indicators_update"),
        string("windows_summary_list"),
        string("confident_sets")
    ))
    {
        tryParseVersionBasedOnNames(
            archive,
            string("m_params"),
            string("m_lastIndicatorsUpdate"),
            string("m_windows_summary_list"),
            string("m_confident_sets")
        );
    }

}

void ConfidenceCalculator::convertWindowSummaryToConfidenceLevel(const WindowsConfidentValuesList &windows)
{
    for (const auto &windowKey : windows)
    {
        for (const auto &window : windowKey.second)
        {
            for (const auto &value : window)
            {
                m_confidence_level[windowKey.first][value] += ceil(SCORE_THRESHOLD / m_params.minIntervals);
            }
        }
    }
}

void ConfidenceCalculator::loadVer2(cereal::JSONInputArchive &archive)
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
    params.maxMemoryUsage = defaultConfidenceMemUsage;
    reset(params);
    for (auto &confidentSet : confidenceSets)
    {
        m_confident_sets[normalize_param(confidentSet.first)] = confidentSet.second;
    }
    for (auto &confidenceLevel : confidenceLevels)
    {
        string normParam = normalize_param(confidenceLevel.first);
        if (m_confidence_level.find(normParam) == m_confidence_level.end())
        {
            m_confidence_level[normParam] = confidenceLevel.second;
        }
        else
        {
            for (auto &valueLevelItr : confidenceLevel.second)
            {
                if (m_confidence_level[normParam].find(valueLevelItr.first) == m_confidence_level[normParam].end())
                {
                    m_confidence_level[normParam][valueLevelItr.first] = valueLevelItr.second;
                }
                else
                {
                    double maxScore = max(m_confidence_level[normParam][valueLevelItr.first],
                        valueLevelItr.second);
                    m_confidence_level[normParam][valueLevelItr.first] = maxScore;
                }
            }
        }
    }
}

void ConfidenceCalculator::loadVer3(cereal::JSONInputArchive &archive)
{
    ConfidenceCalculatorParams params;
    archive(
        cereal::make_nvp("params", params),
        cereal::make_nvp("last_indicators_update", m_last_indicators_update),
        cereal::make_nvp("confidence_levels", m_confidence_level),
        cereal::make_nvp("confident_sets", m_confident_sets)
    );
    try {
        archive(cereal::make_nvp("latest_index", m_latest_index));
    }
    catch (runtime_error & e) {
        m_latest_index = 0;
        archive.setNextName(nullptr);
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR)
            << "Owner: " << m_owner <<
            ", failed to load the latest index from the learned data file: "
            << e.what();
    }
    if (params.maxMemoryUsage == 0)
    {
        params.maxMemoryUsage = defaultConfidenceMemUsage;
    }
    reset(params);
}


void ConfidenceCalculator::loadVer1(cereal::JSONInputArchive &archive)
{
    WindowsConfidentValuesList windows_summary_list;
    ConfidenceCalculatorParams params;

    archive(
        cereal::make_nvp("params", params),
        cereal::make_nvp("last_indicators_update", m_last_indicators_update),
        cereal::make_nvp("windows_summary_list", windows_summary_list),
        cereal::make_nvp("confident_sets", m_confident_sets)
    );
    params.maxMemoryUsage = defaultConfidenceMemUsage;

    reset(params);

    convertWindowSummaryToConfidenceLevel(windows_summary_list);
}

bool ConfidenceCalculator::tryParseVersionBasedOnNames(
    cereal::JSONInputArchive &archive,
    const string &params_field_name,
    const string &indicators_update_field_name,
    const string &windows_summary_field_name,
    const string &confident_sets_field_name)
{
    bool result = true;
    try
    {
        ConfidenceCalculatorParams temp_params;
        archive(cereal::make_nvp(params_field_name, temp_params));
        reset(temp_params);
        m_params = temp_params;
    }
    catch (runtime_error & e) {
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
    catch (runtime_error & e) {
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
    catch (runtime_error & e) {
        archive.setNextName(nullptr);
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to load windows summary list from the learned data file: " << e.what();
        result = false;
    }

    try
    {
        unordered_map<Key, ValuesSet> temp_confident_sets;
        archive(cereal::make_nvp(confident_sets_field_name, temp_confident_sets));
        size_t current_time = chrono::duration_cast<chrono::seconds>(
                Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime()
            ).count();

        for (auto setItr : temp_confident_sets)
        {
            m_confident_sets[setItr.first] = pair<ValuesSet, size_t>(setItr.second, current_time);
        }
    }
    catch (runtime_error & e) {
        archive.setNextName(nullptr);
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
            " failed to load confident sets from the learned data file: " << e.what();
        result = false;
    }

    return result;
}

void ConfidenceCalculator::mergeConfidenceSets(
    ConfidenceSet &confidence_set,
    const ConfidenceSet &confidence_set_to_merge,
    size_t &last_indicators_update
)
{
    for (auto &set : confidence_set_to_merge)
    {
        size_t num_of_values = confidence_set[set.first].first.size();
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Merging the set for the key: " << set.first <<
            ". Number of present values: " << num_of_values;
        for (auto &value : set.second.first)
        {
            confidence_set[normalize_param(set.first)].first.insert(value);
        }

        confidence_set[set.first].second = max<size_t>(confidence_set[set.first].second, set.second.second);
        last_indicators_update = max<size_t>(last_indicators_update, confidence_set[set.first].second);
    }
};

void ConfidenceCalculator::mergeFromRemote(const ConfidenceSet &remote_confidence_set, bool is_first_pull)
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

    const ValuesSet &confidentValues = confidentSetItr->second.first;
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
    unordered_map<Key, ValueSetWithTime> confidenceSetCopy = m_confident_sets;
    if (!m_params.learnPermanently)
    {
        m_confident_sets.clear();
    }

    for (auto &confidenceLevels : m_confidence_level)
    {
        Key key = confidenceLevels.first;
        for (auto &valConfidenceLevel : confidenceLevels.second)
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
                    chrono::seconds current_time = chrono::duration_cast<chrono::seconds>(
                                        Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime());
                    m_confident_sets[key].second = current_time.count();
                    m_last_indicators_update = chrono::duration_cast<chrono::minutes>(current_time).count();
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

void ConfidenceCalculator::log(const Key &key, const Val &value, const string &source)
{
    // Only track in time window logger if we should track this parameter
    if (shouldTrackParameter(key, value)) {
        auto &sources_set = (*m_time_window_logger)[key][value];
        auto result = sources_set.insert(source);
        if (result.second) {
            // New entry added, update memory usage
            if ((*m_time_window_logger)[key][value].size() == 1) {
                // first source for this value - means new value
                m_estimated_memory_usage += sizeof(value) + value.capacity();
                m_estimated_memory_usage += sizeof(SourcesSet);

                if ((*m_time_window_logger)[key].size() == 1) {
                    // first value for this key - means new key
                    m_estimated_memory_usage += sizeof(key) + key.capacity();
                    m_estimated_memory_usage += sizeof(SourcesCounters);
                }
            }
            m_estimated_memory_usage += sizeof(source) + source.capacity();
        }
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "memory usage: " << m_estimated_memory_usage <<
            "/" << m_params.maxMemoryUsage;
    }

    if (value != m_null_obj)
    {
        logSourceHit(key, source);
        return;
    }

    // if estimated memory usage is too high, send to the server
    if (m_remoteSyncEnabled && m_estimated_memory_usage > m_params.maxMemoryUsage)
    {
        dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "sending data to the server, memory usage: "
            << m_estimated_memory_usage;
        // run a onetime routine to send the data to the server
        I_MainLoop *mainLoop = Singleton::Consume<I_MainLoop>::by<WaapComponent>();
        mainLoop->addOneTimeRoutine(I_MainLoop::RoutineType::Offline,
            [this]() {
                postData();
            },
            "ConfidenceCalculator post data offsync"
        );
        m_estimated_memory_usage = 0;
    }
}

void ConfidenceCalculator::logSourceHit(const Key &key, const string &source)
{
    log(key, m_null_obj, source);
}

void ConfidenceCalculator::setIndicatorTrackingKeys(const std::vector<std::string>& keys)
{
    m_indicator_tracking_keys.clear();
    for (const auto& key : keys) {
        m_indicator_tracking_keys.insert(key);
    }
    m_tracking_keys_received = true;
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
        " - received " << keys.size() << " indicator tracking keys from service";
}

void ConfidenceCalculator::markKeyAsConfident(const Key &key)
{
    // This method is kept for API compatibility but doesn't affect conditional tracking
    // The confidence set is managed independently and not altered by conditional tracking feature
    // Add the key to confident sets if not already present
    if (m_confident_sets.find(key) == m_confident_sets.end()) {
        size_t current_time = chrono::duration_cast<chrono::seconds>(
            Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime()
        ).count();
        m_confident_sets[key] = std::make_pair(ValuesSet(), current_time);
    }
}

bool ConfidenceCalculator::shouldTrackParameter(const Key &key, const Val &value)
{
    // For backward compatibility: if tracking list hasn't been received from service yet, track all
    if (!m_tracking_keys_received) {
        return true;
    }

    // Should NOT track if key->value combination is already in confidence set
    if (is_confident(key, value)) {
        return !m_params.learnPermanently; // If learnPermanently is true, we don't track confident values
    }
    if (!m_params.learnPermanently && m_confident_sets.find(key) != m_confident_sets.end()) {
        m_indicator_tracking_keys.insert(key); // Ensure the key is in the tracking list
        return true;
    }

    // Should NOT track if key is not in tracking list AND value is null obj
    bool keyInTrackingList = (m_indicator_tracking_keys.find(key) != m_indicator_tracking_keys.end());
    if (!keyInTrackingList && value == m_null_obj) {
        return false;
    }

    if (!keyInTrackingList) {
        // If tracking list is full, do not track this key
        m_indicator_tracking_keys.insert(key); // Ensure the key is in the tracking list
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
            " - tracking key: " << key << ", value: " << value;
    }
    // Should track if:
    // 1. Key is in tracking list, OR
    // 2. New value (not null obj) AND key->value not in confidence set (already checked above)
    return keyInTrackingList || (value != m_null_obj);
}

void ConfidenceCalculator::removeBadSources(SourcesSet &sources, const vector<string>* badSources)
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

size_t ConfidenceCalculator::sumSourcesWeight(const SourcesSet &sources)
{
    size_t sourcesWeights = sources.size();
    if (m_tuning == nullptr)
    {
        return sourcesWeights;
    }
    for (const auto &source : sources)
    {
        if (m_tuning->getDecision(source, SOURCE) == BENIGN)
        {
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "increasing source weight";
            sourcesWeights += m_params.minSources - 1;
        }
    }
    return sourcesWeights;
}

void ConfidenceCalculator::loadConfidenceLevels()
{
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
        " - loading the confidence levels from disk, latest index: " << m_latest_index <<
        ", intervals count: " << getIntervalsCount();

    string file_path = m_filePath + ".levels." + to_string((m_latest_index + getIntervalsCount() - 1) % 2) + ".gz";
    ifstream file(file_path, ios::binary);
    if (!file.is_open()) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to open the file: " << file_path <<
            ", errno: " << errno << ", strerror: " << strerror(errno);
        return;
    }
    try {
        BufferedCompressedInputStream decompressed_stream(file);
        cereal::JSONInputArchive archive(decompressed_stream);
        archive(cereal::make_nvp("confidence_levels", m_confidence_level));
    } catch (runtime_error &e) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR)
            << "Failed to load the confidence levels, owner: "
            << m_owner << ", error: " << e.what();
    }
    file.close();
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
        " - loaded the confidence levels from disk, latest index: " << m_latest_index <<
        ", intervals count: " << getIntervalsCount();
    m_mainLoop->yield(false);
    if (m_confidence_level.empty())
    {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "confidence levels are empty, owner: " << m_owner <<
            ", file: " << file_path;
    }
}

void ConfidenceCalculator::saveConfidenceLevels()
{
    Maybe<ConfidenceCalculator::ConfidenceLevels> confidenceLevels(genError("not available"));
    saveConfidenceLevels(confidenceLevels);
}

void ConfidenceCalculator::saveConfidenceLevels(Maybe<ConfidenceCalculator::ConfidenceLevels> confidenceLevels)
{
    if (!confidenceLevels.ok())
    {
        // if confidence levels are not available, use the current confidence level
        extractLowConfidenceKeys(m_confidence_level);
    }
    else
    {
        // if confidence levels are empty, use the current confidence level
        extractLowConfidenceKeys(confidenceLevels.unpackMove());
    }
    string file_path = m_filePath + ".levels." + to_string((m_latest_index + getIntervalsCount()) % 2) + ".gz";
    ofstream file(file_path, ios::binary);
    if (!file.is_open()) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to open file: " << file_path
            << ", errno: " << errno << ", strerror: " << strerror(errno);
        return;
    }
    {
        try {
            BufferedCompressedOutputStream compressed_out(file);
            cereal::JSONOutputArchive archive(compressed_out);
            if (confidenceLevels.ok()) {
                archive(cereal::make_nvp("confidence_levels", confidenceLevels.unpackMove()));
            }
            else
            {
                archive(cereal::make_nvp("confidence_levels", m_confidence_level));
            }
        } catch (runtime_error &e) {
            file.close();
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to serialize the confidence levels: " << e.what();
            return;
        }
    }
    file.close();
    m_mainLoop->yield(false);

    m_confidence_level.clear();

    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
        " - saved the confidence levels to disk, latest index: " << m_latest_index <<
        ", intervals count: " << getIntervalsCount();
}

void ConfidenceCalculator::calculateInterval()
{
    // load confidence levels from the disk
    loadConfidenceLevels();

    vector<string>* sourcesToIgnore = nullptr;
    if (m_ignoreSources != nullptr)
    {
        int waitItr = 0;
        while (!m_ignoreSources->ready() && waitItr < WAIT_LIMIT)
        {
            m_mainLoop->yield(BUSY_WAIT_TIME);
            waitItr++;
        }
        if (waitItr == WAIT_LIMIT && !m_ignoreSources->ready())
        {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                " - wait for ignore sources ready timeout";
        }
        sourcesToIgnore = m_ignoreSources->getSourcesToIgnore();
    }

    int itr = 0;
    for (auto sourcesCtrItr : *m_time_window_logger_backup)
    {
        if (++itr % 20 == 0) {
            // yield every 20 iterations
            m_mainLoop->yield(false);
        }
        SourcesCounters &srcCtrs = sourcesCtrItr.second;
        Key key = sourcesCtrItr.first;
        ValuesSet summary;
        double factor = 1.0;
        if (m_tuning != nullptr)
        {
            string param_name = key;
            auto param_name_pos = key.find("#");
            if (param_name_pos != string::npos && (param_name_pos + 1) <= key.size()) {
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
        SourcesSet &sourcesUnion = srcCtrs[m_null_obj];
        removeBadSources(sourcesUnion, sourcesToIgnore);
        size_t numOfSources = sumSourcesWeight(sourcesUnion);

        if (numOfSources < m_params.minSources)
        {
            // not enough sources to learn from
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " -" <<
                " not enough sources to learn for " << key << " - needed: " <<
                m_params.minSources << ", have: " << sourcesUnion.size();
            continue;
        }

        for (auto srcSets : srcCtrs)
        {
            // log the ratio of unique sources from all sources for each value
            SourcesSet &currentSourcesSet = srcSets.second;
            Val value = srcSets.first;
            if (value == m_null_obj)
            {
                continue;
            }
            removeBadSources(currentSourcesSet, sourcesToIgnore);
            size_t currentSourcesCount = sumSourcesWeight(currentSourcesSet);
            auto &confidenceLevel = m_confidence_level[key][value];
            if (currentSourcesCount == 0)
            {
                confidenceLevel -= ceil(SCORE_THRESHOLD / m_params.minIntervals);
                continue;
            }
            double ratio = ((double)currentSourcesCount / numOfSources);

            double diff = ceil(SCORE_THRESHOLD / m_params.minIntervals) * (ratio / m_params.ratioThreshold) *
                logn(currentSourcesCount, m_params.minSources) * factor;

            confidenceLevel += diff;
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner << " - key: " << key <<
                " value: " << value << " confidence level: " << confidenceLevel;
        }
    }

    for (auto &keyMap : m_confidence_level)
    {
        for (auto &valMap : keyMap.second)
        {
            if (m_time_window_logger_backup->find(keyMap.first) != m_time_window_logger_backup->end() &&
                (*m_time_window_logger_backup)[keyMap.first].find(valMap.first) ==
                (*m_time_window_logger_backup)[keyMap.first].end())
            {
                // reduce confidence when value do not appear
                valMap.second *= m_params.ratioThreshold;
            }
        }
    }

    calcConfidentValues();
    // save confidence levels to the disk
    saveConfidenceLevels();
}

void ConfidenceCalculator::setOwner(const string &owner)
{
    m_owner = owner + "/ConfidenceCalculator";
}

bool ConfidenceCalculatorParams::operator==(const ConfidenceCalculatorParams &other)
{
    return (minSources == other.minSources &&
        minIntervals == other.minIntervals &&
        intervalDuration == other.intervalDuration &&
        ratioThreshold == other.ratioThreshold &&
        learnPermanently == other.learnPermanently &&
        maxMemoryUsage == other.maxMemoryUsage);
}

ostream &operator<<(ostream &os, const ConfidenceCalculatorParams &ccp)
{
    os << "min sources: " << ccp.minSources <<
        " min intervals: " << ccp.minIntervals <<
        " interval duration(minutes): " << ccp.intervalDuration.count() <<
        " ratio threshold: " << ccp.ratioThreshold <<
        " should keep indicators permanently: " << ccp.learnPermanently <<
        " max memory usage: " << ccp.maxMemoryUsage;
    return os;
}

void ConfidenceCalculator::garbageCollector()
{
    dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
        " - starting asynchronous garbage collection of carry-on data files";

    I_MainLoop *mainLoop = Singleton::Consume<I_MainLoop>::by<WaapComponent>();
    mainLoop->addOneTimeRoutine(I_MainLoop::RoutineType::Offline,
        // LCOV_EXCL_START
        [this, mainLoop]() {
            dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                " - running garbage collection of carry-on data files";
            // Extract the base filename from m_filePath (without directory)
            string baseFileName;
            size_t lastSlash = m_filePath.find_last_of('/');
            if (lastSlash != string::npos) {
                baseFileName = m_filePath.substr(lastSlash + 1);
            } else {
                baseFileName = m_filePath;
            }

            // Cache the directory path where we'll be looking for .data files
            string dirPath = m_filePath.substr(0, m_filePath.find_last_of('/'));
            if (dirPath.empty()) {
                dirPath = ".";
            }

            DIR* dir = opendir(dirPath.c_str());
            if (!dir) {
                dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                    " - failed to open directory for garbage collection: " << dirPath;
                return;
            }

            struct dirent* entry;
            int filesDeleted = 0;
            int fileCount = 0;

            // Iterate through directory entries
            while ((entry = readdir(dir)) != nullptr) {
                string filename = entry->d_name;

                // Check if this is a carry-on data file matching the pattern:
                // m_filePath + "." + to_string(keyHash) + ".data"
                if (filename.length() > baseFileName.length() + 7 &&
                    filename.compare(filename.length() - 5, 5, ".data") == 0 &&
                    filename.compare(0, baseFileName.length(), baseFileName) == 0) {

                    // Extract the part between baseFileName and .data (should be .{number})
                    string middlePart = filename.substr(
                        baseFileName.length(),
                        filename.length() - baseFileName.length() - 5
                    );

                    // Verify middle part starts with a dot followed by numeric characters
                    if (middlePart.length() > 1 && middlePart[0] == '.') {
                        bool isNumeric = true;
                        for (size_t i = 1; i < middlePart.length(); i++) {
                            if (!isdigit(middlePart[i])) {
                                isNumeric = false;
                                break;
                            }
                        }

                        if (isNumeric) {
                            string fullPath = dirPath + "/" + filename;
                            // yield to prevent blocking - use all allocated time
                            mainLoop->yield(false);
                            // Delete the file
                            if (remove(fullPath.c_str()) == 0) {
                                filesDeleted++;
                            } else {
                                dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                                    " - failed to delete carry-on data file: " << fullPath <<
                                    " errono: " << errno;
                            }
                        }
                    }
                    if (fileCount - filesDeleted > 5) {
                        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                            " - failed to delete many files. Files not deleted: " << fileCount - filesDeleted;
                    }
                }
            }

            closedir(dir);

            // Additional logic to delete temporary files under /tmp/ matching waap_confidence_XXXXXX
            const string tmpDir = getProfileAgentSettingWithDefault<string>(
                "/tmp/",
                "appsecLearningSettings.tmpDir"
            );
            dir = opendir(tmpDir.c_str());
            if (!dir) {
                dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                    " - failed to open /tmp/ directory for garbage collection.";
                return;
            }

            while ((entry = readdir(dir)) != nullptr) {
                string filename = entry->d_name;

                // Check if the file matches the pattern waap_confidence_XXXXXX
                if (filename.find("waap_confidence_") == 0) {
                    string fullPath = tmpDir + filename;
                    if (remove(fullPath.c_str()) == 0) {
                        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Deleted temporary file: " << fullPath;
                    } else {
                        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to delete temporary file: " << fullPath;
                    }
                    mainLoop->yield(false);
                }
            }

            closedir(dir);

            dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                " - finished garbage collection.";
        },
        // LCOV_EXCL_STOP
        "ConfidenceCalculator garbage collection"
    );
}

void ConfidenceCalculator::extractLowConfidenceKeys(const ConfidenceLevels& confidence_levels)
{
    const double LOW_CONFIDENCE_THRESHOLD = 100.0;
    size_t keys_added = 0;
    m_tracking_keys_received = true; // Ensure tracking keys are considered received

    for (const auto& keyEntry : confidence_levels) {
        const std::string& key = keyEntry.first;
        const auto& valueConfidenceMap = keyEntry.second;

        if (!m_params.learnPermanently) {
            m_indicator_tracking_keys.insert(key); // Ensure the key is in the tracking list
            continue;
        }

        // Check if any value for this key has confidence level below threshold
        bool hasLowConfidence = false;
        for (const auto& valueEntry : valueConfidenceMap) {
            if (valueEntry.second < LOW_CONFIDENCE_THRESHOLD) {
                hasLowConfidence = true;
                break;
            }
        }

        // If key has low confidence values, add it to tracking keys
        if (hasLowConfidence) {
            auto result = m_indicator_tracking_keys.insert(key);
            if (result.second) { // Key was newly inserted
                keys_added++;
                dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                    " - added key '" << key << "' to tracking list (has confidence < " <<
                    LOW_CONFIDENCE_THRESHOLD << ")";
            }
        }
    }

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
        " - added " << keys_added << " keys with low confidence values to tracking list";
}
