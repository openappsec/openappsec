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

double logn(double x, double n)
{
    return log(x) / log(n);
}

ConfidenceCalculator::ConfidenceCalculator(size_t minSources,
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
    m_mainLoop(Singleton::Consume<I_MainLoop>::by<WaapComponent>()),
    m_routineId(0),
    m_filesToRemove()
{
    restore();

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

    ~WindowLogPost()
    {
        window_logger.get().clear();
        window_logger.get().rehash(0);
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


// Function to handle compression
void compressDataWrapper(const string& uncompressed_data, size_t chunk_size, vector<unsigned char>& compressed_data) {
    auto compression_stream = initCompressionStream();
    size_t offset = 0;

    while (offset < uncompressed_data.size()) {
        size_t current_chunk_size = std::min(chunk_size, uncompressed_data.size() - offset);
        bool is_last = (offset + current_chunk_size >= uncompressed_data.size());
        CompressionResult chunk_res = compressData(
            compression_stream,
            CompressionType::GZIP,
            static_cast<uint32_t>(current_chunk_size),
            reinterpret_cast<const unsigned char*>(uncompressed_data.c_str() + offset),
            is_last ? 1 : 0
        );

        if (!chunk_res.ok) {
            finiCompressionStream(compression_stream);
            throw runtime_error("Compression failed");
        }

        if (chunk_res.output && chunk_res.num_output_bytes > 0) {
            compressed_data.insert(
                compressed_data.end(),
                chunk_res.output,
                chunk_res.output + chunk_res.num_output_bytes
            );
            free(chunk_res.output);
        }

        offset += current_chunk_size;
    }

    finiCompressionStream(compression_stream);
}


Maybe<void> ConfidenceCalculator::writeToFile(const string& path, const vector<unsigned char>& data)
{
    ofstream file(path, ios::binary);
    if (!file.is_open()) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to open file: " << path
            << ", errno: " << errno << ", strerror: " << strerror(errno);
        return genError("Failed to open file");
    }

    // Write compressed data to file in chunks to avoid large memory usage
    const uint CHUNK_SIZE = getProfileAgentSettingWithDefault<uint>(
        64 * 1024, // 64 KiB
        "appsecLearningSettings.writeChunkSize"
    );
    size_t offset = 0;
    while (offset < data.size()) {
        size_t current_chunk_size = min(static_cast<size_t>(CHUNK_SIZE), data.size() - offset);
        file.write(reinterpret_cast<const char *>(data.data()) + offset, current_chunk_size);
        offset += current_chunk_size;
        m_mainLoop->yield(false);
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Write progress: " << offset << "/" << data.size()
            << " bytes (" << (offset * 100 / data.size()) << "%) - yielded";
    }
    file.close();
    return Maybe<void>();
}

void ConfidenceCalculator::saveTimeWindowLogger()
{
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

    stringstream ss;
    {
        cereal::JSONOutputArchive archive(ss);
        archive(cereal::make_nvp("logger", *m_time_window_logger));
    }

    m_mainLoop->yield(false);
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "JSON serialized, size: " << ss.str().size() << " bytes";

    string data = ss.str();

    const uint COMPRESSED_CHUNK_SIZE = getProfileAgentSettingWithDefault<uint>(
        16 * 1024, // 16KB
        "appsecLearningSettings.compressionChunkSize"
    );
    auto compression_stream = initCompressionStream();
    size_t offset = 0;
    vector<unsigned char> compressed_data;
    bool ok = true;

    while (offset < data.size()) {
        size_t chunk_size = min(static_cast<size_t>(COMPRESSED_CHUNK_SIZE), data.size() - offset);
        bool is_last = (offset + chunk_size >= data.size());
        CompressionResult chunk_res = compressData(
            compression_stream,
            CompressionType::GZIP,
            static_cast<uint32_t>(chunk_size),
            reinterpret_cast<const unsigned char *>(data.c_str() + offset),
            is_last ? 1 : 0
        );
        if (!chunk_res.ok) {
            ok = false;
            break;
        }
        if (chunk_res.output && chunk_res.num_output_bytes > 0) {
            compressed_data.insert(
                compressed_data.end(),
                chunk_res.output,
                chunk_res.output + chunk_res.num_output_bytes
            );
            free(chunk_res.output);
        }
        offset += chunk_size;
        m_mainLoop->yield(false);
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Compression progress: " << offset << "/" << data.size()
            << " bytes processed (" << (offset * 100 / data.size()) << "%) - yielded";
    }
    finiCompressionStream(compression_stream);

    if (!ok) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to compress data";
        m_time_window_logger_backup = m_time_window_logger;
        return;
    }

    auto maybeError = writeToFile(m_path_to_backup, compressed_data);
    if (!maybeError.ok()) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to write the backup file: " << m_path_to_backup;
        m_time_window_logger_backup = m_time_window_logger;
        m_path_to_backup = "";
    } else {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Finished writing the backup file: " << m_path_to_backup;
    }
}

shared_ptr<ConfidenceCalculator::KeyValSourcesLogger> ConfidenceCalculator::loadTimeWindowLogger()
{
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Loading the time window logger from: " << m_path_to_backup;
    if (m_path_to_backup.empty()) {
        dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "No backup file path set, cannot load logger";
        return nullptr;
    }

    ifstream file(m_path_to_backup, ios::binary);
    if (!file.is_open()) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to open file: " << m_path_to_backup
            << ", errno: " << errno << ", strerror: " << strerror(errno);
        return nullptr;
    }

    stringstream buffer;
    // Read the file in chunks to avoid large memory usage
    const uint READ_CHUNK_SIZE = getProfileAgentSettingWithDefault<uint>(
        16 * 1024,
        "appsecLearningSettings.readChunkSize"); // 16 KiB
    vector<char> chunk(READ_CHUNK_SIZE);
    size_t chunk_size = static_cast<size_t>(READ_CHUNK_SIZE);
    size_t total_bytes_read = 0;
    size_t chunks_read = 0;

    while (file.peek() != EOF) {
        file.read(chunk.data(), chunk_size);
        streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            buffer.write(chunk.data(), bytesRead);
            total_bytes_read += bytesRead;
            chunks_read++;
        }
        m_mainLoop->yield(false);
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Read chunk " << chunks_read
            << " (" << total_bytes_read << " bytes total) - yielded";
    }
    file.close();

    remove(m_path_to_backup.c_str());
    m_path_to_backup = "";

    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Completed reading " << total_bytes_read
        << " bytes in " << chunks_read << " chunks";

    string compressed_data = buffer.str();
    auto compression_stream = initCompressionStream();

    chunk_size = static_cast<size_t>(
        getProfileAgentSettingWithDefault<uint>(
            32 * 1024, // 32KiB
            "appsecLearningSettings.compressionChunkSize"
        )
    );
    size_t offset = 0;
    string decompressed_data;

    while (offset < compressed_data.size()) {
        size_t current_chunk_size = min(chunk_size, compressed_data.size() - offset);
        DecompressionResult res = decompressData(
            compression_stream,
            current_chunk_size,
            reinterpret_cast<const unsigned char *>(compressed_data.c_str() + offset)
        );

        if (!res.ok) {
            dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to decompress data from file: " << m_path_to_backup;
            finiCompressionStream(compression_stream);
            return nullptr;
        }

        decompressed_data.append(reinterpret_cast<const char *>(res.output), res.num_output_bytes);
        free(res.output);
        res.output = nullptr;
        res.num_output_bytes = 0;

        offset += current_chunk_size;

        // Yield control after processing each chunk
        m_mainLoop->yield(false);
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Decompression progress: " << offset << "/" << compressed_data.size()
            << " bytes (" << (offset * 100 / compressed_data.size()) << "%) - yielded";
    }

    finiCompressionStream(compression_stream);

    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Decompressed data size: " << decompressed_data.size()
        << " bytes (compression ratio: " << (float)decompressed_data.size() / compressed_data.size() << "x)";

    stringstream decompressed_stream(decompressed_data);
    auto window_logger = make_shared<KeyValSourcesLogger>();

    try {
        cereal::JSONInputArchive archive(decompressed_stream);
        archive(cereal::make_nvp("logger", *window_logger));
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Successfully deserialized logger from JSON";
    } catch (cereal::Exception& e) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to load the time window logger: " << e.what();
        return nullptr;
    }

    return window_logger;
}

bool ConfidenceCalculator::postData()
{
    saveTimeWindowLogger();
    m_mainLoop->yield(false);
    WindowLogPost currentWindow(*m_time_window_logger);
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

void ConfidenceCalculator::pullData(const vector<string>& files)
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
    for (auto file : files)
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
        for (auto& log : remoteLogger)
        {
            const string & key = log.first;
            for (auto& entry : log.second)
            {
                const string & value = entry.first;
                for (auto & source : entry.second)
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
        if (m_path_to_backup != "")
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
    if (m_path_to_backup != "")
    {
        remove(m_path_to_backup.c_str());
        m_path_to_backup = "";
    }
}

void ConfidenceCalculator::updateState(const vector<string>& files)
{
    pullProcessedData(files);
    // clear temp data
    if (m_time_window_logger_backup)
    {
        m_time_window_logger_backup->clear();
        m_time_window_logger_backup.reset();
    }
    if (m_path_to_backup != "")
    {
        remove(m_path_to_backup.c_str());
        m_path_to_backup = "";
    }
}

void ConfidenceCalculator::pullProcessedData(const vector<string>& files)
{
    dbgTrace(D_WAAP) << "Fetching the confidence set object";
    m_post_index = 0;
    bool is_first_pull = true;
    bool is_ok = false;
    for (auto file : files)
    {
        ConfidenceFileDecryptor getConfFile;
        bool res = sendObjectWithRetry(getConfFile,
            HTTPMethod::GET,
            getUri() + "/" + file);
        is_ok |= res;
        if (res && getConfFile.getConfidenceSet().ok())
        {
            mergeFromRemote(getConfFile.getConfidenceSet().unpackMove(), is_first_pull);
            is_first_pull = false;
        }
        if (res && getConfFile.getConfidenceLevels().ok())
        {
            // write to disk the confidence levels
            saveConfidenceLevels(getConfFile.getConfidenceLevels());
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
    string postUrl = getUri() + "/" + m_remotePath + "/processed/confidence.data";
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Posting the confidence set object to: " << postUrl;
    ConfidenceFileEncryptor postConfFile(m_confident_sets, m_confidence_level);
    sendNoReplyObjectWithRetry(postConfFile,
        HTTPMethod::PUT,
        postUrl);
}

void ConfidenceCalculator::serialize(ostream& stream)
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
void ConfidenceCalculator::deserialize(istream& stream)
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

void ConfidenceCalculator::loadVer0(cereal::JSONInputArchive& archive)
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

void ConfidenceCalculator::convertWindowSummaryToConfidenceLevel(const WindowsConfidentValuesList& windows)
{
    for (const auto& windowKey : windows)
    {
        for (const auto& window : windowKey.second)
        {
            for (const auto& value : window)
            {
                m_confidence_level[windowKey.first][value] += ceil(SCORE_THRESHOLD / m_params.minIntervals);
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
    params.maxMemoryUsage = defaultConfidenceMemUsage;
    reset(params);
    for (auto& confidentSet : confidenceSets)
    {
        m_confident_sets[normalize_param(confidentSet.first)] = confidentSet.second;
    }
    for (auto& confidenceLevel : confidenceLevels)
    {
        string normParam = normalize_param(confidenceLevel.first);
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
                    double maxScore = max(m_confidence_level[normParam][valueLevelItr.first],
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
    params.maxMemoryUsage = defaultConfidenceMemUsage;

    reset(params);

    convertWindowSummaryToConfidenceLevel(windows_summary_list);
}

bool ConfidenceCalculator::tryParseVersionBasedOnNames(
    cereal::JSONInputArchive& archive,
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

        confidence_set[set.first].second = max<size_t>(confidence_set[set.first].second, set.second.second);
        last_indicators_update = max<size_t>(last_indicators_update, confidence_set[set.first].second);
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
    unordered_map<Key, ValueSetWithTime> confidenceSetCopy = m_confident_sets;
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
    auto& sources_set = (*m_time_window_logger)[key][value];
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

void ConfidenceCalculator::removeBadSources(SourcesSet& sources, const vector<string>* badSources)
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

void ConfidenceCalculator::loadConfidenceLevels()
{
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
        " - loading the confidence levels from disk, latest index: " << m_latest_index <<
        ", intervals count: " << getIntervalsCount();

    string file_path = m_filePath + ".levels." + to_string((m_latest_index + getIntervalsCount() - 1) % 2) + ".gz";
    ifstream file(file_path, ios::binary);
    if (!file.is_open()) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to open the file: " << file_path;
        return;
    }

    stringstream buffer;
    // Read the file in chunks to avoid large memory usage
    const uint READ_CHUNK_SIZE = getProfileAgentSettingWithDefault<uint>(
        16 * 1024,
        "appsecLearningSettings.readChunkSize"); // 16 KiB
    vector<char> chunk(READ_CHUNK_SIZE);
    size_t chunk_size = static_cast<size_t>(READ_CHUNK_SIZE);
    while (file.peek() != EOF) {
        file.read(chunk.data(), chunk_size);
        streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            buffer.write(chunk.data(), bytesRead);
        }
        m_mainLoop->yield(false);
    }
    file.close();

    string compressed_data = buffer.str();

    auto compression_stream = initCompressionStream();
    DecompressionResult res;
    res.ok = true;
    res.output = nullptr;
    res.num_output_bytes = 0;
    size_t offset = 0;
    const size_t CHUNK_SIZE = static_cast<size_t>(
        getProfileAgentSettingWithDefault<uint>(
            16 * 1024, // 16KiB
            "appsecLearningSettings.compressionChunkSize"
        )
    );
    vector<char> decompressed_data_vec;
    while (offset < compressed_data.size()) {
        size_t current_chunk_size = min(CHUNK_SIZE, compressed_data.size() - offset);
        DecompressionResult chunk_res = decompressData(
            compression_stream,
            current_chunk_size,
            reinterpret_cast<const unsigned char *>(compressed_data.c_str() + offset)
        );
        if (!chunk_res.ok) {
            res.ok = false;
            break;
        }
        if (chunk_res.output && chunk_res.num_output_bytes > 0) {
            // Append directly to the vector to avoid extra copies
            size_t old_size = decompressed_data_vec.size();
            decompressed_data_vec.resize(old_size + chunk_res.num_output_bytes);
            memcpy(decompressed_data_vec.data() + old_size, chunk_res.output, chunk_res.num_output_bytes);
            free(chunk_res.output);
        }
        offset += current_chunk_size;
        m_mainLoop->yield(false);
    }
    finiCompressionStream(compression_stream);

    if (!res.ok) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to decompress the confidence levels data.";
        return;
    }

    string decompressed_data(decompressed_data_vec.begin(), decompressed_data_vec.end());
    stringstream decompressed_stream(decompressed_data);

    try {
        cereal::JSONInputArchive archive(decompressed_stream);
        archive(cereal::make_nvp("confidence_levels", m_confidence_level));
    } catch (runtime_error &e) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to load the confidence levels from disk: " << e.what();
    }
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
        " - loaded the confidence levels from disk, latest index: " << m_latest_index <<
        ", intervals count: " << getIntervalsCount();
    m_mainLoop->yield(false);
    if (m_confidence_level.empty())
    {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to load the confidence levels from disk";
    }
}

void ConfidenceCalculator::saveConfidenceLevels()
{
    Maybe<ConfidenceCalculator::ConfidenceLevels> confidenceLevels(genError("not available"));
    saveConfidenceLevels(confidenceLevels);
}

void ConfidenceCalculator::saveConfidenceLevels(Maybe<ConfidenceCalculator::ConfidenceLevels> confidenceLevels)
{
    string file_path = m_filePath + ".levels." + to_string((m_latest_index + getIntervalsCount()) % 2) + ".gz";
    stringstream serialized_data;

    try {
        {
            cereal::JSONOutputArchive archive(serialized_data);
            if (confidenceLevels.ok()) {
                archive(cereal::make_nvp("confidence_levels", confidenceLevels.unpackMove()));
            } else {
                archive(cereal::make_nvp("confidence_levels", m_confidence_level));
            }
        }
    } catch (runtime_error &e) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to serialize the confidence levels: " << e.what();
        return;
    }
    m_mainLoop->yield(false);

    string uncompressed_data = serialized_data.str();
    const size_t CHUNK_SIZE = 16 * 1024; // 16 KiB
    vector<unsigned char> compressed_data;

    try {
        compressDataWrapper(uncompressed_data, CHUNK_SIZE, compressed_data);
        writeToFile(file_path, compressed_data);
    } catch (const runtime_error& e) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to compress the confidence levels data: " << e.what();
    }

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
        SourcesCounters& srcCtrs = sourcesCtrItr.second;
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
        SourcesSet& sourcesUnion = srcCtrs[m_null_obj];
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

    for (auto& keyMap : m_confidence_level)
    {
        for (auto& valMap : keyMap.second)
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

void ConfidenceCalculator::setOwner(const string& owner)
{
    m_owner = owner + "/ConfidenceCalculator";
}

bool ConfidenceCalculatorParams::operator==(const ConfidenceCalculatorParams& other)
{
    return (minSources == other.minSources &&
        minIntervals == other.minIntervals &&
        intervalDuration == other.intervalDuration &&
        ratioThreshold == other.ratioThreshold &&
        learnPermanently == other.learnPermanently &&
        maxMemoryUsage == other.maxMemoryUsage);
}

ostream& operator<<(ostream& os, const ConfidenceCalculatorParams& ccp)
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
        "ConfidenceCalculator garbage collection"
    );
}
