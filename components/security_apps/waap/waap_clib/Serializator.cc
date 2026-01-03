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

#include "i_serialize.h"
#include "waap.h"
#include "Waf2Util.h"
#include "WaapAssetState.h"
#include "i_instance_awareness.h"
#include "buffered_compressed_stream.h"
#include <boost/regex.hpp>
#include <sstream>
#include <fstream>
#include <functional>
#include "debug.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>
#include "SyncLearningNotification.h"
#include "report_messaging.h"
#include "compression_utils.h"
#include "config.h"

USE_DEBUG_FLAG(D_WAAP_SERIALIZE);

namespace ch = std::chrono;
using namespace std;
typedef ch::duration<size_t, ratio<86400>> days;

// Define interval between successful sync times
static const ch::minutes assetSyncTimeSliceLength(10);
static const int remoteSyncMaxPollingAttempts = 10;
static const string defaultLearningHost = "appsec-learning-svc";
static const string defaultSharedStorageHost = "appsec-shared-storage-svc";

#define SHARED_STORAGE_HOST_ENV_NAME "SHARED_STORAGE_HOST"
#define LEARNING_HOST_ENV_NAME "LEARNING_HOST"

bool RestGetFile::loadJson(const string &json)
{
    // Try streaming approach first - handles both encryption and compression
    try {
        dbgTrace(D_WAAP_SERIALIZE) << "Attempting to use streaming approach for JSON loading, data size: "
            << json.size() << " bytes";
        stringstream json_stream(json);
        // if input json is big then yield to allow other routines to run
        if (json.size() > 1000000) {
            dbgTrace(D_WAAP_SERIALIZE) << "Input JSON is large, yielding to allow other routines to run";
            YIELD_IF_POSSIBLE();
        }
        BufferedCompressedInputStream decompressed_stream(json_stream);
        {
            cereal::JSONInputArchive json_archive(decompressed_stream);
            load(json_archive);
        }
        YIELD_IF_POSSIBLE();
        dbgTrace(D_WAAP_SERIALIZE) << "Successfully loaded JSON using streaming approach";
        return true;
    }
    catch (const exception &e) {
        dbgDebug(D_WAAP_SERIALIZE) << "Failed to load JSON using streaming approach: " << e.what()
            << ". Falling back to legacy approach.";
        // Fall back to the legacy approach for backward compatibility
    }
    catch (...) {
        dbgDebug(D_WAAP_SERIALIZE) << "Failed to load JSON using streaming approach"
            << ". Falling back to legacy approach.";
        // Fall back to the legacy approach for backward compatibility
    }

    // Legacy approach: manual decryption and decompression
    string json_str;
    json_str = json;
    if (!Waap::Util::isGzipped(json_str))
    {
        return ClientRest::loadJson(json_str);
    }
    YIELD_IF_POSSIBLE();
    dbgTrace(D_WAAP_SERIALIZE) << "before decompression in loadJson, data size: "
        << json_str.size() << " bytes";
    auto compression_stream = initCompressionStream();
    DecompressionResult res = decompressData(
        compression_stream,
        json_str.size(),
        reinterpret_cast<const unsigned char *>(json_str.c_str()));

    if (res.ok){
        json_str = string((const char *)res.output, res.num_output_bytes);
        if (res.output) free(res.output);
        res.output = nullptr;
        res.num_output_bytes = 0;
    }

    finiCompressionStream(compression_stream);
    YIELD_IF_POSSIBLE();
    dbgTrace(D_WAAP_SERIALIZE) << "Yielded after legacy decompression in loadJson, decompressed size: "
        << json_str.size() << " bytes";

    return ClientRest::loadJson(json_str);
}

Maybe<string> RestGetFile::genJson() const
{
    stringstream output_stream;
    try
    {
        BufferedCompressedOutputStream compressed_out(output_stream);
        {
            cereal::JSONOutputArchive json_archive(compressed_out, cereal::JSONOutputArchive::Options::NoIndent());
            save(json_archive);
        }
        compressed_out.close();
    }
    catch (const exception &e)
    {
        dbgWarning(D_WAAP_SERIALIZE) << "Failed to generate JSON: " << e.what();
        return genError("Failed to generate JSON: " + string(e.what()));
    }
    return output_stream.str();
}

// Class to handle retrieving the state timestamp file from learning service
class StateTimestampRetriever : public ClientRest
{
public:
    StateTimestampRetriever() {}

    Maybe<string> getStateTimestamp() const
    {
        if (timestamp.get().empty()) {
            return genError("State timestamp is empty");
        }
        return timestamp.get();
    }
private:
    S2C_PARAM(string, timestamp);
};

SerializeToFilePeriodically::SerializeToFilePeriodically(ch::seconds pollingIntervals, const string &filePath) :
    SerializeToFileBase(filePath),
    m_lastSerialization(0),
    m_interval(pollingIntervals)
{
    I_TimeGet* timer = Singleton::Consume<I_TimeGet>::by<WaapComponent>();

    if (timer != NULL)
    {
        m_lastSerialization = timer->getMonotonicTime();
    }
}

SerializeToFilePeriodically::~SerializeToFilePeriodically()
{

}

void SerializeToFilePeriodically::backupWorker()
{
    I_TimeGet* timer = Singleton::Consume<I_TimeGet>::by<WaapComponent>();
    auto currentTime = timer->getMonotonicTime();

    dbgTrace(D_WAAP_SERIALIZE) << "backup worker: current time: " << currentTime.count();

    if (currentTime - m_lastSerialization >= m_interval)
    {
        dbgTrace(D_WAAP_SERIALIZE) << "backup worker: backing up data";
        m_lastSerialization = currentTime;
        // save data
        saveData();

        dbgTrace(D_WAAP_SERIALIZE) << "backup worker: data is backed up";
    }
}

void SerializeToFilePeriodically::setInterval(ch::seconds newInterval)
{
    if (m_interval != newInterval)
    {
        m_interval = newInterval;
        I_TimeGet* timer = Singleton::Consume<I_TimeGet>::by<WaapComponent>();
        m_lastSerialization = timer->getMonotonicTime();
    }
}

SerializeToFileBase::SerializeToFileBase(const string &fileName) : m_filePath(fileName)
{
    dbgTrace(D_WAAP_SERIALIZE) << "SerializeToFileBase::SerializeToFileBase() fname='" << m_filePath
        << "'";
}

SerializeToFileBase::~SerializeToFileBase()
{

}

void SerializeToFileBase::saveData()
{
    fstream filestream;
    auto maybe_routine = Singleton::Consume<I_MainLoop>::by<WaapComponent>()->getCurrentRoutineId();
    dbgTrace(D_WAAP_SERIALIZE) << "saving to file: " << m_filePath;
    filestream.open(m_filePath, fstream::out);

    stringstream ss;

    if (filestream.is_open() == false) {
        dbgWarning(D_WAAP_SERIALIZE) << "failed to open file: " << m_filePath << " Error: "
            << strerror(errno);
        return;
    }
    if (maybe_routine.ok()) {
        Singleton::Consume<I_MainLoop>::by<WaapComponent>()->yield(false);
    }
    serialize(ss);

    if (maybe_routine.ok()) {
        Singleton::Consume<I_MainLoop>::by<WaapComponent>()->yield(false);
    }
    const string &data = ss.str(); // Use const reference to avoid copying
    dbgDebug(D_WAAP_SERIALIZE) << "Serialized data size: " << data.size() << " bytes";

    // Get chunk size from profile settings, with default of 16 MiB for compression chunks
    const size_t CHUNK_SIZE = static_cast<size_t>(
        getProfileAgentSettingWithDefault<uint>(16 * 1024 * 1024, "appsecLearningSettings.writeChunkSize"));
    // Get chunk size for writing compressed data, with default of 16 MiB
    const size_t COMPRESSED_CHUNK_SIZE = static_cast<size_t>(
        getProfileAgentSettingWithDefault<uint>(16 * 1024 * 1024, "appsecLearningSettings.compressionChunkSize"));

    auto compression_stream = initCompressionStream();
    size_t offset = 0;
    vector<unsigned char> compressed_data;
    bool ok = true;
    size_t chunk_count = 0;

    // Process data in chunks for compression
    while (offset < data.size()) {
        size_t chunk_size = min(COMPRESSED_CHUNK_SIZE, data.size() - offset);
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
            chunk_res.output = nullptr;
        }

        offset += chunk_size;
        chunk_count++;
        if (maybe_routine.ok()) {
            Singleton::Consume<I_MainLoop>::by<WaapComponent>()->yield(false);
            dbgTrace(D_WAAP_SERIALIZE) << "Compression chunk " << chunk_count
                << " processed (" << offset << "/" << data.size() << " bytes, "
                << (offset * 100 / data.size()) << "%) - yielded";
        }
    }
    finiCompressionStream(compression_stream);
    dbgDebug(D_WAAP_SERIALIZE) << "Finished compression stream. "
        << "Total chunks: " << chunk_count << ", Compression ratio: "
        << (data.size() > 0 ? (float)compressed_data.size() / data.size() : 0) << "x";

    if (!ok) {
        dbgWarning(D_WAAP_SERIALIZE) << "Failed to compress data";
        filestream.close();
        return;
    }

    dbgDebug(D_WAAP_SERIALIZE) << "Compression complete: " << data.size() << " bytes -> "
        << compressed_data.size() << " bytes (ratio: "
        << (data.size() > 0 ? (float)compressed_data.size() / data.size() : 0) << "x)";


    // Use compressed data directly
    string data_to_write(reinterpret_cast<const char*>(compressed_data.data()), compressed_data.size());

    // Write data to file in chunks with yield points
    offset = 0;
    size_t write_chunks = 0;

    while (offset < data_to_write.size()) {
        size_t current_chunk_size = min(CHUNK_SIZE, data_to_write.size() - offset);
        filestream.write(data_to_write.c_str() + offset, current_chunk_size);
        offset += current_chunk_size;
        write_chunks++;
        Singleton::Consume<I_MainLoop>::by<WaapComponent>()->yield(false);
        dbgTrace(D_WAAP_SERIALIZE) << "Write chunk " << write_chunks
            << " complete: " << offset << "/" << data_to_write.size() << " bytes ("
            << (offset * 100 / data_to_write.size()) << "%) - yielded";
    }

    filestream.close();
    dbgDebug(D_WAAP_SERIALIZE) << "Finished writing backup file: " << m_filePath
        << " (" << data_to_write.size() << " bytes in " << write_chunks << " chunks)";
}

string decompress(const string &fileContent) {
    if (!Waap::Util::isGzipped(fileContent)) {
        dbgTrace(D_WAAP_SERIALIZE) << "file note zipped";
        return fileContent;
    }
    auto compression_stream = initCompressionStream();

    DecompressionResult res = decompressData(
        compression_stream,
        fileContent.size(),
        reinterpret_cast<const unsigned char *>(fileContent.c_str())
    );

    finiCompressionStream(compression_stream);

    if (res.ok) {
        string decompressedData = string((const char *)res.output, res.num_output_bytes);
        if (res.output) free(res.output);
        res.output = nullptr;
        res.num_output_bytes = 0;
        return decompressedData;
    }

    return fileContent;
}

void SerializeToFileBase::loadFromFile(const string &filePath)
{
    dbgTrace(D_WAAP_SERIALIZE) << "loadFromFile() file: " << filePath;
    fstream filestream;

    filestream.open(filePath, fstream::in);

    if (filestream.is_open() == false) {
        dbgWarning(D_WAAP_SERIALIZE) << "failed to open file: " << filePath << " Error: " <<
            strerror(errno);
        if (!Singleton::exists<I_InstanceAwareness>() || errno != ENOENT)
        {
            return;
        }
        // if we fail to open a file because it doesn't exist and instance awareness is present
        // try to strip the unique ID from the path and load the file from the parent directory
        // that might exist in previous run where instance awareness didn't exits.
        I_InstanceAwareness* instanceAwareness = Singleton::Consume<I_InstanceAwareness>::by<WaapComponent>();
        Maybe<string> id = instanceAwareness->getUniqueID();
        if (!id.ok())
        {
            return;
        }
        string idStr = "/" + id.unpack() + "/";
        size_t idPosition = filePath.find(idStr);
        if (idPosition != string::npos)
        {
            string modifiedFilePath = filePath;  // Create a mutable copy
            modifiedFilePath.erase(idPosition, idStr.length() - 1);
            dbgDebug(D_WAAP_SERIALIZE) << "retry to load file from : " << modifiedFilePath;
            loadFromFile(modifiedFilePath);
        }
        return;
    }

    dbgTrace(D_WAAP_SERIALIZE) << "loading from file: " << filePath;

    try {
        dbgTrace(D_WAAP_SERIALIZE) << "Attempting to load file using streaming approach";
        BufferedCompressedInputStream decompressed_stream(filestream);
        deserialize(decompressed_stream);
        filestream.close();
        dbgTrace(D_WAAP_SERIALIZE) << "Successfully loaded file using streaming approach";
        return;
    }
    catch (const exception &e) {
        dbgDebug(D_WAAP_SERIALIZE) << "Failed to load file using streaming approach: " << e.what()
            << ". Falling back to legacy approach.";
        // Fall back to the legacy approach for backward compatibility
        filestream.clear();
        filestream.seekg(0, ios::beg);
    }

    // Legacy approach: manual file reading, decryption, and decompression
    filestream.seekg(0, ios::end);
    int length = filestream.tellg();
    dbgTrace(D_WAAP_SERIALIZE) << "file length: " << length;
    assert(length >= 0); // length -1 really happens if filePath is a directory (!)
    vector<char> buffer(length);       // Use vector instead of raw pointer for safety
    filestream.seekg(0, ios::beg);    // go back to the beginning
    if (!filestream.read(buffer.data(), length))  // read the whole file into the buffer
    {
        filestream.close();
        dbgWarning(D_WAAP_SERIALIZE) << "Failed to read file, file: " << filePath;
        return;
    }
    filestream.close();

    string dataObfuscated(buffer.begin(), buffer.end());

    stringstream ss;
    ss << decompress(dataObfuscated);

    try
    {
        deserialize(ss);
        dbgTrace(D_WAAP_SERIALIZE) << "Successfully loaded file using legacy approach";
    }
    catch (runtime_error & e) {
        dbgWarning(D_WAAP_SERIALIZE) << "failed to deserialize file: " << m_filePath << ", error: " <<
            e.what();
    }
}

void SerializeToFileBase::restore()
{
    loadFromFile(m_filePath);
}

RemoteFilesList::RemoteFilesList() : files(), filesPathsList()
{

}

// parses xml instead of json
// extracts a file list in <Contents><Key>
bool RemoteFilesList::loadJson(const string &xml)
{
    xmlDocPtr doc; // the resulting document tree
    dbgTrace(D_WAAP_SERIALIZE) << "XML input: " << xml;
    doc = xmlParseMemory(xml.c_str(), xml.length());

    if (doc == NULL) {
        dbgWarning(D_WAAP_SERIALIZE) << "Failed to parse " << xml;
        return false;
    }

    xmlNodePtr node = doc->children;
    if (node->children == NULL)
    {
        return false;
    }
    node = node->children;

    xmlChar *contents_name = xmlCharStrdup("Contents");
    xmlChar *key_name = xmlCharStrdup("Key");
    xmlChar *last_modified_name = xmlCharStrdup("LastModified");

    // allows to get reference to the internal member and modify it
    files.setActive(true);
    while (node != NULL)
    {
        if (xmlStrEqual(contents_name, node->name) == 1)
        {
            dbgTrace(D_WAAP_SERIALIZE) << "Found the Contents element";
            xmlNodePtr contents_node = node->children;
            string file;
            string lastModified;
            while (contents_node != NULL)
            {
                if (xmlStrEqual(key_name, contents_node->name) == 1)
                {
                    dbgTrace(D_WAAP_SERIALIZE) << "Found the Key element";
                    xmlChar* xml_file = xmlNodeGetContent(contents_node);
                    file = string(reinterpret_cast<const char*>(xml_file));
                    xmlFree(xml_file);
                }
                if (xmlStrEqual(last_modified_name, contents_node->name) == 1)
                {
                    dbgTrace(D_WAAP_SERIALIZE) << "Found the LastModified element";
                    xmlChar* xml_file = xmlNodeGetContent(contents_node);
                    lastModified = string(reinterpret_cast<const char*>(xml_file));
                    xmlFree(xml_file);
                }
                if (!file.empty() && !lastModified.empty())
                {
                    dbgTrace(D_WAAP_SERIALIZE) << "Adding the file: " << file <<
                        " last modified: " << lastModified;
                    break;
                }
                contents_node = contents_node->next;
            }
            files.get().push_back(FileMetaData{ move(file), move(lastModified) });
            filesPathsList.push_back(files.get().back().filename); // Use the moved string to avoid extra copy
        }
        node = node->next;
    }

    // free up memory
    xmlFree(last_modified_name);
    xmlFree(contents_name);
    xmlFree(key_name);
    xmlFreeDoc(doc);
    return true;
}

const vector<string> &RemoteFilesList::getFilesList() const
{
    return filesPathsList;
}

const vector<FileMetaData> &RemoteFilesList::getFilesMetadataList() const
{
    return files.get();
}

SerializeToLocalAndRemoteSyncBase::SerializeToLocalAndRemoteSyncBase(
    ch::minutes interval,
    ch::seconds waitForSync,
    const string &filePath,
    const string &remotePath,
    const string &assetId,
    const string &owner
) :
    SerializeToFileBase(filePath),
    m_remotePath(replaceAllCopy(remotePath, "//", "/")),
    m_interval(0),
    m_owner(owner),
    m_assetId(replaceAllCopy(assetId, "/", "")),
    m_remoteSyncEnabled(true),
    m_pMainLoop(nullptr),
    m_waitForSync(waitForSync),
    m_workerRoutineId(0),
    m_daysCount(0),
    m_windowsCount(0),
    m_intervalsCounter(0),
    m_isAssetIdUuid(Waap::Util::isUuid(assetId)),
    m_shared_storage_host(genError("not set")),
    m_learning_host(genError("not set"))
{
    dbgInfo(D_WAAP_SERIALIZE) << "Create SerializeToLocalAndRemoteSyncBase. assetId='" << assetId <<
        "', owner='" << m_owner << "'";
    m_pMainLoop = Singleton::Consume<I_MainLoop>::by<WaapComponent>();

    if (Singleton::exists<I_AgentDetails>() &&
        Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getOrchestrationMode() ==
            OrchestrationMode::HYBRID) {
        char* sharedStorageHost = getenv(SHARED_STORAGE_HOST_ENV_NAME);
        if (sharedStorageHost != NULL) {
            m_shared_storage_host = string(sharedStorageHost);
        } else {
            dbgWarning(D_WAAP_SERIALIZE) <<
                "shared storage host name(" <<
                SHARED_STORAGE_HOST_ENV_NAME <<
                ") is not set";
        }
        char* learningHost = getenv(LEARNING_HOST_ENV_NAME);
        if (learningHost != NULL) {
            m_learning_host = string(learningHost);
        } else {
            dbgWarning(D_WAAP_SERIALIZE) <<
                "learning host name(" <<
                SHARED_STORAGE_HOST_ENV_NAME <<
                ") is not set";
        }
    }
    if (remotePath != "") {
        // remote path is /<tenantId>/<assetId>/<type>
        auto parts = split(m_remotePath, '/');
        if (parts.size() > 2) {
            size_t offset = 0;
            if (parts[0].empty()) {
                offset = 1;
            }
            string type = "";
            for (size_t i = offset + 2; i < parts.size(); i++)
            {
                type += type.empty() ? parts[i] : "/" + parts[i];
            }
            m_type = type;
        }
    }
    setInterval(interval);
}

bool SerializeToLocalAndRemoteSyncBase::isBase() const
{
    return m_remotePath == "";
}

void SerializeToLocalAndRemoteSyncBase::waitSync()
{
    if (m_pMainLoop == nullptr)
    {
        return;
    }
    m_pMainLoop->yield(m_waitForSync);
}

string SerializeToLocalAndRemoteSyncBase::getUri()
{
    static const string hybridModeUri = "/api";
    static const string onlineModeUri = "/storage/waap";
    if (Singleton::exists<I_AgentDetails>() &&
        Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getOrchestrationMode() ==
        OrchestrationMode::HYBRID) return hybridModeUri;
    return onlineModeUri;
}

size_t SerializeToLocalAndRemoteSyncBase::getIntervalsCount()
{
    return m_intervalsCounter;
}

void SerializeToLocalAndRemoteSyncBase::incrementIntervalsCount()
{
    m_intervalsCounter++;
}

SerializeToLocalAndRemoteSyncBase::~SerializeToLocalAndRemoteSyncBase()
{

}

string SerializeToLocalAndRemoteSyncBase::getWindowId()
{
    return "window_" + to_string(m_daysCount) + "_" + to_string(m_windowsCount);
}

string SerializeToLocalAndRemoteSyncBase::getPostDataUrl()
{
    string agentId = Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getAgentId();
    if (Singleton::exists<I_InstanceAwareness>())
    {
        I_InstanceAwareness* instance = Singleton::Consume<I_InstanceAwareness>::by<WaapComponent>();
        Maybe<string> uniqueId = instance->getUniqueID();
        if (uniqueId.ok() && !uniqueId.unpack().empty())
        {
            agentId += "/" + uniqueId.unpack();
        }
    }
    string windowId = getWindowId();
    return getUri() + "/" + m_remotePath + "/" + windowId + "/" + agentId + "/data.data";
}
void SerializeToLocalAndRemoteSyncBase::setRemoteSyncEnabled(bool enabled)
{
    m_remoteSyncEnabled = enabled;
}

void SerializeToLocalAndRemoteSyncBase::setInterval(ch::seconds newInterval)
{
    if (newInterval == m_interval)
    {
        return;
    }
    dbgDebug(D_WAAP_SERIALIZE) << "setInterval: from " << m_interval.count() << " to " <<
        newInterval.count() << " seconds. assetId='" << m_assetId << "', owner='" << m_owner << "'";

    m_interval = newInterval;

    if (m_workerRoutineId != 0)
    {
        return;
    }
    I_MainLoop::Routine syncRoutineOnLoad = [this]() {
        I_TimeGet* timer = Singleton::Consume<I_TimeGet>::by<WaapComponent>();
        ch::microseconds timeBeforeSyncWorker = timer->getWalltime();
        ch::microseconds timeAfterSyncWorker = timeBeforeSyncWorker;
        while (true)
        {
            m_daysCount = ch::duration_cast<days>(timeBeforeSyncWorker).count();

            ch::microseconds timeSinceMidnight = timeBeforeSyncWorker - ch::duration_cast<days>(timeBeforeSyncWorker);
            m_windowsCount = timeSinceMidnight / m_interval;

            // Distribute syncWorker tasks for different assets spread over assetSyncTimeSliceLengthintervals
            // It is guaranteed that for the same asset, sync events will start at the same time on all
            // http_transaction_host instances.
            size_t slicesCount = m_interval / assetSyncTimeSliceLength;
            size_t sliceIndex = 0;
            if (slicesCount != 0 && m_assetId != "") {
                sliceIndex = hash<string>{}(m_assetId) % slicesCount;
            }
            ch::seconds sliceOffset = assetSyncTimeSliceLength * sliceIndex;

            ch::microseconds remainingTime = m_interval - (timeAfterSyncWorker - timeBeforeSyncWorker) -
                timeBeforeSyncWorker % m_interval + sliceOffset;

            if (remainingTime > m_interval) {
                // on load between trigger and offset remaining time is larger than the interval itself
                remainingTime -= m_interval;
                dbgDebug(D_WAAP_SERIALIZE) << "adjusting remaining time: " << remainingTime.count();
                if (timeBeforeSyncWorker.count() != 0)
                {
                    auto updateTime = timeBeforeSyncWorker - m_interval;
                    m_daysCount = ch::duration_cast<days>(updateTime).count();

                    ch::microseconds timeSinceMidnight = updateTime - ch::duration_cast<days>(updateTime);
                    m_windowsCount = timeSinceMidnight / m_interval;
                }
            }

            if (remainingTime < ch::seconds(0)) {
                // syncWorker execution time was so large the remaining time became negative
                remainingTime = ch::seconds(0);
                dbgError(D_WAAP_SERIALIZE) << "syncWorker execution time (owner='" << m_owner <<
                    "', assetId='" << m_assetId << "') is " <<
                    ch::duration_cast<ch::seconds>(timeAfterSyncWorker - timeBeforeSyncWorker).count() <<
                    " seconds, too long to cause negative remainingTime. Waiting 0 seconds...";
            }

            dbgDebug(D_WAAP_SERIALIZE) << "current time: " << timeBeforeSyncWorker.count() << " \u00b5s" <<
                ": assetId='" << m_assetId << "'" <<
                ", owner='" << m_owner << "'" <<
                ", daysCount=" << m_daysCount <<
                ", windowsCount=" << m_windowsCount <<
                ", interval=" << m_interval.count() << " seconds"
                ", seconds till next window=" << ch::duration_cast<ch::seconds>(remainingTime - sliceOffset).count() <<
                ", sliceOffset=" << sliceOffset.count() << " seconds" <<
                ", hashIndex=" << sliceIndex <<
                ": next wakeup in " << ch::duration_cast<ch::seconds>(remainingTime).count() << " seconds";
            m_pMainLoop->yield(remainingTime);

            timeBeforeSyncWorker = timer->getWalltime();
            syncWorker();
            timeAfterSyncWorker = timer->getWalltime();
        }
    };
    m_workerRoutineId = m_pMainLoop->addOneTimeRoutine(
        I_MainLoop::RoutineType::System,
        syncRoutineOnLoad,
        "Sync worker learning on load"
    );
}

bool SerializeToLocalAndRemoteSyncBase::localSyncAndProcess()
{
    bool isBackupSyncEnabled = getProfileAgentSettingWithDefault<bool>(
        false,
        "appsecLearningSettings.backupLocalSync");

    if (!isBackupSyncEnabled) {
        dbgInfo(D_WAAP_SERIALIZE) << "Local sync is disabled";
        processData();
        saveData();
        return true;
    }

    RemoteFilesList rawDataFiles;

    dbgTrace(D_WAAP_SERIALIZE) << "Getting files of all agents";

    bool isSuccessful = sendObjectWithRetry(rawDataFiles,
        HTTPMethod::GET,
        getUri() + "/?list-type=2&prefix=" + m_remotePath + "/" + getWindowId() + "/");

    if (!isSuccessful)
    {
        dbgError(D_WAAP_SERIALIZE) << "Failed to get the list of files";
        return false;
    }

    pullData(rawDataFiles.getFilesList());
    processData();
    saveData();
    postProcessedData();
    return true;
}

ch::seconds SerializeToLocalAndRemoteSyncBase::getIntervalDuration() const
{
    return m_interval;
}

Maybe<string> SerializeToLocalAndRemoteSyncBase::getStateTimestampByListing()
{
    RemoteFilesList remoteFiles = getRemoteProcessedFilesList();
    if (remoteFiles.getFilesMetadataList().empty())
    {
        return genError("No remote processed files available");
    }
    dbgDebug(D_WAAP_SERIALIZE) << "State timestamp by listing: "
        << remoteFiles.getFilesMetadataList()[0].modified;

    return remoteFiles.getFilesMetadataList()[0].modified;
}

bool SerializeToLocalAndRemoteSyncBase::checkAndUpdateStateTimestamp(const string& currentStateTimestamp)
{
    // Check if the state has been updated since last check
    if (currentStateTimestamp != m_lastProcessedModified)
    {
        m_lastProcessedModified = currentStateTimestamp;
        dbgDebug(D_WAAP_SERIALIZE) << "State timestamp updated: " << m_lastProcessedModified;
        return true; // State was updated
    }
    return false; // State unchanged
}

void SerializeToLocalAndRemoteSyncBase::updateStateFromRemoteService()
{
    bool useFallbackMethod = false;
    for (int i = 0; i < remoteSyncMaxPollingAttempts; i++)
    {
        m_pMainLoop->yield(ch::seconds(60));

        // Try the dedicated timestamp file first
        Maybe<string> timestampResult(genError("Failed to get state timestamp"));
        if (!useFallbackMethod) {
            timestampResult = getStateTimestamp();
            if (!timestampResult.ok()) {
                dbgDebug(D_WAAP_SERIALIZE) << "Failed to get state timestamp from file: "
                    << timestampResult.getErr() << ", trying listing method";
                useFallbackMethod = true; // Switch to listing method on first failure
            }
        }
        else
        {
            dbgDebug(D_WAAP_SERIALIZE) << "trying listing method";
            timestampResult = getStateTimestampByListing();
        }

        if (!timestampResult.ok())
        {
            dbgWarning(D_WAAP_SERIALIZE) << "Failed to get state timestamp using any method: "
                << timestampResult.getErr();
            continue;
        }

        string currentStateTimestamp = timestampResult.unpack();

        if (checkAndUpdateStateTimestamp(currentStateTimestamp))
        {
            // Update state directly from the known remote file path
            updateStateFromRemoteFile();
            dbgInfo(D_WAAP_SERIALIZE) << "Owner: " << m_owner
                << ". updated state using " << (useFallbackMethod ? "file listing (fallback)" : "timestamp file")
                << ": " << m_lastProcessedModified;
            return;
        }
        else
        {
            dbgWarning(D_WAAP_SERIALIZE) << "State timestamp unchanged ("
                << (useFallbackMethod ? "file listing (fallback)" : "timestamp file") << "): "
                << currentStateTimestamp;
        }
    }

    // All polling attempts failed - fall back to local sync
    dbgWarning(D_WAAP_SERIALIZE) << "Polling for update state timeout, falling back to local sync. for assetId='"
        << m_assetId << "', owner='" << m_owner;
    localSyncAndProcess();
}

Maybe<void> SerializeToLocalAndRemoteSyncBase::updateStateFromRemoteFile()
{
    auto maybeRemoteFilePath = getRemoteStateFilePath();
    if (!maybeRemoteFilePath.ok())
    {
        string error = "Owner: " + m_owner + ", no remote state file path defined: " + maybeRemoteFilePath.getErr();
        dbgWarning(D_WAAP_SERIALIZE) << error;
        return genError(error);
    }

    string remoteFilePath = maybeRemoteFilePath.unpack();
    vector<string> files = {remoteFilePath};
    updateState(files);
    dbgDebug(D_WAAP_SERIALIZE) << "updated state from remote file: " << remoteFilePath;
    return Maybe<void>();
}

bool SerializeToLocalAndRemoteSyncBase::shouldNotSync() const
{
    OrchestrationMode mode = Singleton::exists<I_AgentDetails>() ?
        Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getOrchestrationMode() : OrchestrationMode::ONLINE;
    return mode == OrchestrationMode::OFFLINE  || !m_remoteSyncEnabled || isBase();
}

bool SerializeToLocalAndRemoteSyncBase::shouldSendSyncNotification() const
{
    return getSettingWithDefault<bool>(true, "features", "learningLeader") &&
        ((m_type == "CentralizedData") ==
        (getProfileAgentSettingWithDefault<bool>(false, "agent.learning.centralLogging")));
}

void SerializeToLocalAndRemoteSyncBase::syncWorker()
{
    dbgInfo(D_WAAP_SERIALIZE) << "Running the sync worker for assetId='" << m_assetId << "', owner='" <<
        m_owner << "'" << " last modified state: " << m_lastProcessedModified;
    incrementIntervalsCount();
    OrchestrationMode mode = Singleton::exists<I_AgentDetails>() ?
        Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getOrchestrationMode() : OrchestrationMode::ONLINE;

    if (shouldNotSync() || !postData()) {
        dbgDebug(D_WAAP_SERIALIZE)
            << "Did not synchronize the data. for asset: "
            << m_assetId
            << " Remote URL: "
            << m_remotePath
            << " is enabled: "
            << to_string(m_remoteSyncEnabled)
            << ", mode: " << int(mode);
        processData();
        saveData();
        return;
    }

    dbgTrace(D_WAAP_SERIALIZE) << "Waiting for all agents to post their data";
    waitSync();
    // check if learning service is operational
    if (m_lastProcessedModified == "")
    {
        dbgTrace(D_WAAP_SERIALIZE) << "check if remote service is operational";
        Maybe<string> maybeTimestamp = getStateTimestamp();
        if (maybeTimestamp.ok() && !maybeTimestamp.unpack().empty())
        {
            m_lastProcessedModified = maybeTimestamp.unpack();
            dbgInfo(D_WAAP_SERIALIZE) << "First sync by remote service: " << m_lastProcessedModified;
        }
        else
        {
            dbgWarning(D_WAAP_SERIALIZE) << "Failed to get state timestamp from remote service: "
                << maybeTimestamp.getErr();
            maybeTimestamp = getStateTimestampByListing();
            if (maybeTimestamp.ok() && !maybeTimestamp.unpack().empty())
            {
                m_lastProcessedModified = maybeTimestamp.unpack();
                dbgInfo(D_WAAP_SERIALIZE) << "First sync by remote service using listing: " << m_lastProcessedModified;
            }
            else
            {
                dbgWarning(D_WAAP_SERIALIZE)
                    << "Failed to get state timestamp from remote service by listing: "
                    << maybeTimestamp.getErr()
                    << " skipping syncWorker for assetId='"
                    << m_assetId << "', owner='" << m_owner << "'";
            }
        }
    }

    // check if learning service is enabled
    bool isRemoteServiceEnabled = getProfileAgentSettingWithDefault<bool>(
        true,
        "appsecLearningSettings.remoteServiceEnabled");

    dbgDebug(D_WAAP_SERIALIZE) << "using remote service: " << isRemoteServiceEnabled;
    if ((m_lastProcessedModified == "" || !isRemoteServiceEnabled) && !localSyncAndProcess())
    {
        dbgWarning(D_WAAP_SERIALIZE) << "local sync and process failed";
        return;
    }

    // TODO: add should send sync notification function (e.g. do not sync if not leader)

    if (mode == OrchestrationMode::HYBRID) {
        dbgDebug(D_WAAP_SERIALIZE) << "detected running in standalone mode";
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<WaapComponent>();
        I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<WaapComponent>();

        SyncLearningObject syncObj(m_assetId, m_type, getWindowId());

        MessageMetadata req_md(getLearningHost(), 80);
        req_md.insertHeader("X-Tenant-Id", agentDetails->getTenantId());
        req_md.setConnectioFlag(MessageConnectionConfig::UNSECURE_CONN);
        req_md.setConnectioFlag(MessageConnectionConfig::ONE_TIME_CONN);
        bool ok = messaging->sendSyncMessageWithoutResponse(
            HTTPMethod::POST,
            "/api/sync",
            syncObj,
            MessageCategory::GENERIC,
            req_md
        );
        dbgDebug(D_WAAP_SERIALIZE) << "sent learning sync notification ok: " << ok;
        if (!ok) {
            dbgWarning(D_WAAP_SERIALIZE) << "failed to send learning notification";
        }
    } else if (shouldSendSyncNotification())
    {
        SyncLearningNotificationObject syncNotification(m_assetId, m_type, getWindowId());

        dbgDebug(D_WAAP_SERIALIZE) << "sending sync notification: " << syncNotification;

        ReportMessaging(
            "sync notification for '" + m_assetId + "'",
            ReportIS::AudienceTeam::WAAP,
            syncNotification,
            MessageCategory::GENERIC,
            ReportIS::Tags::WAF,
            ReportIS::Notification::SYNC_LEARNING
        );
    }

    if (m_lastProcessedModified != "" && isRemoteServiceEnabled)
    {
        // wait for remote service to process the data
        waitSync();
        updateStateFromRemoteService();
    }
}

void SerializeToLocalAndRemoteSyncBase::restore()
{
    SerializeToFileBase::restore();
    if (!isBase())
    {
        dbgTrace(D_WAAP_SERIALIZE) << "merge state from remote service";
        mergeProcessedFromRemote();
    }
}

RemoteFilesList SerializeToLocalAndRemoteSyncBase::getRemoteProcessedFilesList()
{
    RemoteFilesList remoteFiles;
    bool isRemoteServiceEnabled = getProfileAgentSettingWithDefault<bool>(
        true,
        "appsecLearningSettings.remoteServiceEnabled");

    if (!isRemoteServiceEnabled)
    {
        dbgDebug(D_WAAP_SERIALIZE) << "remote service is disabled";
        return remoteFiles;
    }

    bool isSuccessful = sendObject(
        remoteFiles,
        HTTPMethod::GET,
        getUri() + "/?list-type=2&prefix=" + m_remotePath + "/remote");

    if (!isSuccessful)
    {
        dbgWarning(D_WAAP_SERIALIZE) << "Failed to get the list of files";
    }
    return remoteFiles;
}


RemoteFilesList SerializeToLocalAndRemoteSyncBase::getProcessedFilesList()
{
    RemoteFilesList processedFilesList = getRemoteProcessedFilesList();

    if (!processedFilesList.getFilesList().empty())
    {
        const vector<FileMetaData> &filesMD = processedFilesList.getFilesMetadataList();
        if (filesMD.size() > 1) {
            dbgWarning(D_WAAP_SERIALIZE) << "got more than 1 expected processed file";
        }
        if (!filesMD.empty()) {
            m_lastProcessedModified = filesMD[0].modified;
        }
        dbgTrace(D_WAAP_SERIALIZE) << "found " << filesMD.size() << " remote service state files. "
            "last modified: " << m_lastProcessedModified;

        return processedFilesList;
    }


    bool isSuccessful = sendObject(
        processedFilesList,
        HTTPMethod::GET,
        getUri() + "/?list-type=2&prefix=" + m_remotePath + "/processed");

    if (!isSuccessful)
    {
        dbgDebug(D_WAAP_SERIALIZE) << "Failed to get the list of files";
    }
    else if (!processedFilesList.getFilesList().empty())
    {
        dbgTrace(D_WAAP_SERIALIZE) << "found state files";
        return processedFilesList;
    }
    // backward compatibility - try to get backup file with the buggy prefix tenantID/assetID/instanceID/
    string bcRemotePath = m_remotePath;
    size_t pos = bcRemotePath.find('/');
    pos = bcRemotePath.find('/', pos + 1);
    if (!Singleton::exists<I_InstanceAwareness>())
    {
        dbgDebug(D_WAAP_SERIALIZE) << "missing instance of instance awareness,"
            " can't check backward compatibility";
        return processedFilesList;
    }
    I_InstanceAwareness* instanceAwareness = Singleton::Consume<I_InstanceAwareness>::by<WaapComponent>();
    Maybe<string> id = instanceAwareness->getUniqueID();
    if (!id.ok())
    {
        dbgDebug(D_WAAP_SERIALIZE) << "failed to get instance id err: " << id.getErr() <<
            ". can't check backward compatibility";
        return processedFilesList;
    }
    string idStr = id.unpack();
    bcRemotePath.insert(pos + 1, idStr + "/");
    dbgDebug(D_WAAP_SERIALIZE) << "List of files is empty - trying to get the file from " <<
        bcRemotePath;

    isSuccessful = sendObject(
        processedFilesList,
        HTTPMethod::GET,
        getUri() + "/?list-type=2&prefix=" + bcRemotePath + "/processed");

    if (!isSuccessful)
    {
        dbgWarning(D_WAAP_SERIALIZE) << "Failed to get the list of files";
    }
    dbgDebug(D_WAAP_SERIALIZE) << "backwards computability: got "
        << processedFilesList.getFilesList().size() << " state files";
    return processedFilesList;
}

void SerializeToLocalAndRemoteSyncBase::mergeProcessedFromRemote()
{
    dbgDebug(D_WAAP_SERIALIZE) << "Merging processed data from remote. assetId='" << m_assetId <<
        "', owner='" << m_owner << "'";
    m_pMainLoop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        [&]()
        {
            // Instrumentation breadcrumbs to help diagnose startup crash inside this routine
            dbgTrace(D_WAAP_SERIALIZE) << "start routine for assetId='" << m_assetId
                << "', owner='" << m_owner << "'";
            try {
                auto success = updateStateFromRemoteFile();
                if (!success.ok()) {
                    dbgInfo(D_WAAP_SERIALIZE) << "direct state file unavailable: "
                        << success.getErr() << ". Falling back to listing.";
                    RemoteFilesList remoteFiles = getProcessedFilesList();
                    if (remoteFiles.getFilesList().empty()) {
                        dbgWarning(D_WAAP_SERIALIZE) << "no remote processed files";
                        return;
                    }
                    const auto &md_list = remoteFiles.getFilesMetadataList();
                    if (!md_list.empty()) {
                        m_lastProcessedModified = md_list[0].modified;
                    } else {
                        dbgWarning(D_WAAP_SERIALIZE) << "metadata list empty while files list not empty";
                    }
                    updateState(remoteFiles.getFilesList());
                    dbgInfo(D_WAAP_SERIALIZE) << "updated state from remote files. Last modified: "
                        << m_lastProcessedModified;
                } else {
                    dbgTrace(D_WAAP_SERIALIZE) << "updated state via direct remote file";
                }
            } catch (const JsonError &j) {
                dbgError(D_WAAP_SERIALIZE) << "JsonError caught: '" << j.getMsg()
                    << "' assetId='" << m_assetId << "' owner='" << m_owner << "'";
                throw std::runtime_error(std::string("mergeProcessedFromRemote JsonError: ") + j.getMsg());
            } catch (const std::exception &e) {
                dbgError(D_WAAP_SERIALIZE) << "std::exception caught: " << e.what()
                    << " assetId='" << m_assetId << "' owner='" << m_owner << "'";
                throw; // Let mainloop handle termination with detailed message
            }
        },
        "Merge processed data from remote for asset Id: " + m_assetId + ", owner:" + m_owner
    );
}

string
SerializeToLocalAndRemoteSyncBase::getLearningHost()
{
    if (m_learning_host.ok()) {
        return *m_learning_host;
    } else {
        char* learningHost = getenv(LEARNING_HOST_ENV_NAME);
        if (learningHost != NULL) {
            m_learning_host = string(learningHost);
            return learningHost;
        }
        dbgWarning(D_WAAP_SERIALIZE) << "learning host is not set. using default";
    }
    return defaultLearningHost;
}

string
SerializeToLocalAndRemoteSyncBase::getSharedStorageHost()
{
    if (m_shared_storage_host.ok()) {
        return *m_shared_storage_host;
    } else {
        char* sharedStorageHost = getenv(SHARED_STORAGE_HOST_ENV_NAME);
        if (sharedStorageHost != NULL) {
            m_shared_storage_host = string(sharedStorageHost);
            return sharedStorageHost;
        }
        dbgWarning(D_WAAP_SERIALIZE) << "shared storage host is not set. using default";
    }
    return defaultSharedStorageHost;
}

string SerializeToLocalAndRemoteSyncBase::getStateTimestampPath()
{
    return m_remotePath + "/internal/lastModified.data";
}

Maybe<string> SerializeToLocalAndRemoteSyncBase::getStateTimestamp()
{
    string timestampPath = getStateTimestampPath();
    if (timestampPath.empty()) {
        dbgWarning(D_WAAP_SERIALIZE) << "Cannot get state timestamp - invalid path";
        return genError("Invalid timestamp path");
    }

    StateTimestampRetriever timestampRetriever;
    bool isSuccessful = sendObject(
        timestampRetriever,
        HTTPMethod::GET,
        getUri() + "/" + timestampPath);

    if (!isSuccessful) {
        dbgDebug(D_WAAP_SERIALIZE) << "Failed to get state timestamp file from: " << timestampPath;
        return genError("Failed to retrieve timestamp file from: " + timestampPath);
    }

    dbgDebug(D_WAAP_SERIALIZE) << "Retrieved state timestamp: " << timestampRetriever.getStateTimestamp().unpack()
        << " from path: " << timestampPath;
    return timestampRetriever.getStateTimestamp().unpack();
}
