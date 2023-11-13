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

USE_DEBUG_FLAG(D_WAAP_CONFIDENCE_CALCULATOR);

namespace ch = std::chrono;
using namespace std;
typedef ch::duration<size_t, std::ratio<86400>> days;

// Define interval between successful sync times
static const ch::minutes assetSyncTimeSliceLength(10);
static const int remoteSyncMaxPollingAttempts = 10;
static const string defaultLearningHost = "appsec-learning-svc";
static const string defaultSharedStorageHost = "appsec-shared-storage-svc";

#define SHARED_STORAGE_HOST_ENV_NAME "SHARED_STORAGE_HOST"
#define LEARNING_HOST_ENV_NAME "LEARNING_HOST"

static bool
isGZipped(const string &stream)
{
    if (stream.size() < 2) return false;
    auto unsinged_stream = reinterpret_cast<const u_char *>(stream.data());
    return unsinged_stream[0] == 0x1f && unsinged_stream[1] == 0x8b;
}

bool RestGetFile::loadJson(const string& json)
{
    string json_str;

    json_str = json;
    if (!isGZipped(json_str))
    {
        return ClientRest::loadJson(json_str);
    }
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
    return ClientRest::loadJson(json_str);
}

Maybe<string> RestGetFile::genJson() const
{
    Maybe<string> json = ClientRest::genJson();
    if (json.ok())
    {
        string data = json.unpack();
        auto compression_stream = initCompressionStream();
        CompressionResult res = compressData(
            compression_stream,
            CompressionType::GZIP,
            data.size(),
            reinterpret_cast<const unsigned char *>(data.c_str()),
            true);
        finiCompressionStream(compression_stream);
        if (!res.ok) {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to gzip data";
            return genError("Failed to compress data");
        }
        data = string((const char *)res.output, res.num_output_bytes);
        json = data;

        if (res.output) free(res.output);
        res.output = nullptr;
        res.num_output_bytes = 0;
    }
    return json;
}
SerializeToFilePeriodically::SerializeToFilePeriodically(ch::seconds pollingIntervals, string filePath) :
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

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "backup worker: current time: " << currentTime.count();

    if (currentTime - m_lastSerialization >= m_interval)
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "backup worker: backing up data";
        m_lastSerialization = currentTime;
        // save data
        saveData();

        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "backup worker: data is backed up";
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

SerializeToFileBase::SerializeToFileBase(string fileName) : m_filePath(fileName)
{
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "SerializeToFileBase::SerializeToFileBase() fname='" << m_filePath
        << "'";
}

SerializeToFileBase::~SerializeToFileBase()
{

}

void SerializeToFileBase::saveData()
{
    fstream filestream;

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "saving to file: " << m_filePath;
    filestream.open(m_filePath, fstream::out);

    stringstream ss;

    if (filestream.is_open() == false) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "failed to open file: " << m_filePath << " Error: "
            << strerror(errno);
        return;
    }

    serialize(ss);

    string data = ss.str();

    auto compression_stream = initCompressionStream();
    CompressionResult res = compressData(
        compression_stream,
        CompressionType::GZIP,
        data.size(),
        reinterpret_cast<const unsigned char *>(data.c_str()),
        true
    );
    finiCompressionStream(compression_stream);
    if (!res.ok) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to gzip data";
    } else {
        ss.str(string((const char *)res.output, res.num_output_bytes));
    }


    filestream << ss.str();
    filestream.close();
}

string decompress(string fileContent) {
    if (!isGZipped(fileContent)) {
        dbgTrace(D_WAAP) << "file note zipped";
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

void SerializeToFileBase::loadFromFile(string filePath)
{
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "loadFromFile() file: " << filePath;
    fstream filestream;

    filestream.open(filePath, fstream::in);

    if (filestream.is_open() == false) {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "failed to open file: " << filePath << " Error: " <<
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
            filePath.erase(idPosition, idStr.length() - 1);
            dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "retry to load file from : " << filePath;
            loadFromFile(filePath);
        }
        return;
    }

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "loading from file: " << filePath;

    int length;
    filestream.seekg(0, ios::end);    // go to the end
    length = filestream.tellg();           // report location (this is the length)
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "file length: " << length;
    assert(length >= 0); // length -1 really happens if filePath is a directory (!)
    char* buffer = new char[length];       // allocate memory for a buffer of appropriate dimension
    filestream.seekg(0, ios::beg);    // go back to the beginning
    if (!filestream.read(buffer, length))  // read the whole file into the buffer
    {
        filestream.close();
        delete[] buffer;
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to read file, file: " << filePath;
        return;
    }
    filestream.close();

    string dataObfuscated(buffer, length);

    delete[] buffer;

    stringstream ss;
    ss << decompress(dataObfuscated);

    try
    {
        deserialize(ss);
    }
    catch (runtime_error & e) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "failed to deserialize file: " << m_filePath << ", error: " <<
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
bool RemoteFilesList::loadJson(const string& xml)
{
    xmlDocPtr doc; // the resulting document tree
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "XML input: " << xml;
    doc = xmlParseMemory(xml.c_str(), xml.length());

    if (doc == NULL) {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to parse " << xml;
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
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Found the Contents element";
            xmlNodePtr contents_node = node->children;
            string file;
            string lastModified;
            while (contents_node != NULL)
            {
                if (xmlStrEqual(key_name, contents_node->name) == 1)
                {
                    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Found the Key element";
                    xmlChar* xml_file = xmlNodeGetContent(contents_node);
                    file = string(reinterpret_cast<const char*>(xml_file));
                    xmlFree(xml_file);
                }
                if (xmlStrEqual(last_modified_name, contents_node->name) == 1)
                {
                    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Found the LastModified element";
                    xmlChar* xml_file = xmlNodeGetContent(contents_node);
                    lastModified = string(reinterpret_cast<const char*>(xml_file));
                    xmlFree(xml_file);
                }
                if (!file.empty() && !lastModified.empty())
                {
                    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Adding the file: " << file <<
                        " last modified: " << lastModified;
                    break;
                }
                contents_node = contents_node->next;
            }
            files.get().push_back(FileMetaData{ file, lastModified });
            filesPathsList.push_back(file);
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

const vector<string>& RemoteFilesList::getFilesList() const
{
    return filesPathsList;
}

const vector<FileMetaData>& RemoteFilesList::getFilesMetadataList() const
{
    return files.get();
}


SerializeToLocalAndRemoteSyncBase::SerializeToLocalAndRemoteSyncBase(
    ch::minutes interval,
    ch::seconds waitForSync,
    const string& filePath,
    const string& remotePath,
    const string& assetId,
    const string& owner)
    :
    SerializeToFileBase(filePath),
    m_remotePath(remotePath),
    m_interval(0),
    m_owner(owner),
    m_pMainLoop(nullptr),
    m_waitForSync(waitForSync),
    m_workerRoutineId(0),
    m_daysCount(0),
    m_windowsCount(0),
    m_intervalsCounter(0),
    m_remoteSyncEnabled(true),
    m_assetId(assetId),
    m_shared_storage_host(genError("not set")),
    m_learning_host(genError("not set"))
{
    dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "Create SerializeToLocalAndRemoteSyncBase. assetId='" << assetId <<
        "', owner='" << m_owner << "'";

    if (Singleton::exists<I_AgentDetails>() &&
        Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getOrchestrationMode() ==
            OrchestrationMode::HYBRID) {
        char* sharedStorageHost = getenv(SHARED_STORAGE_HOST_ENV_NAME);
        if (sharedStorageHost != NULL) {
            m_shared_storage_host = string(sharedStorageHost);
        } else {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) <<
                "shared storage host name(" <<
                SHARED_STORAGE_HOST_ENV_NAME <<
                ") is not set";
        }
        char* learningHost = getenv(LEARNING_HOST_ENV_NAME);
        if (learningHost != NULL) {
            m_learning_host = string(learningHost);
        } else {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) <<
                "learning host name(" <<
                SHARED_STORAGE_HOST_ENV_NAME <<
                ") is not set";
        }
    }
    if (remotePath != "") {
        // remote path is /<tenantId>/<assetId>/<type>
        auto parts = split(remotePath, '/');
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
    m_pMainLoop = Singleton::Consume<I_MainLoop>::by<WaapComponent>();
    setInterval(interval);
}

bool SerializeToLocalAndRemoteSyncBase::isBase()
{
    return m_remotePath == "";
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
        if (uniqueId.ok())
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
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "setInterval: from " << m_interval.count() << " to " <<
        newInterval.count() << " seconds. assetId='" << m_assetId << "', owner='" << m_owner << "'";

    if (newInterval == m_interval)
    {
        return;
    }

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
                dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "adjusting remaining time: " << remainingTime.count();
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
                dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "syncWorker execution time (owner='" << m_owner <<
                    "', assetId='" << m_assetId << "') is " <<
                    ch::duration_cast<ch::seconds>(timeAfterSyncWorker - timeBeforeSyncWorker).count() <<
                    " seconds, too long to cause negative remainingTime. Waiting 0 seconds...";
            }

            dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "current time: " << timeBeforeSyncWorker.count() << " \u00b5s" <<
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
    RemoteFilesList rawDataFiles;

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Getting files of all agents";

    bool isSuccessful = sendObjectWithRetry(rawDataFiles,
        I_Messaging::Method::GET,
        getUri() + "/?list-type=2&prefix=" + m_remotePath + "/" + getWindowId() + "/");

    if (!isSuccessful)
    {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get the list of files";
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

void SerializeToLocalAndRemoteSyncBase::updateStateFromRemoteService()
{
    for (int i = 0; i < remoteSyncMaxPollingAttempts; i++)
    {
        m_pMainLoop->yield(ch::seconds(60));
        RemoteFilesList remoteFiles = getRemoteProcessedFilesList();
        if (remoteFiles.getFilesMetadataList().empty())
        {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "no files generated by the remote service were found";
            continue;
        }
        string lastModified = remoteFiles.getFilesMetadataList().begin()->modified;
        if (lastModified != m_lastProcessedModified)
        {
            m_lastProcessedModified = lastModified;
            updateState(remoteFiles.getFilesList());
            dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "Owner: " << m_owner <<
                ". updated state generated by remote at " << m_lastProcessedModified;
            return;
        }
    }
    dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "polling for update state timeout. for assetId='"
        << m_assetId << "', owner='" << m_owner;
    localSyncAndProcess();
}

void SerializeToLocalAndRemoteSyncBase::syncWorker()
{
    dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "Running the sync worker for assetId='" << m_assetId << "', owner='" <<
        m_owner << "'" << " last modified state: " << m_lastProcessedModified;
    m_intervalsCounter++;
    OrchestrationMode mode = Singleton::exists<I_AgentDetails>() ?
        Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getOrchestrationMode() : OrchestrationMode::ONLINE;

    if (!m_remoteSyncEnabled || isBase() || !postData() ||
        mode == OrchestrationMode::OFFLINE)
    {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR)
            << "Did not synchronize the data. Remote URL: "
            << m_remotePath
            << " is enabled: "
            << to_string(m_remoteSyncEnabled);
        processData();
        saveData();
        return;
    }

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Waiting for all agents to post their data";
    m_pMainLoop->yield(m_waitForSync);
    // check if learning service is operational
    if (m_lastProcessedModified == "")
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "check if remote service is operational";
        RemoteFilesList remoteFiles = getRemoteProcessedFilesList();
        if (!remoteFiles.getFilesMetadataList().empty())
        {
            m_lastProcessedModified = remoteFiles.getFilesMetadataList()[0].modified;
            dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "First sync by remote service: " << m_lastProcessedModified;
        }
    }

    // check if learning service is enabled
    bool isRemoteServiceEnabled = getProfileAgentSettingWithDefault<bool>(
        true,
        "appsecLearningSettings.remoteServiceEnabled");

    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "using remote service: " << isRemoteServiceEnabled;
    if ((m_lastProcessedModified == "" || !isRemoteServiceEnabled) && !localSyncAndProcess())
    {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "local sync and process failed";
        return;
    }

    if (mode == OrchestrationMode::HYBRID) {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "detected running in standalone mode";
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<WaapComponent>();
        I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<WaapComponent>();

        SyncLearningObject syncObj(m_assetId, m_type, getWindowId());

        Flags<MessageConnConfig> conn_flags;
        conn_flags.setFlag(MessageConnConfig::EXTERNAL);
        string tenant_header = "X-Tenant-Id: " + agentDetails->getTenantId();
        bool ok = messaging->sendNoReplyObject(syncObj,
                I_Messaging::Method::POST,
                getLearningHost(),
                80,
                conn_flags,
                "/api/sync",
                tenant_header);
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "sent learning sync notification ok: " << ok;
        if (!ok) {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "failed to send learning notification";
        }
    } else {
        SyncLearningNotificationObject syncNotification(m_assetId, m_type, getWindowId());

        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "sending sync notification: " << syncNotification;

        ReportMessaging(
            "sync notification for '" + m_assetId + "'",
            ReportIS::AudienceTeam::WAAP,
            syncNotification,
            false,
            MessageTypeTag::WAAP_LEARNING,
            ReportIS::Tags::WAF,
            ReportIS::Notification::SYNC_LEARNING
        );
    }

    if (m_lastProcessedModified != "" && isRemoteServiceEnabled)
    {
        updateStateFromRemoteService();
    }
}

void SerializeToLocalAndRemoteSyncBase::restore()
{
    SerializeToFileBase::restore();
    if (!isBase())
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "merge state from remote service";
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
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "remote service is disabled";
        return remoteFiles;
    }

    bool isSuccessful = sendObject(
        remoteFiles,
        I_Messaging::Method::GET,
        getUri() + "/?list-type=2&prefix=" + m_remotePath + "/remote");

    if (!isSuccessful)
    {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get the list of files";
    }
    return remoteFiles;
}


RemoteFilesList SerializeToLocalAndRemoteSyncBase::getProcessedFilesList()
{
    RemoteFilesList processedFilesList = getRemoteProcessedFilesList();

    if (!processedFilesList.getFilesList().empty())
    {
        const vector<FileMetaData>& filesMD = processedFilesList.getFilesMetadataList();
        if (filesMD.size() > 1) {
            dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "got more than 1 expected processed file";
        }
        if (!filesMD.empty()) {
            m_lastProcessedModified = filesMD[0].modified;
        }
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "found " << filesMD.size() << " remote service state files. "
            "last modified: " << m_lastProcessedModified;

        return processedFilesList;
    }


    bool isSuccessful = sendObject(
        processedFilesList,
        I_Messaging::Method::GET,
        getUri() + "/?list-type=2&prefix=" + m_remotePath + "/processed");

    if (!isSuccessful)
    {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get the list of files";
    }
    else if (!processedFilesList.getFilesList().empty())
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "found state files";
        return processedFilesList;
    }
    // backward compatibility - try to get backup file with the buggy prefix tenantID/assetID/instanceID/
    string bcRemotePath = m_remotePath;
    size_t pos = bcRemotePath.find('/');
    pos = bcRemotePath.find('/', pos + 1);
    if (!Singleton::exists<I_InstanceAwareness>())
    {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "missing instance of instance awareness,"
            " can't check backward compatibility";
        return processedFilesList;
    }
    I_InstanceAwareness* instanceAwareness = Singleton::Consume<I_InstanceAwareness>::by<WaapComponent>();
    Maybe<string> id = instanceAwareness->getUniqueID();
    if (!id.ok())
    {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "failed to get instance id err: " << id.getErr() <<
            ". can't check backward compatibility";
        return processedFilesList;
    }
    string idStr = id.unpack();
    bcRemotePath.insert(pos + 1, idStr + "/");
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "List of files is empty - trying to get the file from " <<
        bcRemotePath;

    isSuccessful = sendObject(
        processedFilesList,
        I_Messaging::Method::GET,
        getUri() + "/?list-type=2&prefix=" + bcRemotePath + "/processed");

    if (!isSuccessful)
    {
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get the list of files";
    }
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "backwards computability: got "
        << processedFilesList.getFilesList().size() << " state files";
    return processedFilesList;
}

void SerializeToLocalAndRemoteSyncBase::mergeProcessedFromRemote()
{
    dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "Merging processed data from remote. assetId='" << m_assetId <<
        "', owner='" << m_owner << "'";
    m_pMainLoop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        [&]()
        {
            RemoteFilesList processedFiles = getProcessedFilesList();
            pullProcessedData(processedFiles.getFilesList());
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
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "learning host is not set. using default";
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
        dbgWarning(D_WAAP_CONFIDENCE_CALCULATOR) << "shared storage host is not set. using default";
    }
    return defaultSharedStorageHost;
}
