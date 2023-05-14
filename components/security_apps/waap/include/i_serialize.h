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
#include <fstream>
#include "i_time_get.h"
#include "rest.h"
#include "i_messaging.h"
#include "i_mainloop.h"
#include "i_agent_details.h"

static const uint max_send_obj_retries = 3;
static const std::chrono::microseconds wait_next_attempt(5000000);

USE_DEBUG_FLAG(D_WAAP);

class RestGetFile : public ClientRest
{
public:
    // decrypts and load json
    bool loadJson(const std::string& json);
    // gen json and encrypt
    Maybe<std::string> genJson() const;
};

struct FileMetaData
{
    std::string filename;
    std::string modified;
};

class RemoteFilesList : public ClientRest
{
public:
    RemoteFilesList();

    // parses xml instead of json
    // extracts a file list in <Contents><Key>
    bool loadJson(const std::string& xml);

    const std::vector<FileMetaData>& getFilesMetadataList() const;
    const std::vector<std::string>& getFilesList() const;

private:
    RestParam<std::vector<FileMetaData>> files;
    std::vector<std::string> filesPathsList;
};


class I_Serializable {
public:
    virtual void serialize(std::ostream& stream) = 0;
    virtual void deserialize(std::istream& stream) = 0;
};

class I_RemoteSyncSerialize {
public:
    virtual bool postData() = 0;
    virtual void pullData(const std::vector<std::string>& files) = 0;
    virtual void processData() = 0;
    virtual void postProcessedData() = 0;
    virtual void pullProcessedData(const std::vector<std::string>& files) = 0;
    virtual void updateState(const std::vector<std::string>& files) = 0;
};

class I_Backup {
public:
    // open stream and serialize data
    virtual void saveData() = 0;
    // open stream and deserialize data
    virtual void restore() = 0;
};

class SerializeToFileBase :
    public I_Backup,
    public I_Serializable
{
public:
    SerializeToFileBase(std::string filePath);
    virtual ~SerializeToFileBase();

    virtual void saveData();
    virtual void restore();

protected:
    // saved file name for testing
    std::string m_filePath;
private:
    void loadFromFile(std::string filePath);
};

class SerializeToFilePeriodically : public SerializeToFileBase
{
public:
    SerializeToFilePeriodically(std::chrono::seconds pollingIntervals, std::string filePath);
    virtual ~SerializeToFilePeriodically();

    void setInterval(std::chrono::seconds newInterval);

protected:
    void backupWorker();

private:
    std::chrono::microseconds m_lastSerialization;
    std::chrono::seconds m_interval;
};

class WaapComponent;

class SerializeToLocalAndRemoteSyncBase : public I_RemoteSyncSerialize, public SerializeToFileBase
{
public:
    SerializeToLocalAndRemoteSyncBase(std::chrono::minutes interval,
        std::chrono::seconds waitForSync,
        const std::string& filePath,
        const std::string& remotePath,
        const std::string& assetId,
        const std::string& owner);
    virtual ~SerializeToLocalAndRemoteSyncBase();

    virtual void restore();

    virtual void syncWorker();

    void setInterval(std::chrono::seconds newInterval);
    std::chrono::seconds getIntervalDuration() const;
    void setRemoteSyncEnabled(bool enabled);
protected:
    void mergeProcessedFromRemote();
    std::string getPostDataUrl();
    std::string getUri();
    size_t getIntervalsCount();

    template<typename T>
    bool sendObject(T &obj, I_Messaging::Method method, std::string uri)
    {
        I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<WaapComponent>();
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<WaapComponent>();
        if (agentDetails->getOrchestrationMode() == OrchestrationMode::OFFLINE) {
            dbgDebug(D_WAAP) << "offline mode not sending object";
            return false;
        }
        if (agentDetails->getOrchestrationMode() == OrchestrationMode::HYBRID) {
            Flags <MessageConnConfig> conn_flags;
            conn_flags.setFlag(MessageConnConfig::EXTERNAL);
            std::string tenant_header = "X-Tenant-Id: " + agentDetails->getTenantId();

            return messaging->sendObject(
                obj,
                method,
                getSharedStorageHost(),
                80,
                conn_flags,
                uri,
                tenant_header,
                nullptr,
                MessageTypeTag::WAAP_LEARNING);
        }
        return messaging->sendObject(
            obj,
            method,
            uri,
            "",
            nullptr,
            true,
            MessageTypeTag::WAAP_LEARNING);
    }

    template<typename T>
    bool sendObjectWithRetry(T &obj, I_Messaging::Method method, std::string uri)
    {
        I_MainLoop *mainloop = Singleton::Consume<I_MainLoop>::by<WaapComponent>();
        for (uint i = 0; i < max_send_obj_retries; i++)
        {
            if (sendObject(obj, method, uri))
            {
                dbgTrace(D_WAAP) <<
                    "object sent successfully after " << i << " retry attempts";
                return true;
            }
            dbgInfo(D_WAAP) << "Failed to send object. Attempt: " << i;
            mainloop->yield(wait_next_attempt);
        }
        dbgWarning(D_WAAP) << "Failed to send object to " << uri << ", reached maximum attempts: " <<
            max_send_obj_retries;
        return false;
    }

    template<typename T>
    bool sendNoReplyObject(T &obj, I_Messaging::Method method, std::string uri)
    {
        I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<WaapComponent>();
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<WaapComponent>();
        if (agentDetails->getOrchestrationMode() == OrchestrationMode::OFFLINE) {
            dbgDebug(D_WAAP) << "offline mode not sending object";
            return false;
        }
        if (agentDetails->getOrchestrationMode() == OrchestrationMode::HYBRID) {
            Flags<MessageConnConfig> conn_flags;
            conn_flags.setFlag(MessageConnConfig::EXTERNAL);
            std::string tenant_header = "X-Tenant-Id: " + agentDetails->getTenantId();
            return messaging->sendNoReplyObject(
                obj,
                method,
                getSharedStorageHost(),
                80,
                conn_flags,
                uri,
                tenant_header,
                nullptr,
                MessageTypeTag::WAAP_LEARNING);
        }
        return messaging->sendNoReplyObject(
            obj,
            method,
            uri,
            "",
            nullptr,
            true,
            MessageTypeTag::WAAP_LEARNING);
    }

    template<typename T>
    bool sendNoReplyObjectWithRetry(T &obj, I_Messaging::Method method, std::string uri)
    {
        I_MainLoop *mainloop= Singleton::Consume<I_MainLoop>::by<WaapComponent>();
        for (uint i = 0; i < max_send_obj_retries; i++)
        {
            if (sendNoReplyObject(obj, method, uri))
            {
                dbgTrace(D_WAAP) <<
                    "object sent successfully after " << i << " retry attempts";
                return true;
            }
            dbgInfo(D_WAAP) << "Failed to send object. Attempt: " << i;
            mainloop->yield(wait_next_attempt);
        }
        dbgWarning(D_WAAP) << "Failed to send object to " << uri << ", reached maximum attempts: " <<
            max_send_obj_retries;
        return false;
    }

    const std::string m_remotePath; // Created from tenentId + / + assetId + / + class
    std::chrono::seconds m_interval;
    std::string m_owner;

private:
    bool localSyncAndProcess();
    void updateStateFromRemoteService();
    RemoteFilesList getProcessedFilesList();
    RemoteFilesList getRemoteProcessedFilesList();
    std::string getWindowId();
    bool isBase();
    std::string getLearningHost();
    std::string getSharedStorageHost();

    I_MainLoop* m_pMainLoop;
    std::chrono::microseconds m_waitForSync;
    uint m_workerRoutineId;
    size_t m_daysCount;
    size_t m_windowsCount;
    size_t m_intervalsCounter;
    bool m_remoteSyncEnabled;
    const std::string m_assetId;
    std::string m_type;
    std::string m_lastProcessedModified;
    Maybe<std::string> m_shared_storage_host;
    Maybe<std::string> m_learning_host;
};
