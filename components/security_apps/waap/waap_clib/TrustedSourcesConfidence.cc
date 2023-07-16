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

#include "TrustedSourcesConfidence.h"
#include "i_messaging.h"
#include "waap.h"
#include "Waf2Util.h"

USE_DEBUG_FLAG(D_WAAP_CONFIDENCE_CALCULATOR);
#define SYNC_WAIT_TIME std::chrono::seconds(300) // 5 minutes in seconds

TrustedSourcesConfidenceCalculator::TrustedSourcesConfidenceCalculator(
    std::string path,
    const std::string& remotePath,
    const std::string& assetId)
    :
    SerializeToLocalAndRemoteSyncBase(std::chrono::minutes(120),
        SYNC_WAIT_TIME,
        path,
        (remotePath == "") ? remotePath : remotePath + "/Trust",
        assetId,
        "TrustedSourcesConfidenceCalculator")
{
    restore();
}

bool TrustedSourcesConfidenceCalculator::is_confident(Key key, Val value, size_t minSources) const
{
    auto sourceCtrItr = m_logger.find(key);
    if (sourceCtrItr != m_logger.end())
    {
        auto sourceSetItr = sourceCtrItr->second.find(value);
        if (sourceSetItr != sourceCtrItr->second.end())
        {
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "The number of trusted sources for " << key
                << " : " << value << " is " << sourceSetItr->second.size();
            return sourceSetItr->second.size() >= minSources;
        }
        else
        {
            dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to find the value(" << value << ")";
        }
    }
    else
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to find the key(" << key << ")";
    }
    return false;
}


class GetTrustedFile : public RestGetFile
{
public:
    GetTrustedFile()
    {
    }

    Maybe<TrustedSourcesConfidenceCalculator::KeyValSourceLogger>
        getTrustedLogs() const
    {
        if (!logger.get().empty()) return logger.get();
        return genError("failed to get file");
    }

private:
    S2C_PARAM(TrustedSourcesConfidenceCalculator::KeyValSourceLogger, logger)
};

class TrsutedSourcesLogger : public RestGetFile
{
public:
    TrsutedSourcesLogger(const TrustedSourcesConfidenceCalculator::KeyValSourceLogger& _logger)
        : logger(_logger)
    {

    }
private:
    C2S_PARAM(TrustedSourcesConfidenceCalculator::KeyValSourceLogger, logger);
};

bool TrustedSourcesConfidenceCalculator::postData()
{
    std::string url = getPostDataUrl();

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Sending the data to: " << url;

    TrsutedSourcesLogger logger(m_logger);
    bool ok = sendNoReplyObjectWithRetry(logger,
        I_Messaging::Method::PUT,
        url);
    if (!ok) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to post collected data to: " << url;
    }
    return ok;
}

void TrustedSourcesConfidenceCalculator::pullData(const std::vector<std::string>& files)
{
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Fetching the window data for trusted sources";
    std::string url = getPostDataUrl();
    std::string sentFile = url.erase(0, url.find_first_of('/') + 1);
    for (auto file : files)
    {
        if (file == sentFile)
        {
            continue;
        }
        GetTrustedFile getTrustFile;
        bool res = sendObjectWithRetry(getTrustFile,
            I_Messaging::Method::GET,
            getUri() + "/" + file);
        if (!res)
        {
            dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to get file: " << file;
            continue;
        }
        if (getTrustFile.getTrustedLogs().ok())
        {
            mergeFromRemote(getTrustFile.getTrustedLogs().unpack());
        }
    }
}

void TrustedSourcesConfidenceCalculator::processData()
{

}

void TrustedSourcesConfidenceCalculator::updateState(const std::vector<std::string>& files)
{
    m_logger.clear();
    pullProcessedData(files);
}

void TrustedSourcesConfidenceCalculator::pullProcessedData(const std::vector<std::string>& files) {
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Fetching the logger object for trusted sources";
    bool pull_ok = false;
    for (auto file: files) {
        GetTrustedFile getTrustFile;
        bool res = sendObjectWithRetry(getTrustFile,
            I_Messaging::Method::GET,
            getUri() + "/" + file);
        pull_ok |= res;
        if (res && getTrustFile.getTrustedLogs().ok()) {
            mergeFromRemote(getTrustFile.getTrustedLogs().unpack());
        }
    }
    if (!pull_ok && !files.empty()) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to pull state data";
    }
}

void TrustedSourcesConfidenceCalculator::postProcessedData()
{
    std::string url = getUri() + "/" + m_remotePath + "/processed/data.data";
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Sending the processed data to: " << url;

    TrsutedSourcesLogger logger(m_logger);
    sendNoReplyObjectWithRetry(logger,
        I_Messaging::Method::PUT,
        url);
}

TrustedSourcesConfidenceCalculator::ValuesSet TrustedSourcesConfidenceCalculator::getConfidenceValues(
    const Key& key,
    size_t minSources) const
{
    ValuesSet values;
    auto sourceCtrItr = m_logger.find(key);
    if (sourceCtrItr != m_logger.end())
    {
        for (auto sourceSetItr : sourceCtrItr->second)
        {
            if (sourceSetItr.second.size() >= minSources)
            {
                values.insert(sourceSetItr.first);
            }
        }
    }
    else
    {
        dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to find the key(" << key << ")";
    }
    return values;
}

void TrustedSourcesConfidenceCalculator::serialize(std::ostream& stream)
{
    cereal::JSONOutputArchive archive(stream);

    archive(cereal::make_nvp("version", 2), cereal::make_nvp("logger", m_logger));
}

void TrustedSourcesConfidenceCalculator::deserialize(std::istream& stream)
{
    cereal::JSONInputArchive archive(stream);
    size_t version = 0;

    try
    {
        archive(cereal::make_nvp("version", version));
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        version = 0;
        dbgDebug(D_WAAP) << "Can't load file version: " << e.what();
    }

    switch (version)
    {
    case 2:
    {
        archive(cereal::make_nvp("logger", m_logger));
        break;
    }
    case 1:
    {
        KeyValSourceLogger logger;
        archive(cereal::make_nvp("logger", logger));
        for (auto& log : logger)
        {
            m_logger[normalize_param(log.first)] = log.second;
        }
        break;
    }
    case 0:
    {
        archive(cereal::make_nvp("m_logger", m_logger));
        break;
    }
    default:
        dbgError(D_WAAP) << "unknown file format version: " << version;
        break;
    }
}

void TrustedSourcesConfidenceCalculator::mergeFromRemote(const KeyValSourceLogger& logs)
{
    for (auto& srcCounterItr : logs)
    {
        for (auto& sourcesItr : srcCounterItr.second)
        {
            for (auto& src : sourcesItr.second)
            {
                dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Registering the source: " << src
                    << " for the value: " << sourcesItr.first << " and the key: " << srcCounterItr.first;
                m_logger[normalize_param(srcCounterItr.first)][sourcesItr.first].insert(src);
            }
        }
    }
}

void TrustedSourcesConfidenceCalculator::log(Key key, Val value, Source source)
{
    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR)
        << "Logging the value: "
        << value
        << " for the key: "
        << key
        << " from the source: "
        << source;
    m_logger[key][value].insert(source);
}

void TrustedSourcesConfidenceCalculator::reset()
{
    m_logger.clear();
}
