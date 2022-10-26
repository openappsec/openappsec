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
#include "i_serialize.h"
#include <cereal/archives/json.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/unordered_set.hpp>

USE_DEBUG_FLAG(D_WAAP);

// this class is responsible for logging trusted sources indicators matches (without validation)
class TrustedSourcesConfidenceCalculator : public SerializeToLocalAndRemoteSyncBase
{
public:
    typedef std::string Key;
    typedef std::string Val;
    typedef std::string Source;
    typedef std::set<Val> ValuesSet;
    typedef std::unordered_set<Source> SourcesSet;
    typedef std::unordered_map<Val, SourcesSet> SourcesCounter;
    typedef std::unordered_map<Key, SourcesCounter> KeyValSourceLogger;

    TrustedSourcesConfidenceCalculator(std::string path, const std::string& remotePath,
        const std::string& assetId);
    bool is_confident(Key key, Val value, size_t minSources) const;

    virtual bool postData();
    virtual void pullData(const std::vector<std::string>& files);
    virtual void processData();
    virtual void postProcessedData();
    virtual void pullProcessedData(const std::vector<std::string>& files);
    virtual void updateState(const std::vector<std::string>& files);

    ValuesSet getConfidenceValues(const Key& key, size_t minSources) const;

    virtual void serialize(std::ostream& stream);
    virtual void deserialize(std::istream& stream);

    void mergeFromRemote(const KeyValSourceLogger& logs);

    void log(Key key, Val value, Source source);
    void reset();

private:
    KeyValSourceLogger m_logger;
};
