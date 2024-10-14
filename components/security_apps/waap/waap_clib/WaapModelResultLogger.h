// Copyright (C) 2024 Check Point Software Technologies Ltd. All rights reserved.

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

#include <memory>
#include <string>
#include <map>
#include <chrono>
#include <vector>
#include <ostream>
#include "cereal/archives/json.hpp"

#include "i_waap_model_result_logger.h"
#include "DeepAnalyzer.h"
#include "i_transaction.h"
#include "ScanResult.h"
#include "WaapAssetState.h"
#include "WaapScores.h"

class WaapModelResultLogger
        :
    Singleton::Provide<I_WaapModelResultLogger>
{
public:
    WaapModelResultLogger(size_t maxLogs = MAX_WAAP_MODEL_LOGS);
    virtual ~WaapModelResultLogger();
    virtual void logModelResult(
        Waap::Scores::ModelLoggingSettings &settings,
        IWaf2Transaction* transaction,
        Waf2ScanResult &res,
        std::string modelName,
        std::string otherModelName,
        double score,
        double otherScore
    );
    class Impl;

protected:
    std::unique_ptr<Impl> pimpl;
    static const size_t MAX_WAAP_MODEL_LOGS = 20000;
};

class WaapModelResult
{
public:
    WaapModelResult(
        IWaf2Transaction &transaction,
        Waf2ScanResult &res,
        const std::string &modelName,
        const std::string &otherModelName,
        double score,
        double otherScore,
        uint64_t time
    ) : uri(transaction.getUri()), location(res.location), param(res.param_name),
        modelName(modelName), otherModelName(otherModelName),
        score(score), otherScore(otherScore), keywords(res.keywordsAfterFilter),
        sample(res.unescaped_line.substr(0, 100)), id(transaction.getIndex()), time(time)
    {
    }

    template<class Archive>
    void serialize(Archive &ar) const
    {
        ar(cereal::make_nvp("uri", uri));
        ar(cereal::make_nvp("location", location));
        ar(cereal::make_nvp("param", param));
        ar(cereal::make_nvp("modelName", modelName));
        ar(cereal::make_nvp("otherModelName", otherModelName));
        ar(cereal::make_nvp("score", score));
        ar(cereal::make_nvp("otherScore", otherScore));
        ar(cereal::make_nvp("keywords", keywords));
        ar(cereal::make_nvp("sample", sample));
        ar(cereal::make_nvp("id", id));
        ar(cereal::make_nvp("time", time));
    }

    std::string toString() const
    {
        std::stringstream message_stream;
        {
            cereal::JSONOutputArchive ar(message_stream);
            serialize(ar);
        }
        return message_stream.str();
    }

    std::string uri;
    std::string location;
    std::string param;
    std::string modelName;
    std::string otherModelName;
    double score;
    double otherScore;
    std::vector<std::string> keywords;
    std::string sample;
    uint64_t id;
    uint64_t time;
};
