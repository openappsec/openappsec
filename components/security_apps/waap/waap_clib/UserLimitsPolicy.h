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
#include "debug.h"
#include <cereal/types/string.hpp>
#include <string>
#include <sstream>
#include <iostream>

USE_DEBUG_FLAG(D_WAAP_ULIMITS);

namespace Waap {
namespace UserLimits {

typedef unsigned long long ull;
#define DEFAULT_URL_MAX_SIZE 32*1024
#define DEFAULT_HEADER_MAX_SIZE 100*1024
#define DEFAULT_BODY_MAX_SIZE_KB 1000000
#define DEFAULT_BODY_MAX_SIZE 1000000*1024
#define DEFAULT_OBJECT_MAX_DEPTH 40

// @file Feature behaviour description:
// Phase 1:
// 1. No enforcement. No logs to mgmt.
// 2. Only logs to automation and dev Kibana.
// 3. Logs should represent the state as if the limits are enforced as described in phase 2.
// Phase 2:
// 1. DISABLE mode: no enforcement and no logs.
// 2. LEARNING mode: requests that violated a limit will be accepted, and won't be scanned any further.
//    Illegal methods won't be automatically accepted, and will be further scanned.
// 3. PREVENT mode: requests that violated a limit will be dropped, and won't be scanned any further.
class Policy {
    struct Config {
        Config() :
        urlMaxSize(DEFAULT_URL_MAX_SIZE),
        httpHeaderMaxSize(DEFAULT_HEADER_MAX_SIZE),
        httpBodyMaxSizeKb(DEFAULT_BODY_MAX_SIZE_KB),
        httpBodyMaxSize(DEFAULT_BODY_MAX_SIZE),
        maxObjectDepth(DEFAULT_OBJECT_MAX_DEPTH),
        httpIllegalMethodsAllowed(false) {}
        ~Config() {}

        template <typename _A>
        void serialize(_A& ar) {
            ar(cereal::make_nvp("urlMaxSize", urlMaxSize));
            ar(cereal::make_nvp("httpHeaderMaxSize", httpHeaderMaxSize));
            httpBodyMaxSizeKb = 0;
            ar(cereal::make_nvp("httpRequestBodyMaxSize", httpBodyMaxSizeKb));
            // Kilobytes to bytes conversion
            httpBodyMaxSize = httpBodyMaxSizeKb * 1024;
            ar(cereal::make_nvp("jsonMaxObjectDepth", maxObjectDepth));
            int intToBool = 0;
            ar(cereal::make_nvp("httpIllegalMethodsAllowed", intToBool));
            httpIllegalMethodsAllowed = (intToBool == 1);
        }

        bool operator==(const Policy::Config& other) const;

        size_t urlMaxSize;  // URL max size in bytes
        size_t httpHeaderMaxSize;  // Header Size in Bytes
        size_t httpBodyMaxSizeKb;  // Body Size in Kilobytes
        ull httpBodyMaxSize;  // Body Size in Bytes
        size_t maxObjectDepth;  // Can range from 0 to 1024
        // List of legal methods can be viewed in isLegalHttpMethod function
        bool httpIllegalMethodsAllowed;
    };
public:
    template <typename _A>
    explicit Policy(_A& ar)
    {
        ar(cereal::make_nvp("practiceAdvancedConfig", m_config));
    }
    Policy() : m_config() {}
    ~Policy() {}

    bool operator==(const Policy& other) const;
    size_t getUrlMaxSize() const { return m_config.urlMaxSize; }
    size_t getMaxObjectDepth() const { return m_config.maxObjectDepth; }
    size_t getHttpHeaderMaxSize() const { return m_config.httpHeaderMaxSize; }
    size_t getHttpBodyMaxSizeKb() const { return m_config.httpBodyMaxSizeKb; }
    ull getHttpBodyMaxSize() const { return m_config.httpBodyMaxSize; }
    bool isHttpIllegalMethodAllowed() const { return m_config.httpIllegalMethodsAllowed; }
    const Config& getConfig() const { return m_config; }

private:
    Config m_config;

    friend std::ostream& operator<<(std::ostream& os, const Policy& policy);
};

struct ViolatedStrData
{
    std::string type;
    std::string policy;
    std::string assetId;
};

class State {
public:
    enum class StateType
    {
        NO_STATE,
        URL,
        METHOD,
        HEADER,
        BODY,
        DEPTH
    };

    enum class ViolationType
    {
        NO_LIMIT,
        ILLEGAL_METHOD,
        URL_LIMIT,
        URL_OVERFLOW,
        HEADER_LIMIT,
        HEADER_OVERFLOW,
        BODY_LIMIT,
        BODY_OVERFLOW,
        OBJECT_DEPTH_LIMIT
    };
public:
    explicit State(const Policy& policy) :
        m_policy(policy),
        m_urlSize(0),
        m_httpHeaderSize(0),
        m_httpBodySize(0),
        m_objectDepth(0),
        m_currState(StateType::NO_STATE),
        m_type(ViolationType::NO_LIMIT),
        m_strData()
        {
            m_strData.type = "no violation";
        }
    ~State() {}

    void setAssetId(const std::string& assetId) { m_strData.assetId = assetId; }
    // @return true if limit is reached or overflows
    bool addUrlBytes(size_t size);
    bool addHeaderBytes(const std::string& name, const std::string& value);
    bool addBodyBytes(size_t chunkSize);
    // @return true if limit is reached
    bool setObjectDepth(size_t depth);
    bool isValidHttpMethod(const std::string& method);
    bool isLimitReached() const;
    bool isIllegalMethodViolation() const;
    const std::string getViolatedTypeStr() const { return m_strData.type; }
    const ViolatedStrData& getViolatedStrData() const { return m_strData; }
    size_t getViolatingSize() const;

private:
    bool isLegalHttpMethod(const std::string& method) const;
    void setCurrStateType(StateType type) { m_currState = type; }
    StateType getCurrStateType() { return m_currState; }
    void setViolationType(ViolationType type);
    void setViolatedTypeStr();
    void setViolatedPolicyStr();
    const std::string& getAssetId() const { return m_strData.assetId; }

private:
    const Policy& m_policy;
    size_t m_urlSize;
    size_t m_httpHeaderSize;
    ull m_httpBodySize;
    size_t m_objectDepth;
    StateType m_currState;  // State that is currently being enforced
    ViolationType m_type;  // Type of violation reached
    ViolatedStrData m_strData;  // Holds the string info of the violated data
};

}
}
