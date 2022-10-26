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

#include "UserLimitsPolicy.h"
#include <limits>
#include <iomanip>

namespace Waap {
namespace UserLimits {

typedef unsigned long long ull;

bool Policy::operator==(const Policy& other) const
{
    return getConfig() == other.getConfig();
}

bool Policy::Config::operator==(const Policy::Config& other) const
{
    return urlMaxSize == other.urlMaxSize &&
        httpHeaderMaxSize == other.httpHeaderMaxSize &&
        httpBodyMaxSize == other.httpBodyMaxSize &&
        maxObjectDepth == other.maxObjectDepth &&
        httpIllegalMethodsAllowed == other.httpIllegalMethodsAllowed;
}

std::ostream& operator<<(std::ostream& os, const Policy& policy)
{
    auto config = policy.getConfig();
    os << "[Policy] " << "urlMaxSize: " << config.urlMaxSize << "  " <<
        "httpHeaderMaxSize: " << config.httpHeaderMaxSize << "  " <<
        "httpBodyMaxSize: " << config.httpBodyMaxSize << "  " <<
        "maxObjectDepth: " << config.maxObjectDepth << "  " <<
        std::boolalpha << "httpIllegalMethodsAllowed: " << config.httpIllegalMethodsAllowed;
    return os;
}

bool State::addUrlBytes(size_t size)
{
    setCurrStateType(StateType::URL);
    if (m_urlSize > std::numeric_limits<size_t>::max() - size) {
        // We are about to overflow
        setViolationType(ViolationType::URL_OVERFLOW);
        m_urlSize = std::numeric_limits<size_t>::max();
        dbgWarning(D_WAAP_ULIMITS) << "[USER LIMITS] Url size overflow. Asset id: " << getAssetId();
        return true;
    }

    m_urlSize += size;
    if (m_urlSize > m_policy.getUrlMaxSize()) {
        setViolationType(ViolationType::URL_LIMIT);
        dbgWarning(D_WAAP_ULIMITS) << "[USER LIMITS] Url size limit exceeded " <<
            m_urlSize << "/" << m_policy.getUrlMaxSize() << ". Asset id: " << getAssetId();
        return true;
    }
    dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Current url bytes " << m_urlSize << "/" <<
        m_policy.getUrlMaxSize();
    return false;
}

bool State::addHeaderBytes(const std::string& name, const std::string& value)
{
    setCurrStateType(StateType::HEADER);
    size_t chunkSize = name.size() + value.size();
    if (m_httpHeaderSize > std::numeric_limits<size_t>::max() - chunkSize) {
        // We are about to overflow
        setViolationType(ViolationType::HEADER_OVERFLOW);
        m_httpHeaderSize = std::numeric_limits<size_t>::max();
        dbgWarning(D_WAAP_ULIMITS) << "[USER LIMITS] Http header size overflow. Asset id: " << getAssetId();
        return true;
    }

    m_httpHeaderSize += chunkSize;
    if (m_httpHeaderSize > m_policy.getHttpHeaderMaxSize()) {
        setViolationType(ViolationType::HEADER_LIMIT);
        dbgWarning(D_WAAP_ULIMITS) << "[USER LIMITS] Http header size limit exceeded " <<
            m_httpHeaderSize << "/" << m_policy.getHttpHeaderMaxSize() << ". Asset id: " << getAssetId();
        return true;
    }
    dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Current header bytes " << m_httpHeaderSize << "/" <<
        m_policy.getHttpHeaderMaxSize();
    return false;
}

bool State::addBodyBytes(size_t chunkSize)
{
    setCurrStateType(StateType::BODY);
    if (m_httpBodySize > std::numeric_limits<size_t>::max() - chunkSize) {
        // We are about to overflow
        setViolationType(ViolationType::BODY_OVERFLOW);
        m_httpBodySize = std::numeric_limits<size_t>::max();
        dbgWarning(D_WAAP_ULIMITS) << "[USER LIMITS] Http body size overflow. Asset id: " << getAssetId();
        return true;
    }

    m_httpBodySize += chunkSize;
    if (m_httpBodySize > m_policy.getHttpBodyMaxSize()) {
        setViolationType(ViolationType::BODY_LIMIT);
        dbgWarning(D_WAAP_ULIMITS) << "[USER LIMITS] Http body size limit exceeded " <<
            m_httpBodySize << "/" << m_policy.getHttpBodyMaxSize() << ". Asset id: " << getAssetId();
        return true;
    }
    dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Current body bytes " << m_httpBodySize << "/" <<
        m_policy.getHttpBodyMaxSize();
    return false;
}

bool State::setObjectDepth(size_t depth)
{
    setCurrStateType(StateType::DEPTH);
    m_objectDepth = depth;
    if (m_objectDepth > m_policy.getMaxObjectDepth()) {
        setViolationType(ViolationType::OBJECT_DEPTH_LIMIT);
        dbgWarning(D_WAAP_ULIMITS) << "[USER LIMITS] Http object depth limit exceeded " <<
            m_objectDepth << "/" << m_policy.getMaxObjectDepth() << ". Asset id: " << getAssetId();
        return true;
    }
    dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] Current object depth " << m_objectDepth << "/" <<
        m_policy.getMaxObjectDepth();
    return false;
}

bool State::isValidHttpMethod(const std::string& method)
{
    setCurrStateType(StateType::METHOD);
    if (m_policy.isHttpIllegalMethodAllowed()) {
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS][method: " << method << "] Http all methods allowed";
        return true;
    }

    if (isLegalHttpMethod(method)) {
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS][method: " << method << "] Http legal method";
        return true;
    }
    setViolationType(ViolationType::ILLEGAL_METHOD);
    dbgWarning(D_WAAP_ULIMITS) << "[USER LIMITS][method: " << method << "] Http illegal method" <<
        ". Asset id: " << getAssetId();
    return false;
}

bool State::isLegalHttpMethod(const std::string& method) const
{
    if (method == "GET") return true;
    if (method == "POST") return true;
    if (method == "DELETE") return true;
    if (method == "PATCH") return true;
    if (method == "PUT") return true;
    if (method == "CONNECT") return true;
    if (method == "OPTIONS") return true;
    if (method == "HEAD") return true;
    if (method == "TRACE") return true;
    // Below methods are part of WebDAV http protocol extension
    if (method == "MKCOL") return true;
    if (method == "COPY") return true;
    if (method == "MOVE") return true;
    if (method == "PROPFIND") return true;
    if (method == "PROPPATCH") return true;
    if (method == "LOCK") return true;
    if (method == "UNLOCK") return true;
    if (method == "VERSION-CONTROL") return true;
    if (method == "REPORT") return true;
    if (method == "INDEX") return true;
    if (method == "CHECKOUT") return true;
    if (method == "CHECKIN") return true;
    if (method == "UNCHECKOUT") return true;
    if (method == "MKWORKSPACE") return true;
    if (method == "UPDATE") return true;
    if (method == "LABEL") return true;
    if (method == "MERGE") return true;
    if (method == "BASELINE-CONTROL") return true;
    if (method == "MKACTIVITY") return true;
    if (method == "ORDERPATCH") return true;
    if (method == "ACL") return true;
    if (method == "PATCH") return true;
    if (method == "SEARCH") return true;
    if (method == "MKREDIRECTREF") return true;
    if (method == "BIND") return true;
    if (method == "UNBIND") return true;
    return false;
}

bool State::isLimitReached() const
{
    return m_type != ViolationType::NO_LIMIT;
}

bool State::isIllegalMethodViolation() const
{
    return m_type == ViolationType::ILLEGAL_METHOD;
}

void State::setViolationType(ViolationType type)
{
    m_type = type;
    setViolatedTypeStr();
    setViolatedPolicyStr();
}

void State::setViolatedTypeStr()
{
    std::stringstream ss;
    switch (m_type)
    {
        case ViolationType::ILLEGAL_METHOD: {
            ss << "method violation";
            break;
        }
        case ViolationType::URL_LIMIT: {
            ss << "url size exceeded";
            break;
        }
        case ViolationType::URL_OVERFLOW: {
            ss << "url size overflow";
            break;
        }
        case ViolationType::HEADER_LIMIT: {
            ss << "header size exceeded";
            break;
        }
        case ViolationType::HEADER_OVERFLOW: {
            ss << "header size overflow";
            break;
        }
        case ViolationType::BODY_LIMIT: {
            ss << "body size exceeded";
            break;
        }
        case ViolationType::BODY_OVERFLOW: {
            ss << "body size overflow";
            break;
        }
        case ViolationType::OBJECT_DEPTH_LIMIT: {
            ss << "object depth exceeded";
            break;
        }
        default:
            ss << "no violation";
    }
    m_strData.type = ss.str();
}

void State::setViolatedPolicyStr()
{
    std::stringstream ss;
    switch (m_type)
    {
        case ViolationType::ILLEGAL_METHOD: {
            if (m_policy.isHttpIllegalMethodAllowed()) {
                ss << "true";
            }
            else {
                ss << "false";
            }
            break;
        }
        case ViolationType::URL_LIMIT:
        case ViolationType::URL_OVERFLOW: {
            ss << m_policy.getUrlMaxSize();
            if (m_policy.getUrlMaxSize() == 1) {
                ss << " Byte";
            }
            else {
                ss << " Bytes";
            };
            break;
        }
        case ViolationType::HEADER_LIMIT:
        case ViolationType::HEADER_OVERFLOW: {
            ss << m_policy.getHttpHeaderMaxSize();
            if (m_policy.getHttpHeaderMaxSize() == 1) {
                ss << " Byte";
            }
            else {
                ss << " Bytes";
            }
            break;
        }
        case ViolationType::BODY_LIMIT:
        case ViolationType::BODY_OVERFLOW: {
            ss << m_policy.getHttpBodyMaxSizeKb();
            if (m_policy.getHttpBodyMaxSizeKb() == 1) {
                ss << " Kilobyte";
            }
            else {
                ss << " Kilobytes";
            }
            break;
        }
        case ViolationType::OBJECT_DEPTH_LIMIT: {
            ss << m_policy.getMaxObjectDepth();
            break;
        }
        default:
            ss << "unknown";
    }
    m_strData.policy = ss.str();
}

size_t State::getViolatingSize() const
{
    switch (m_type)
    {
        case ViolationType::URL_LIMIT:
        case ViolationType::URL_OVERFLOW:
            return m_urlSize;
        case ViolationType::HEADER_LIMIT:
        case ViolationType::HEADER_OVERFLOW:
            return m_httpHeaderSize;
        case ViolationType::BODY_LIMIT:
        case ViolationType::BODY_OVERFLOW:
            return static_cast<size_t>(m_httpBodySize / 1024);
        case ViolationType::OBJECT_DEPTH_LIMIT:
            return m_objectDepth;
        default:
            return 0;
    }
}

} // namespace UserLimits
} // namespace Waap
