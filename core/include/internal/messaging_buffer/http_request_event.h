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

#ifndef __HTTP_REQUEST_EVENT_H__
#define __HTTP_REQUEST_EVENT_H__

#include <string>

#include "cereal/archives/json.hpp"

class HTTPRequestSignature
{
public:
    HTTPRequestSignature() = default;
    HTTPRequestSignature(const std::string &_method, const std::string &_url, const std::string &_tag)
            :
        method(_method),
        url(_url),
        tag(_tag)
    {
    }

    bool
    operator<(const HTTPRequestSignature &other) const
    {
        return getSignature() < other.getSignature();
    }

    std::string getSignature() const { return method + url + tag; }

    const std::string & getMethod()  const { return method;  }
    const std::string & getURL()     const { return url;     }
    const std::string & getTag()     const { return tag;     }

    template<class Archive>
    void load(Archive &ar)
    {
        try {
            ar(cereal::make_nvp("tag", tag));
        } catch(...) {
            tag = "buffered messages";
            ar.setNextName(nullptr);
        }
        ar(method, url);
    }

    template<class Archive>
    void save(Archive &ar) const
    {
        ar(cereal::make_nvp("tag", tag));
        ar(method, url);
    }

private:
    std::string method;
    std::string url;
    std::string tag;
};

class HTTPRequestEvent : public HTTPRequestSignature
{
public:
    HTTPRequestEvent() = default;
    HTTPRequestEvent(
        const std::string &_method,
        const std::string &_url,
        const std::string &_headers,
        const std::string &&_body,
        const std::string &_tag = "buffered messages")
            :
        HTTPRequestSignature(_method, _url, _tag),
        headers(_headers),
        body(std::move(_body))
    {
    }

    HTTPRequestEvent(
        const HTTPRequestSignature &&sig,
        const std::string &_headers,
        const std::string &&_body)
            :
        HTTPRequestSignature(std::move(sig)),
        headers(_headers),
        body(std::move(_body))
    {
    }

    template<class Archive>
    void load(Archive &ar)
    {
        HTTPRequestSignature::load(ar);
        ar(headers, body);
    }

    template<class Archive>
    void save(Archive &ar) const
    {
        HTTPRequestSignature::save(ar);
        ar(headers, body);
    }

    const std::string & getHeaders() const { return headers; }
    const std::string & getBody()    const { return body;    }

private:
    std::string headers;
    std::string body;
};

#endif // __HTTP_REQUEST_EVENT_H__
