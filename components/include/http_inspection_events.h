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

#ifndef __HTTP_INSPECTION_EVENTS_H__
#define __HTTP_INSPECTION_EVENTS_H__

#include "debug.h"
#include "event.h"

#include "http_event_impl/filter_verdict.h"
#include "http_event_impl/i_http_event_impl.h"

using ResponseCode = uint16_t;

class HttpRequestHeaderEvent : public Event<HttpRequestHeaderEvent, EventVerdict>
{
public:
    HttpRequestHeaderEvent(const HttpHeader &header) : req_header(header) {}

    const Buffer & getKey() const { return req_header.getKey(); }
    const Buffer & getValue() const { return req_header.getValue(); }
    bool isLastHeader() const { return req_header.isLastHeader(); }
    uint8_t getHeaderIndex() const { return req_header.getHeaderIndex(); }

    template <class Archive>
    void
    save(Archive &ar) const
    {
        req_header.save(ar);
    }

    void print(std::ostream &out_stream) const { req_header.print(out_stream); }

private:
    const HttpHeader &req_header;
};

class HttpResponseHeaderEvent: public Event<HttpResponseHeaderEvent, EventVerdict>
{
public:
    HttpResponseHeaderEvent(const HttpHeader &header) : res_header(header) {}

    const Buffer & getKey() const { return res_header.getKey(); }
    const Buffer & getValue() const { return res_header.getValue(); }
    bool isLastHeader() const { return res_header.isLastHeader(); }
    uint8_t getHeaderIndex() const { return res_header.getHeaderIndex(); }

    template <class Archive>
    void
    save(Archive &ar) const
    {
        res_header.save(ar);
    }

    void print(std::ostream &out_stream) const { res_header.print(out_stream); }

private:
    const HttpHeader &res_header;
};

class HttpRequestBodyEvent: public Event<HttpRequestBodyEvent, EventVerdict>
{
public:
    HttpRequestBodyEvent(const HttpBody &body, const Buffer &previous_chunked_data)
            :
        req_body(body),
        prev_chunked_data(previous_chunked_data)
    {}

    const Buffer & getData() const { return req_body.getData(); }
    const Buffer & getPreviousChunkedData() const { return prev_chunked_data; }
    bool isLastChunk() const { return req_body.isLastChunk(); }

    template <class Archive>
    void
    save(Archive &ar) const
    {
        req_body.save(ar);
    }

    void print(std::ostream &out_stream) const { req_body.print(out_stream); }

private:
    const HttpBody &req_body;
    const Buffer &prev_chunked_data;
};

class HttpResponseBodyEvent: public Event<HttpResponseBodyEvent, EventVerdict>
{
public:
    HttpResponseBodyEvent(const HttpBody &body, const Buffer &previous_chunked_data)
            :
        res_body(body),
        prev_chunked_data(previous_chunked_data)
    {}

    const Buffer & getData() const { return res_body.getData(); }
    const Buffer & getPreviousChunkedData() const { return prev_chunked_data; }
    bool isLastChunk() const { return res_body.isLastChunk(); }
    uint8_t getBodyChunkIndex() const { return res_body.getBodyChunkIndex(); }

    template <class Archive>
    void
    save(Archive &ar) const
    {
        res_body.save(ar);
    }

    void print(std::ostream &out_stream) const { res_body.print(out_stream); }

private:
    const HttpBody &res_body;
    const Buffer &prev_chunked_data;
};


class NewHttpTransactionEvent : public Event<NewHttpTransactionEvent, EventVerdict>
{
public:
    NewHttpTransactionEvent(const HttpTransactionData &event_data) : http_transaction_event_data(event_data) {}

    const IPAddr & getSourceIP() const { return http_transaction_event_data.getSourceIP(); }
    uint16_t getSourcePort() const { return http_transaction_event_data.getSourcePort(); }
    const IPAddr & getListeningIP() const { return http_transaction_event_data.getListeningIP(); }
    uint16_t getListeningPort() const { return http_transaction_event_data.getListeningPort(); }
    const std::string & getDestinationHost() const { return http_transaction_event_data.getDestinationHost(); }
    const std::string & getHttpProtocol() const { return http_transaction_event_data.getHttpProtocol(); }
    const std::string & getURI() const { return http_transaction_event_data.getURI(); }
    const std::string & getHttpMethod() const { return http_transaction_event_data.getHttpMethod(); }

    void print(std::ostream &out_stream) const { http_transaction_event_data.print(out_stream); }

    template <class Archive>
    void
    save(Archive &ar) const
    {
        http_transaction_event_data.save(ar);
    }

private:
    const HttpTransactionData &http_transaction_event_data;
};

class ResponseCodeEvent : public Event<ResponseCodeEvent, EventVerdict>
{
public:
    ResponseCodeEvent(const ResponseCode &res_code) : http_response_code(res_code) {}

    const ResponseCode & getResponseCode() const { return http_response_code; }

    template <class Archive>
    void
    save(Archive &ar) const
    {
        ar(http_response_code);
    }

    void print(std::ostream &out_stream) const { out_stream << http_response_code; }

private:
    ResponseCode http_response_code;
};

class EndRequestEvent : public Event<EndRequestEvent, EventVerdict>
{
};

class EndTransactionEvent : public Event<EndTransactionEvent, EventVerdict>
{
};

class WaitTransactionEvent : public Event<WaitTransactionEvent, EventVerdict>
{
};

#endif // __HTTP_INSPECTION_EVENTS_H__
